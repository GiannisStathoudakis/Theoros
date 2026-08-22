package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	_ "modernc.org/sqlite" // SQLite Driver

	// Kubernetes client-go
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	// Generated Protobuf Imports
	pb "github.com/GiannisStathoudakis/Theoros/gen/theoros/v1"
	"github.com/GiannisStathoudakis/Theoros/gen/theoros/v1/v1connect"

	// kubectl source code
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/kubectl/pkg/cmd"
)

func init() {
	cmdutil.BehaviorOnFatal(func(msg string, code int) {
		panic(msg)
	})
}

type TheorosServer struct {
	secretKey []byte
	db        *sql.DB
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for CLI
}

func getOrGenerateJWTSecret() []byte {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Fatal: Failed to load in-cluster K8s config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Fatal: Failed to create K8s client: %v", err)
	}

	// Get the namespace the pod is currently running in
	nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Fatalf("Fatal: Cannot determine namespace: %v", err)
	}

	namespace := string(nsBytes)
	secretName := "theoros-jwt-master"

	secretsClient := clientset.CoreV1().Secrets(namespace)
	sec, err := secretsClient.Get(context.Background(), secretName, metav1.GetOptions{})

	// If it exists, return it
	if err == nil {
		if key, ok := sec.Data["master.key"]; ok {
			log.Println("[Boot] Loaded existing Master JWT Key from Kubernetes Secret.")
			return key
		}
	} else if !k8serrors.IsNotFound(err) {
		log.Fatalf("Fatal: Error communicating with K8s API: %v", err)
	}

	// If it does not exist, generate a new 32-byte secure key
	log.Println("[Boot] Master JWT Key not found. Generating a new one...")
	newKey := make([]byte, 32)
	_, _ = rand.Read(newKey)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data:       map[string][]byte{"master.key": newKey},
	}

	_, err = secretsClient.Create(context.Background(), newSecret, metav1.CreateOptions{})
	if err != nil {
		// If another replica created it exactly at the same time, just fetch theirs
		if k8serrors.IsAlreadyExists(err) {
			sec, _ = secretsClient.Get(context.Background(), secretName, metav1.GetOptions{})
			return sec.Data["master.key"]
		}
		log.Fatalf("Fatal: Could not save JWT secret to K8s: %v", err)
	}

	log.Println("[Boot] Successfully saved new Master JWT Key to Kubernetes Secret.")
	return newKey
}

func initDB(dbPath, bootstrapUser, bootstrapPass string) *sql.DB {
	// Check if the database file already exists
	_, err := os.Stat(dbPath)
	dbExists := err == nil

	// Open/Create with strict 0600 Linux permissions
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalf("Fatal: Failed to create strict DB file: %v", err)
	}
	file.Close()
	os.Chmod(dbPath, 0600)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("Fatal: Failed to open SQLite database: %v", err)
	}
	createTable := `CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);`
	if _, err := db.Exec(createTable); err != nil {
		log.Fatalf("Fatal: Failed to create users table: %v", err)
	}

	// ONLY inject the bootstrap user if this is a brand new database!
	if !dbExists {
		hash, err := bcrypt.GenerateFromPassword([]byte(bootstrapPass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Fatal: Failed to hash bootstrap password: %v", err)
		}

		insertStmt := `INSERT INTO users (username, password_hash) VALUES (?, ?)`
		if _, err := db.Exec(insertStmt, bootstrapUser, hash); err != nil {
			log.Fatalf("Fatal: Failed to inject bootstrap user: %v", err)
		}
		log.Printf("[Boot] Brand new database initialized. Bootstrap user '%s' injected.", bootstrapUser)
	} else {
		log.Println("[Boot] Existing SQLite database found and loaded. Skipping bootstrap injection.")
	}
	return db
}

func (s *TheorosServer) Login(ctx context.Context, req *connect.Request[pb.LoginRequest]) (*connect.Response[pb.LoginResponse], error) {
	providedToken := strings.TrimSpace(req.Msg.Token)
	if providedToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("token cannot be empty"))
	}

	// Fetch ALL users and their hashes from the DB
	rows, err := s.db.Query("SELECT username, password_hash FROM users")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("database error"))
	}
	defer rows.Close()

	var matchedUsername string
	for rows.Next() {
		var u, hash string
		if err := rows.Scan(&u, &hash); err == nil {
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(providedToken)) == nil {
				matchedUsername = u
				break
			}
		}
	}

	if matchedUsername == "" {
		log.Println("[Security] Failed login attempt: Invalid token provided.")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	// Generate JWT for the matched user
	claims := jwt.MapClaims{"username": matchedUsername, "authorized": true, "exp": time.Now().Add(time.Hour * 1).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}

	log.Printf("[Audit] Successful login for user: %s", matchedUsername)
	return connect.NewResponse(&pb.LoginResponse{Token: tokenString}), nil
}

func (s *TheorosServer) ExecuteCommand(ctx context.Context, req *connect.Request[pb.CommandRequest]) (res *connect.Response[pb.CommandResponse], err error) {
	defer func() {
		if r := recover(); r != nil {
			err = connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%v", r))
		}
	}()

	for _, flag := range req.Msg.Flags {
		if flag == "-w" || flag == "--watch" || flag == "-f" || flag == "--follow" || flag == "-it" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("streaming flags must be executed via streaming endpoints."))
		}
	}

	args := []string{req.Msg.Action}
	if req.Msg.Resource != "" {
		args = append(args, req.Msg.Resource)
	}
	if req.Msg.Name != "" {
		args = append(args, req.Msg.Name)
	}
	if req.Msg.Namespace != "" {
		args = append(args, "-n", req.Msg.Namespace)
	}
	if len(req.Msg.Flags) > 0 {
		args = append(args, req.Msg.Flags...)
	}

	var outBuf, errBuf bytes.Buffer
	kubectlCmd := cmd.NewKubectlCommand(cmd.KubectlOptions{
		Arguments:   args,
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams:   genericclioptions.IOStreams{In: bytes.NewReader(nil), Out: &outBuf, ErrOut: &errBuf},
	})
	kubectlCmd.SetArgs(args)
	kubectlCmd.SilenceUsage, kubectlCmd.SilenceErrors = true, true

	err = kubectlCmd.Execute()
	finalOutput := outBuf.String()
	if errBuf.Len() > 0 {
		if finalOutput != "" {
			finalOutput += "\n"
		}
		finalOutput += errBuf.String()
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s\n%s", err.Error(), errBuf.String()))
	}
	return connect.NewResponse(&pb.CommandResponse{Output: finalOutput}), nil
}

type serverStreamWriter struct {
	isStderr bool
	stream   *connect.ServerStream[pb.ExecResponse]
}

func (w *serverStreamWriter) Write(p []byte) (n int, err error) {
	resp := &pb.ExecResponse{}
	if w.isStderr {
		resp.Stderr = p
	} else {
		resp.Stdout = p
	}
	err = w.stream.Send(resp)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *TheorosServer) InteractiveExec(ctx context.Context, req *connect.Request[pb.ExecRequest], stream *connect.ServerStream[pb.ExecResponse]) error {
	args := []string{req.Msg.Action}
	if req.Msg.Resource != "" {
		args = append(args, req.Msg.Resource)
	}
	if req.Msg.Name != "" {
		args = append(args, req.Msg.Name)
	}
	if req.Msg.Namespace != "" {
		args = append(args, "-n", req.Msg.Namespace)
	}
	if len(req.Msg.Flags) > 0 {
		args = append(args, req.Msg.Flags...)
	}

	kubectlCmd := cmd.NewKubectlCommand(cmd.KubectlOptions{
		Arguments:   args,
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams: genericclioptions.IOStreams{
			In:     bytes.NewReader(nil),
			Out:    &serverStreamWriter{isStderr: false, stream: stream},
			ErrOut: &serverStreamWriter{isStderr: true, stream: stream},
		},
	})
	kubectlCmd.SetArgs(args)
	kubectlCmd.SilenceUsage, kubectlCmd.SilenceErrors = true, true

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Audit-Stream] Recovered from panic: %v", r)
		}
	}()
	err := kubectlCmd.ExecuteContext(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeUnknown, err)
	}
	return nil
}

type wsWriter struct{ ws *websocket.Conn }

func (w *wsWriter) Write(p []byte) (int, error) {
	err := w.ws.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *TheorosServer) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.URL.Query().Get("token")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return s.secretKey, nil })
	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	// Read the first message as the command configuration
	_, msg, err := ws.ReadMessage()
	if err != nil {
		return
	}
	var req pb.ExecRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return
	}

	log.Printf("[Audit-WS] Starting Interactive Exec: %s %s (namespace: '%s')", req.Action, req.Resource, req.Namespace)

	// Clean flags to prevent kubectl from complaining about fake TTY
	cleanFlags := []string{}
	for _, f := range req.Flags {
		if f == "-it" || f == "-ti" {
			cleanFlags = append(cleanFlags, "-i")
		} else if f != "-t" && f != "--tty" {
			cleanFlags = append(cleanFlags, f)
		}
	}

	args := []string{req.Action}
	if req.Resource != "" {
		args = append(args, req.Resource)
	}
	if req.Name != "" {
		args = append(args, req.Name)
	}
	if req.Namespace != "" {
		args = append(args, "-n", req.Namespace)
	}
	if len(cleanFlags) > 0 {
		args = append(args, cleanFlags...)
	}

	// Create a pipe to bridge the WebSocket reads to kubectl's Stdin
	pr, pw := io.Pipe()
	go func() {
		for {
			_, p, err := ws.ReadMessage()
			if err != nil {
				pw.Close()
				return
			}
			pw.Write(p)
		}
	}()

	kubectlCmd := cmd.NewKubectlCommand(cmd.KubectlOptions{
		Arguments:   args,
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams: genericclioptions.IOStreams{
			In:     pr,
			Out:    &wsWriter{ws: ws},
			ErrOut: &wsWriter{ws: ws},
		},
	})
	kubectlCmd.SetArgs(args)
	kubectlCmd.SilenceUsage, kubectlCmd.SilenceErrors = true, true

	_ = kubectlCmd.Execute()
	log.Printf("[Audit-WS] Interactive session closed cleanly.")
}

func NewAuthInterceptor(secretKey []byte) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if strings.HasSuffix(req.Spec().Procedure, "Login") {
				return next(ctx, req)
			}
			tokenString := strings.TrimPrefix(req.Header().Get("Authorization"), "Bearer ")
			if tokenString == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization token"))
			}
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return secretKey, nil })
			if err != nil || !token.Valid {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
			}
			return next(ctx, req)
		}
	}
}

func main() {
	log.Println("Starting Theoros Server...")
	bootstrapPath := "/etc/theoros/bootstrap/credentials"
	credBytes, err := os.ReadFile(bootstrapPath)
	if err != nil {
		log.Fatalf("Fatal: Bootstrap credentials not found: %v", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(credBytes)), ":", 2)
	bootstrapUser, bootstrapPass := parts[0], parts[1]

	jwtSecretKey := getOrGenerateJWTSecret()
	db := initDB("/data/theoros.db", bootstrapUser, bootstrapPass)
	defer db.Close()

	server := &TheorosServer{secretKey: jwtSecretKey, db: db}
	mux := http.NewServeMux()
	path, handler := v1connect.NewKubernetesServiceHandler(server, connect.WithInterceptors(NewAuthInterceptor(jwtSecretKey)))

	mux.Handle(path, handler)
	mux.HandleFunc("/ws/exec", server.WebSocketHandler) // 🚨 NEW WEBSOCKET ROUTE!

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	s := http.Server{Addr: ":" + port, Handler: mux, Protocols: &http.Protocols{}}
	s.Protocols.SetHTTP1(true)
	s.Protocols.SetUnencryptedHTTP2(true)

	log.Printf("Connect RPC Server running on %s", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}

func (s *TheorosServer) GenerateToken(ctx context.Context, req *connect.Request[pb.GenerateTokenRequest]) (*connect.Response[pb.GenerateTokenResponse], error) {
	username := strings.TrimSpace(req.Msg.Username)
	keyBytes := make([]byte, 24)
	rand.Read(keyBytes)
	plainToken := "th-" + hex.EncodeToString(keyBytes)
	hash, _ := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	s.db.Exec(`INSERT INTO users (username, password_hash) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash;`, username, hash)
	return connect.NewResponse(&pb.GenerateTokenResponse{Token: plainToken}), nil
}

func (s *TheorosServer) ListUsers(ctx context.Context, req *connect.Request[pb.ListUsersRequest]) (*connect.Response[pb.ListUsersResponse], error) {
	rows, _ := s.db.Query("SELECT username FROM users")
	defer rows.Close()
	var users []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		users = append(users, u)
	}
	return connect.NewResponse(&pb.ListUsersResponse{Usernames: users}), nil
}

func (s *TheorosServer) DeleteUser(ctx context.Context, req *connect.Request[pb.DeleteUserRequest]) (*connect.Response[pb.DeleteUserResponse], error) {
	username := strings.TrimSpace(req.Msg.Username)
	res, _ := s.db.Exec("DELETE FROM users WHERE username = ?", username)
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return connect.NewResponse(&pb.DeleteUserResponse{Message: fmt.Sprintf("User '%s' deleted successfully", username)}), nil
}

func (s *TheorosServer) GetCompletions(ctx context.Context, req *connect.Request[pb.GetCompletionsRequest]) (res *connect.Response[pb.GetCompletionsResponse], err error) {
	cmdArgs := append([]string{"__complete"}, req.Msg.Args...)
	var outBuf, errBuf bytes.Buffer
	rootCmd := cmd.NewKubectlCommand(cmd.KubectlOptions{Arguments: cmdArgs, ConfigFlags: genericclioptions.NewConfigFlags(true), IOStreams: genericclioptions.IOStreams{In: bytes.NewReader(nil), Out: &outBuf, ErrOut: &errBuf}})
	rootCmd.SetArgs(cmdArgs)
	rootCmd.SetOut(&outBuf)
	rootCmd.SetErr(&errBuf)
	rootCmd.SilenceUsage, rootCmd.SilenceErrors = true, true
	_ = rootCmd.Execute()
	var suggestions []string
	for _, line := range strings.Split(outBuf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		suggestions = append(suggestions, strings.TrimSpace(strings.SplitN(line, "\t", 2)[0]))
	}
	return connect.NewResponse(&pb.GetCompletionsResponse{Suggestions: suggestions}), nil
}
