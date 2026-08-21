package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
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
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{
			"master.key": newKey,
		},
	}

	// Save it to Kubernetes
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

	// Always ensure the table exists
	createTable := `CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL
	);`
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
			log.Fatalf("Fatal: Failed to inject bootstrap user into DB: %v", err)
		}
		log.Printf("[Boot] Brand new database initialized. Bootstrap user '%s' injected.", bootstrapUser)
	} else {
		log.Println("[Boot] Existing SQLite database found and loaded. Skipping bootstrap injection.")
	}

	return db
}

func (s *TheorosServer) Login(
	ctx context.Context,
	req *connect.Request[pb.LoginRequest],
) (*connect.Response[pb.LoginResponse], error) {

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

	// Loop through users and compare the hashes
	for rows.Next() {
		var u, hash string
		if err := rows.Scan(&u, &hash); err == nil {
			// Compare Bcrypt hash to the provided token
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(providedToken)) == nil {
				matchedUsername = u
				break
			}
		}
	}

	// If no hash matched the token, reject the login
	if matchedUsername == "" {
		log.Println("[Security] Failed login attempt: Invalid token provided.")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	// Generate JWT for the matched user
	claims := jwt.MapClaims{
		"username":   matchedUsername,
		"authorized": true,
		"exp":        time.Now().Add(time.Hour * 1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}

	log.Printf("[Audit] Successful login for user: %s", matchedUsername)

	return connect.NewResponse(&pb.LoginResponse{
		Token: tokenString,
	}), nil
}

func (s *TheorosServer) ExecuteCommand(
	ctx context.Context,
	req *connect.Request[pb.CommandRequest],
) (res *connect.Response[pb.CommandResponse], err error) {

	defer func() {
		if r := recover(); r != nil {
			err = connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%v", r))
		}
	}()

	log.Printf("[Audit] Executing: %s %s (namespace: '%s', flags: %v)",
		req.Msg.Action, req.Msg.Resource, req.Msg.Namespace, req.Msg.Flags)

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

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	ioStreams := genericclioptions.IOStreams{
		In:     bytes.NewReader(nil),
		Out:    &outBuf,
		ErrOut: &errBuf,
	}

	kubectlOptions := cmd.KubectlOptions{
		Arguments:   args,
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams:   ioStreams,
	}

	kubectlCmd := cmd.NewKubectlCommand(kubectlOptions)
	kubectlCmd.SetArgs(args)

	kubectlCmd.SilenceUsage = true
	kubectlCmd.SilenceErrors = true

	err = kubectlCmd.Execute()

	finalOutput := outBuf.String()
	if errBuf.Len() > 0 {
		if finalOutput != "" {
			finalOutput += "\n"
		}
		finalOutput += errBuf.String()
	}

	if err != nil {
		return nil, connect.NewError(
			connect.CodeInvalidArgument,
			fmt.Errorf("%s\n%s", err.Error(), errBuf.String()),
		)
	}

	return connect.NewResponse(&pb.CommandResponse{Output: finalOutput}), nil
}

func (s *TheorosServer) InteractiveExec(
	ctx context.Context,
	stream *connect.BidiStream[pb.ExecRequest, pb.ExecResponse],
) error {
	return connect.NewError(connect.CodeUnimplemented, errors.New("interactive exec coming soon"))
}

func NewAuthInterceptor(secretKey []byte) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {

			if strings.HasSuffix(req.Spec().Procedure, "Login") {
				return next(ctx, req)
			}

			authHeader := req.Header().Get("Authorization")
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization token"))
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return secretKey, nil
			})

			if err != nil || !token.Valid {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
			}

			return next(ctx, req)
		}
	}
}

func main() {
	log.Println("Starting Theoros Server...")

	// Enforce Bootstrap Credentials
	bootstrapPath := "/etc/theoros/bootstrap/credentials"
	credBytes, err := os.ReadFile(bootstrapPath)
	if err != nil {
		log.Fatalf("Fatal: Bootstrap credentials not found at %s. Pod cannot start without DevOps access! Error: %v", bootstrapPath, err)
	}

	// Expecting format: "username:password"
	parts := strings.SplitN(strings.TrimSpace(string(credBytes)), ":", 2)
	if len(parts) != 2 {
		log.Fatalf("Fatal: Bootstrap file is malformed. Must be 'username:password'.")
	}
	bootstrapUser := parts[0]
	bootstrapPass := parts[1]

	// Fetch or Generate Master JWT Secret
	jwtSecretKey := getOrGenerateJWTSecret()

	// Initialize secure SQLite database
	db := initDB("/data/theoros.db", bootstrapUser, bootstrapPass)
	defer db.Close()

	server := &TheorosServer{
		secretKey: jwtSecretKey,
		db:        db,
	}

	mux := http.NewServeMux()
	path, handler := v1connect.NewKubernetesServiceHandler(
		server,
		connect.WithInterceptors(NewAuthInterceptor(jwtSecretKey)),
	)
	mux.Handle(path, handler)

	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	s := http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		Protocols: p,
	}

	log.Printf("Connect RPC Server running on %s", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}

// -------------------------------------------------------------
// User Management RPCs
// -------------------------------------------------------------

func (s *TheorosServer) GenerateToken(
	ctx context.Context,
	req *connect.Request[pb.GenerateTokenRequest],
) (*connect.Response[pb.GenerateTokenResponse], error) {

	username := strings.TrimSpace(req.Msg.Username)
	if username == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("username cannot be empty"))
	}

	// Generate a secure 24-byte random key and encode to hex string
	keyBytes := make([]byte, 24)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate random key"))
	}
	plainToken := "th-" + hex.EncodeToString(keyBytes)

	// Hash it securely using Bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to hash token"))
	}

	// Save to SQLite Database
	insertStmt := `
		INSERT INTO users (username, password_hash) VALUES (?, ?) 
		ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash;
	`
	if _, err := s.db.Exec(insertStmt, username, hash); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to save user to database"))
	}

	log.Printf("[Audit] Generated new access token for user: %s", username)

	// Return the PLAINTEXT token back to the CLI so they can share it
	return connect.NewResponse(&pb.GenerateTokenResponse{
		Token: plainToken,
	}), nil
}

func (s *TheorosServer) ListUsers(
	ctx context.Context,
	req *connect.Request[pb.ListUsersRequest],
) (*connect.Response[pb.ListUsersResponse], error) {

	rows, err := s.db.Query("SELECT username FROM users")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to query users"))
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			users = append(users, u)
		}
	}

	return connect.NewResponse(&pb.ListUsersResponse{
		Usernames: users,
	}), nil
}

func (s *TheorosServer) DeleteUser(
	ctx context.Context,
	req *connect.Request[pb.DeleteUserRequest],
) (*connect.Response[pb.DeleteUserResponse], error) {

	username := strings.TrimSpace(req.Msg.Username)
	if username == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("username cannot be empty"))
	}

	res, err := s.db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete user"))
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}

	log.Printf("[Audit] Deleted user: %s", username)

	return connect.NewResponse(&pb.DeleteUserResponse{
		Message: fmt.Sprintf("User '%s' deleted successfully", username),
	}), nil
}

// ==========================================
// AUTOCOMPLETION ENGINE
// ==========================================
func (s *TheorosServer) GetCompletions(
	ctx context.Context,
	req *connect.Request[pb.GetCompletionsRequest],
) (res *connect.Response[pb.GetCompletionsResponse], err error) {

	defer func() {
		if r := recover(); r != nil {
			err = connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%v", r))
		}
	}()

	// Prepare the hidden __complete command
	cmdArgs := append([]string{"__complete"}, req.Msg.Args...)

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	ioStreams := genericclioptions.IOStreams{
		In:     bytes.NewReader(nil),
		Out:    &outBuf,
		ErrOut: &errBuf,
	}

	kubectlOptions := cmd.KubectlOptions{
		Arguments:   cmdArgs,
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams:   ioStreams,
	}

	rootCmd := cmd.NewKubectlCommand(kubectlOptions)
	rootCmd.SetArgs(cmdArgs)

	rootCmd.SetOut(&outBuf)
	rootCmd.SetErr(&errBuf)

	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	// Execute the hidden autocomplete command in-memory
	_ = rootCmd.Execute()

	// Parse the output and clean up Bash directives
	rawLines := strings.Split(outBuf.String(), "\n")
	var suggestions []string

	for _, line := range rawLines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		cleanSuggestion := strings.TrimSpace(parts[0])
		suggestions = append(suggestions, cleanSuggestion)
	}

	return connect.NewResponse(&pb.GetCompletionsResponse{
		Suggestions: suggestions,
	}), nil
}
