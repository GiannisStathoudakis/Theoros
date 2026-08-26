package main

import (
	"bytes"
	"context"
	"crypto/rand"
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

	// Kubernetes client-go
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"

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

type contextKey string

const userCtxKey contextKey = "username"

// Decoy
var dummyBcryptHash = []byte("$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa")

type TheorosServer struct {
	secretKey []byte
	clientset *kubernetes.Clientset
	namespace string
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for CLI
}

func getClientsetAndNamespace() (*kubernetes.Clientset, string) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Fatal: Failed to load in-cluster K8s config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Fatal: Failed to create K8s client: %v", err)
	}
	nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Fatalf("Fatal: Cannot determine namespace: %v", err)
	}
	return clientset, string(nsBytes)
}

func getOrGenerateJWTSecret(clientset *kubernetes.Clientset, namespace string) []byte {
	secretName := "theoros-jwt-master"
	secretsClient := clientset.CoreV1().Secrets(namespace)
	sec, err := secretsClient.Get(context.Background(), secretName, metav1.GetOptions{})

	if err == nil {
		if key, ok := sec.Data["master.key"]; ok {
			log.Println("[Boot] Loaded existing Master JWT Key from Kubernetes Secret.")
			return key
		}
	} else if !k8serrors.IsNotFound(err) {
		log.Fatalf("Fatal: Error communicating with K8s API: %v", err)
	}

	log.Println("[Boot] Master JWT Key not found. Generating a new one...")
	newKey := make([]byte, 32)
	_, _ = rand.Read(newKey)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data:       map[string][]byte{"master.key": newKey},
	}
	_, err = secretsClient.Create(context.Background(), newSecret, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			sec, _ = secretsClient.Get(context.Background(), secretName, metav1.GetOptions{})
			return sec.Data["master.key"]
		}
		log.Fatalf("Fatal: Could not save JWT secret to K8s: %v", err)
	}
	log.Println("[Boot] Successfully saved new Master JWT Key to Kubernetes Secret.")
	return newKey
}

func initUserSecret(clientset *kubernetes.Clientset, namespace string) {
	secretName := "theoros-users"
	secretsClient := clientset.CoreV1().Secrets(namespace)
	_, err := secretsClient.Get(context.Background(), secretName, metav1.GetOptions{})

	if err == nil {
		log.Println("[Boot] Existing Kubernetes users database found. Skipping bootstrap injection.")
		return
	}
	if !k8serrors.IsNotFound(err) {
		log.Fatalf("Fatal: Error communicating with K8s API: %v", err)
	}

	// Hardcoded default setup credentials which will be reset automatically in the 1st login
	bootstrapUser := "admin"
	fullBootstrapToken := "th-admin-setup"
	hash, _ := bcrypt.GenerateFromPassword([]byte(fullBootstrapToken), bcrypt.DefaultCost)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data: map[string][]byte{
			bootstrapUser:                  hash,
			bootstrapUser + ".needs_reset": []byte("true"), // Flag them for mandatory reset
		},
	}
	_, err = secretsClient.Create(context.Background(), newSecret, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		log.Fatalf("Fatal: Failed to create users secret database: %v", err)
	}
	log.Printf("[Boot] Brand new database initialized. Default user '%s' created.", bootstrapUser)
}

func (s *TheorosServer) Login(ctx context.Context, req *connect.Request[pb.LoginRequest]) (*connect.Response[pb.LoginResponse], error) {
	providedToken := strings.TrimSpace(req.Msg.Token)
	if providedToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("token cannot be empty"))
	}

	// Enforce token format (th-<username>-<secret>)
	if !strings.HasPrefix(providedToken, "th-") {
		log.Println("[Security] Failed login attempt: Missing 'th-' prefix.")
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(providedToken))
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	body := strings.TrimPrefix(providedToken, "th-")
	lastDashIdx := strings.LastIndex(body, "-")
	if lastDashIdx == -1 || lastDashIdx == len(body)-1 {
		log.Println("[Security] Failed login attempt: Malformed token format.")
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(providedToken))
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	targetUsername := body[:lastDashIdx]

	sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, "theoros-users", metav1.GetOptions{})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read users database"))
	}

	hash, exists := sec.Data[targetUsername]
	if !exists {
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(providedToken))
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(providedToken)); err != nil {
		log.Printf("[Security] Failed login attempt for user: %s", targetUsername)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}

	// Check if the user is flagged for a mandatory reset
	_, requiresReset := sec.Data[targetUsername+".needs_reset"]

	claims := jwt.MapClaims{
		"username":    targetUsername,
		"authorized":  true,
		"needs_reset": requiresReset,
		"exp":         time.Now().Add(time.Hour * 1).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}

	log.Printf("[Audit] Successful login for user: %s", targetUsername)
	return connect.NewResponse(&pb.LoginResponse{Token: tokenString}), nil
}

// ==========================================
// USER MANAGEMENT
// ==========================================
func (s *TheorosServer) GenerateToken(ctx context.Context, req *connect.Request[pb.GenerateTokenRequest]) (*connect.Response[pb.GenerateTokenResponse], error) {
	username := strings.TrimSpace(req.Msg.Username)
	keyBytes := make([]byte, 24)
	rand.Read(keyBytes)

	// Format token as th-<username>-<secret>
	plainToken := fmt.Sprintf("th-%s-%s", username, hex.EncodeToString(keyBytes))
	hash, _ := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, "theoros-users", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if _, exists := sec.Data[username]; exists {
			return errors.New("user already exists. Use 'user reset' to overwrite.")
		}
		if sec.Data == nil {
			sec.Data = make(map[string][]byte)
		}
		sec.Data[username] = hash
		_, err = s.clientset.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{})
		return err
	})

	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&pb.GenerateTokenResponse{Token: plainToken}), nil
}

func (s *TheorosServer) ResetUser(ctx context.Context, req *connect.Request[pb.ResetUserRequest]) (*connect.Response[pb.ResetUserResponse], error) {
	username := strings.TrimSpace(req.Msg.Username)
	keyBytes := make([]byte, 24)
	rand.Read(keyBytes)

	// Format token as th-<username>-<secret>
	plainToken := fmt.Sprintf("th-%s-%s", username, hex.EncodeToString(keyBytes))
	hash, _ := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, "theoros-users", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if _, exists := sec.Data[username]; !exists {
			return errors.New("user does not exist")
		}

		sec.Data[username] = hash
		delete(sec.Data, username+".needs_reset")

		_, err = s.clientset.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{})
		return err
	})

	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	caller, _ := ctx.Value(userCtxKey).(string)
	isSelf := caller == username

	return connect.NewResponse(&pb.ResetUserResponse{
		Token: plainToken,
		Flag:  isSelf,
	}), nil
}

func (s *TheorosServer) ListUsers(ctx context.Context, req *connect.Request[pb.ListUsersRequest]) (*connect.Response[pb.ListUsersResponse], error) {
	sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, "theoros-users", metav1.GetOptions{})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read users"))
	}
	var users []string
	for u := range sec.Data {
		// Do not return internal flags as usernames
		if !strings.HasSuffix(u, ".needs_reset") {
			users = append(users, u)
		}
	}
	return connect.NewResponse(&pb.ListUsersResponse{Usernames: users}), nil
}

func (s *TheorosServer) DeleteUser(ctx context.Context, req *connect.Request[pb.DeleteUserRequest]) (*connect.Response[pb.DeleteUserResponse], error) {
	username := strings.TrimSpace(req.Msg.Username)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, "theoros-users", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if _, exists := sec.Data[username]; !exists {
			return errors.New("user not found")
		}
		delete(sec.Data, username)
		delete(sec.Data, username+".needs_reset") // Clean up flag if it exists
		_, err = s.clientset.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{})
		return err
	})

	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&pb.DeleteUserResponse{Message: fmt.Sprintf("User '%s' deleted successfully", username)}), nil
}

// ==========================================
// INTERCEPTORS & KUBECTL EXECUTION
// ==========================================
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

			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if username, ok := claims["username"].(string); ok {
					ctx = context.WithValue(ctx, userCtxKey, username)
				}

				// Block commands if password reset is required
				if needsReset, ok := claims["needs_reset"].(bool); ok && needsReset {
					if !strings.HasSuffix(req.Spec().Procedure, "ResetUser") {
						return nil, connect.NewError(
							connect.CodePermissionDenied,
							errors.New("SECURITY POLICY: You are using the default setup token. You must run 'theoros user reset' to rotate your credentials before executing commands."),
						)
					}
				}
			}
			return next(ctx, req)
		}
	}
}

func (s *TheorosServer) ExecuteCommand(ctx context.Context, req *connect.Request[pb.CommandRequest]) (res *connect.Response[pb.CommandResponse], err error) {
	defer func() {
		if r := recover(); r != nil {
			err = connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%v", r))
		}
	}()

	// Extract the authenticated username from Context
	caller, _ := ctx.Value(userCtxKey).(string)
	if caller == "" {
		caller = "unknown"
	}

	// Build the argument list
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

	// AUDIT LOG: Record user and full command executed
	log.Printf("[Audit-Exec] User '%s' ran: kubectl %s", caller, strings.Join(args, " "))

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
	// Authenticate Streaming RPCs (Bypasses Unary Interceptor)
	tokenString := strings.TrimPrefix(req.Header().Get("Authorization"), "Bearer ")
	if tokenString == "" {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization token"))
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return s.secretKey, nil })
	if err != nil || !token.Valid {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
	}

	caller := "unknown"
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if username, ok := claims["username"].(string); ok {
			caller = username
		}
		if needsReset, ok := claims["needs_reset"].(bool); ok && needsReset {
			return connect.NewError(connect.CodePermissionDenied, errors.New("SECURITY POLICY: You must run 'user reset' first."))
		}
	}

	// Build the argument list
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

	// AUDIT LOG: Record streaming execution start
	log.Printf("[Audit-Stream] User '%s' started stream: kubectl %s", caller, strings.Join(args, " "))

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
	err = kubectlCmd.ExecuteContext(ctx)
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
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { return s.secretKey, nil })
	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract username from claims for auditing
	var username string = "unknown"
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if u, ok := claims["username"].(string); ok {
			username = u
		}

		if needsReset, ok := claims["needs_reset"].(bool); ok && needsReset {
			http.Error(w, "SECURITY POLICY: You must run 'user reset' first.", http.StatusForbidden)
			return
		}
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	_, msg, err := ws.ReadMessage()
	if err != nil {
		return
	}
	var req pb.ExecRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return
	}

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

	// AUDIT LOG: Record interactive session start (Moved here AFTER args is built)
	log.Printf("[Audit-TTY] User '%s' opened interactive TTY session: kubectl %s", username, strings.Join(args, " "))

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

	defer func() {
		if r := recover(); r != nil {
			ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\nSession terminated: %v\r\n", r)))
		}
	}()

	_ = kubectlCmd.Execute()
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

func main() {
	log.Println("Starting Theoros Server...")

	clientset, namespace := getClientsetAndNamespace()
	jwtSecretKey := getOrGenerateJWTSecret(clientset, namespace)

	initUserSecret(clientset, namespace)

	server := &TheorosServer{
		secretKey: jwtSecretKey,
		clientset: clientset,
		namespace: namespace,
	}

	mux := http.NewServeMux()
	path, handler := v1connect.NewKubernetesServiceHandler(server, connect.WithInterceptors(NewAuthInterceptor(jwtSecretKey)))

	mux.Handle(path, handler)
	mux.HandleFunc("/ws/exec", server.WebSocketHandler)

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
