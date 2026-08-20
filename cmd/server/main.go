package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	// Generated Protobuf Imports
	pb "github.com/GiannisStathoudakis/Theoros/gen/theoros/v1"
	"github.com/GiannisStathoudakis/Theoros/gen/theoros/v1/v1connect"

	// kubectl source code
	"k8s.io/kubectl/pkg/cmd"
)

// Pass the secret key into the struct so we can sign new tokens
type TheorosServer struct {
	secretKey []byte
}

// --- NEW LOGIN GENERATOR ---
func (s *TheorosServer) Login(
	ctx context.Context,
	req *connect.Request[pb.LoginRequest],
) (*connect.Response[pb.LoginResponse], error) {

	// Create a simple JWT that expires in 24 hours
	claims := jwt.MapClaims{
		"authorized": true,
		"exp":        time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}

	log.Println("[Audit] Generated new JWT token via Login RPC")

	return connect.NewResponse(&pb.LoginResponse{
		Token: tokenString,
	}), nil
}

func (s *TheorosServer) ExecuteCommand(
	ctx context.Context,
	req *connect.Request[pb.CommandRequest],
) (*connect.Response[pb.CommandResponse], error) {

	log.Printf("[Audit] Executing: %s %s (namespace: '%s', flags: %v)",
		req.Msg.Action,
		req.Msg.Resource,
		req.Msg.Namespace,
		req.Msg.Flags,
	)

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

	kubectlCmd := cmd.NewDefaultKubectlCommand()
	kubectlCmd.SetArgs(args)
	kubectlCmd.SetOut(&outBuf)
	kubectlCmd.SetErr(&errBuf)

	err := kubectlCmd.Execute()
	if err != nil {
		return nil, connect.NewError(
			connect.CodeInvalidArgument,
			fmt.Errorf("command failed: %s", errBuf.String()),
		)
	}

	return connect.NewResponse(&pb.CommandResponse{Output: outBuf.String()}), nil
}

func (s *TheorosServer) InteractiveExec(
	ctx context.Context,
	stream *connect.BidiStream[pb.ExecRequest, pb.ExecResponse],
) error {
	return connect.NewError(connect.CodeUnimplemented, errors.New("interactive exec coming soon"))
}

// JWT INTERCEPTOR
func NewAuthInterceptor(secretKey []byte) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {

			// The Interceptor skips the auth check for the "Login" endpoint!
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

func loadSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(data))), nil
}

func main() {
	log.Println("Starting Theoros Server...")

	jwtSecretKey, err := loadSecret("/etc/theoros/secrets/jwt.key")
	if err != nil {
		log.Fatalf("Fatal: Failed to load JWT secret file. Is the secret mounted? Error: %v", err)
	}

	server := &TheorosServer{
		secretKey: jwtSecretKey,
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
