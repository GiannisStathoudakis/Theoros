package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/c-bata/go-prompt"
	"github.com/gorilla/websocket"
	"golang.org/x/term"

	pb "github.com/GiannisStathoudakis/Theoros/gen/theoros/v1"
	"github.com/GiannisStathoudakis/Theoros/gen/theoros/v1/v1connect"
)

// ==========================================
// DATA STRUCTURES & INIT
// ==========================================
type Config struct {
	Connections []Connection `json:"connections"`
}
type Connection struct {
	URL      string
	Key      string
	Insecure bool
}

var configPath string

func init() {
	home, _ := os.UserHomeDir()
	theorosDir := filepath.Join(home, ".Theoros")
	os.MkdirAll(theorosDir, 0700)
	configPath = filepath.Join(theorosDir, "config.enc")
}

// ==========================================
// CRYPTO ENGINE (AES-GCM)
// ==========================================
func deriveKey(password string) []byte { hash := sha256.Sum256([]byte(password)); return hash[:] }
func encrypt(data []byte, password string) []byte {
	block, _ := aes.NewCipher(deriveKey(password))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil)
}
func decrypt(data []byte, password string) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(password))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ==========================================
// CONFIG MANAGEMENT
// ==========================================
func saveConfig(cfg Config, password string) {
	data, _ := json.Marshal(cfg)
	os.WriteFile(configPath, encrypt(data, password), 0600)
}
func loadConfig(password string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, err
	}
	decrypted, err := decrypt(data, password)
	if err != nil {
		return cfg, fmt.Errorf("invalid password or corrupted file")
	}
	json.Unmarshal(decrypted, &cfg)
	return cfg, nil
}

// ==========================================
// CLI HELPERS
// ==========================================
func clearScreen() { fmt.Print("\033[H\033[2J") }
func getPassword(prompt string) string {
	fmt.Print(prompt)
	bytepw, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(bytepw)
}
func sanitizeInput(in string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, in)
}

// ==========================================
// MAIN MENU LOOP
// ==========================================
func main() {
	clearScreen()
	var cfg Config
	var masterPassword string

	// Vault Initialization or Login
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		for {
			pass1 := getPassword("Set Master Password: ")
			if pass1 == getPassword("Confirm Master Password: ") && pass1 != "" {
				masterPassword = pass1
				break
			}
			fmt.Println("Passwords do not match or are empty.")
		}
		cfg = Config{Connections: []Connection{}}
		saveConfig(cfg, masterPassword)
	} else {
		for {
			masterPassword = getPassword("Enter Master Password: ")
			loadedCfg, err := loadConfig(masterPassword)
			if err == nil {
				cfg = loadedCfg
				break
			}
			fmt.Println("Incorrect password or corrupted file.")
		}
	}

	reader := bufio.NewReader(os.Stdin)
	var feedbackMsg string

	// Vault Selection Menu
	for {
		clearScreen()
		fmt.Println("=======================================\n           Theoros Client Vault          \n=======================================")
		if feedbackMsg != "" {
			fmt.Printf("%s\n---------------------------------------\n", feedbackMsg)
			feedbackMsg = ""
		}

		fmt.Println("[0] Add a new connection")
		for i, conn := range cfg.Connections {
			fmt.Printf("[%d] %s\n", i+1, conn.URL)
		}
		fmt.Print("\n> ")

		rawInput, _ := reader.ReadString('\n')
		input := strings.TrimSpace(rawInput)

		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" {
			clearScreen()
			os.Exit(0)
		}
		if input == "help" {
			feedbackMsg = "You are in the Vault Menu. Type a number to connect to a cluster first! Once connected, type 'help' again."
			continue
		}

		// Delete Connection
		if strings.HasPrefix(input, "delete") {
			parts := strings.Fields(input)
			if len(parts) > 1 {
				if idx, err := strconv.Atoi(parts[1]); err == nil && idx > 0 && idx <= len(cfg.Connections) {
					cfg.Connections = append(cfg.Connections[:idx-1], cfg.Connections[idx:]...)
					saveConfig(cfg, masterPassword)
				}
			}
			continue
		}

		// Add New Connection
		if input == "0" {
			fmt.Print("Enter Cluster URL (e.g., theoros.site.com): ")
			rawURL, _ := reader.ReadString('\n')
			baseURL := strings.TrimSpace(rawURL)

			if baseURL == "" {
				continue
			}

			// 1. Auto-prefix with https:// if no prefix is given
			if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
				baseURL = "https://" + baseURL
			}

			fmt.Print("Probing server... ")

			// 2. Create a temporary "probe" client (ignores cert errors just to see if the port is open)
			probeClient := &http.Client{
				Timeout: 3 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			finalURL := baseURL
			isHTTPS := strings.HasPrefix(baseURL, "https://")

			// 3. Send a quick test request
			resp, err := probeClient.Get(baseURL)

			if err != nil && isHTTPS {
				// HTTPS failed (e.g., connection refused). Fallback to HTTP test!
				httpURL := strings.Replace(baseURL, "https://", "http://", 1)
				respHTTP, errHTTP := probeClient.Get(httpURL)

				if errHTTP == nil {
					finalURL = httpURL
					isHTTPS = false
					fmt.Println("Detected HTTP.")
					if respHTTP != nil {
						respHTTP.Body.Close()
					}
				} else {
					fmt.Println("Failed (Could not reach server on HTTPS or HTTP).")
					time.Sleep(2 * time.Second)
					continue
				}
			} else if err == nil {
				fmt.Println("Detected HTTPS.")
				if resp != nil {
					resp.Body.Close()
				}
			} else {
				fmt.Println("Failed (Could not reach server).")
				time.Sleep(2 * time.Second)
				continue
			}

			// 4. Only ask about self-signed certs if we are actually using HTTPS!
			insecure := false
			if isHTTPS {
				fmt.Print("Is the certificate self-signed? (y/n): ")
				rawCert, _ := reader.ReadString('\n')
				certInput := strings.ToLower(strings.TrimSpace(rawCert))
				insecure = certInput == "y" || certInput == "yes"
			}

			// 5. Get API Key and Login
			newKey := strings.TrimSpace(getPassword("Enter API Key: "))

			customHttpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
				},
			}

			client := v1connect.NewKubernetesServiceClient(customHttpClient, finalURL)

			if _, loginErr := client.Login(context.Background(), connect.NewRequest(&pb.LoginRequest{Token: newKey})); loginErr == nil {
				cfg.Connections = append(cfg.Connections, Connection{URL: finalURL, Key: newKey, Insecure: insecure})
				saveConfig(cfg, masterPassword)
				feedbackMsg = "Connection added successfully!"
			} else {
				feedbackMsg = "Authentication failed. Invalid API Key."
			}
			continue
		}

		// Connect to Existing Cluster
		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(cfg.Connections) {
			feedbackMsg = "Invalid input. Please type a valid number from the list above."
			continue
		}

		if err = startInteractiveSession(cfg.Connections[idx-1]); err != nil {
			feedbackMsg = err.Error()
		}
	}
}

// ==========================================
// INTERACTIVE SESSION ENGINE
// ==========================================
func startInteractiveSession(conn Connection) error {
	customHttpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: conn.Insecure},
		},
	}

	client := v1connect.NewKubernetesServiceClient(customHttpClient, conn.URL)
	loginResp, err := client.Login(context.Background(), connect.NewRequest(&pb.LoginRequest{Token: conn.Key}))
	if err != nil {
		return fmt.Errorf("authentication failed")
	}
	sessionToken := loginResp.Msg.Token

	clearScreen()
	fmt.Printf("🔗 Connected to %s\n", conn.URL)

	fd := int(os.Stdin.Fd())
	healthyState, stateErr := term.GetState(fd)

	// Helper to refresh expired JWTs seamlessly
	refreshSession := func() error {
		resp, err := client.Login(context.Background(), connect.NewRequest(&pb.LoginRequest{Token: conn.Key}))
		if err == nil {
			sessionToken = resp.Msg.Token
		}
		return err
	}

	executor := func(in string) {
		in = strings.TrimSpace(sanitizeInput(in))
		if in == "" {
			return
		}

		// Built-in Help Menu
		if in == "help" {
			fmt.Println("==================================================")
			fmt.Println("                 Theoros CLI Help                 ")
			fmt.Println("==================================================")
			fmt.Println("Kubernetes Commands:")
			fmt.Println("  - get pods [-A] [-w]               List or watch pods/events")
			fmt.Println("  - logs <pod> [-n <ns>] [-f]        View or follow container logs")
			fmt.Println("  - exec -it <pod> -n <ns> -- /bin/sh  Interactive shell")
			fmt.Println("  - (Any standard kubectl command is supported!)")
			fmt.Println("\nUser Management Commands:")
			fmt.Println("  - user list                        List registered users")
			fmt.Println("  - user generate <username>         Generate a new access token")
			fmt.Println("  - user delete <username>           Revoke and delete a user")
			fmt.Println("\nClient Commands:")
			fmt.Println("  - clear                            Clear the terminal screen")
			fmt.Println("  - exit / quit                      Disconnect and exit")
			fmt.Println("==================================================")
			return
		}

		// Exit / Clear Intercepts
		if in == "exit" || in == "clear" || in == "quit" {
			clearScreen()
			if in == "exit" || in == "quit" {
				if stateErr == nil {
					term.Restore(fd, healthyState)
				}
				os.Exit(0)
			}
			return
		}

		parts := strings.Fields(strings.TrimPrefix(in, "kubectl "))
		action := parts[0]

		// --- USER MANAGEMENT ROUTE ---
		if action == "user" {
			if len(parts) < 2 {
				fmt.Println("Usage: user [list | generate <username> | delete <username>]")
				return
			}
			for retryCount := 0; retryCount < 3; retryCount++ {
				var err error
				switch parts[1] {
				case "list":
					req := connect.NewRequest(&pb.ListUsersRequest{})
					req.Header().Set("Authorization", "Bearer "+sessionToken)
					var resp *connect.Response[pb.ListUsersResponse]
					if resp, err = client.ListUsers(context.Background(), req); err == nil {
						fmt.Println("--- Registered Users ---")
						for _, u := range resp.Msg.Usernames {
							fmt.Printf("- %s\n", u)
						}
						fmt.Println("------------------------")
						return
					}
				case "generate":
					if len(parts) != 3 {
						fmt.Println("Usage: user generate <username>")
						return
					}
					req := connect.NewRequest(&pb.GenerateTokenRequest{Username: parts[2]})
					req.Header().Set("Authorization", "Bearer "+sessionToken)
					var resp *connect.Response[pb.GenerateTokenResponse]
					if resp, err = client.GenerateToken(context.Background(), req); err == nil {
						fmt.Printf("Token generated for '%s':\n%s\nCopy this now!\n", parts[2], resp.Msg.Token)
						return
					}
				case "delete":
					if len(parts) != 3 {
						fmt.Println("Usage: user delete <username>")
						return
					}
					req := connect.NewRequest(&pb.DeleteUserRequest{Username: parts[2]})
					req.Header().Set("Authorization", "Bearer "+sessionToken)
					var resp *connect.Response[pb.DeleteUserResponse]
					if resp, err = client.DeleteUser(context.Background(), req); err == nil {
						fmt.Printf("%s\n", resp.Msg.Message)
						return
					}
				default:
					fmt.Println("Unknown user command.")
					return
				}
				// Auto-retry on token expiration
				if connect.CodeOf(err) == connect.CodeUnauthenticated && refreshSession() == nil {
					continue
				}
				fmt.Printf("Error: %v\n", err)
				return
			}
		}

		// --- KUBECTL COMMAND ROUTING ---
		var flags []string
		if len(parts) > 1 {
			flags = parts[1:]
		} // Pass everything after action to flags for robust parsing

		isInteractive, isStreaming := false, false
		if action == "exec" {
			for _, f := range flags {
				if f == "-it" || f == "-ti" || f == "-i" {
					isInteractive = true
				}
			}
		}
		for _, f := range flags {
			if f == "-w" || f == "--watch" || f == "-f" || f == "--follow" {
				isStreaming = true
			}
		}

		if isInteractive {
			// ROUTE A: WebSockets (Interactive TTY Shell)
			if stateErr == nil {
				term.Restore(fd, healthyState)
			} // Yield keyboard to OS

			wsURL := strings.Replace(conn.URL, "http", "ws", 1) + "/ws/exec?token=" + sessionToken

			dialer := *websocket.DefaultDialer
			if conn.Insecure {
				dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}

			ws, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				fmt.Printf("\r\nFailed to open interactive session: %v\r\n", err)
				return
			}

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() { <-sigCh; ws.Close() }()

			cmdReq := &pb.ExecRequest{Action: action, Flags: flags}
			reqBytes, _ := json.Marshal(cmdReq)
			ws.WriteMessage(websocket.TextMessage, reqBytes)

			go func() { // Keyboard -> Server
				buf := make([]byte, 1024)
				for {
					n, err := os.Stdin.Read(buf)
					if err != nil {
						break
					}
					if ws != nil && ws.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
						break
					}
				}
			}()

			for { // Server -> Screen
				_, msg, err := ws.ReadMessage()
				if err != nil {
					break
				}
				os.Stdout.Write(msg)
			}

			ws.Close()
			signal.Stop(sigCh)
			fmt.Print("\n(Session Ended - Press Enter to return to prompt)\n")
			return

		} else if isStreaming {
			// ROUTE B: Server-Side Streams (Logs -f, Get -w)
			if stateErr == nil {
				term.Restore(fd, healthyState)
			} // Yield keyboard for Ctrl+C

			streamCtx, cancelStream := context.WithCancel(context.Background())
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() { <-sigCh; cancelStream() }()

			req := connect.NewRequest(&pb.ExecRequest{Action: action, Flags: flags})
			req.Header().Set("Authorization", "Bearer "+sessionToken)
			stream, err := client.InteractiveExec(streamCtx, req)

			if err == nil {
				for stream.Receive() {
					resp := stream.Msg()
					if len(resp.Stdout) > 0 {
						fmt.Print(string(resp.Stdout))
					}
					if len(resp.Stderr) > 0 {
						fmt.Print(string(resp.Stderr))
					}
				}
				if stream.Err() != nil && connect.CodeOf(stream.Err()) == connect.CodeCanceled {
					fmt.Println("\n^C (Stream Terminated)")
				}
				stream.Close()
			} else {
				fmt.Printf("\nStream Error: %v\n", err)
			}

			signal.Stop(sigCh)
			cancelStream()
			return

		} else {
			// ROUTE C: Standard Unary Execution
			for retryCount := 0; retryCount < 3; retryCount++ {
				req := connect.NewRequest(&pb.CommandRequest{Action: action, Flags: flags})
				req.Header().Set("Authorization", "Bearer "+sessionToken)
				resp, err := client.ExecuteCommand(context.Background(), req)
				if err != nil {
					if connect.CodeOf(err) == connect.CodeUnauthenticated && refreshSession() == nil {
						continue
					}
					fmt.Printf("Error: %v\n", err)
					return
				}
				fmt.Print(resp.Msg.Output)
				return
			}
			fmt.Println("Session expired. Please log in again.")
		}
	}

	// ==========================================
	// CACHE & AUTOCOMPLETE
	// ==========================================
	type cacheEntry struct {
		suggestions []prompt.Suggest
		timestamp   time.Time
	}
	autocompleteCache := make(map[string]cacheEntry)

	completer := func(d prompt.Document) []prompt.Suggest {
		line := sanitizeInput(d.TextBeforeCursor())
		cleanLine := strings.TrimPrefix(line, "kubectl ")
		args := strings.Fields(cleanLine)
		if strings.HasSuffix(cleanLine, " ") {
			args = append(args, "")
		}
		if len(args) == 0 {
			return nil
		}

		if args[0] == "user" {
			if len(args) <= 2 {
				userCmds := []prompt.Suggest{
					{Text: "list", Description: "List registered users"},
					{Text: "generate", Description: "Generate a new user token"},
					{Text: "delete", Description: "Delete a user"},
				}
				return prompt.FilterHasPrefix(userCmds, args[len(args)-1], true)
			}
			return nil
		}
		if args[0] == "exit" || args[0] == "quit" || args[0] == "clear" || args[0] == "help" {
			return nil
		}

		currentWord := args[len(args)-1]
		contextArgs := args[:len(args)-1]
		contextKey := strings.Join(contextArgs, " ")

		isFlag := strings.HasPrefix(currentWord, "-")
		if isFlag {
			contextKey += " [FLAGS]"
		}

		ttl := time.Hour * 24
		if len(contextArgs) >= 2 && !isFlag {
			ttl = time.Second * 2
		}

		if entry, exists := autocompleteCache[contextKey]; exists && time.Since(entry.timestamp) < ttl {
			return prompt.FilterHasPrefix(entry.suggestions, currentWord, true)
		}

		fetchArgs := make([]string, len(contextArgs))
		copy(fetchArgs, contextArgs)
		if isFlag {
			fetchArgs = append(fetchArgs, "-")
		} else {
			fetchArgs = append(fetchArgs, "")
		}

		req := connect.NewRequest(&pb.GetCompletionsRequest{Args: fetchArgs})
		req.Header().Set("Authorization", "Bearer "+sessionToken)

		resp, err := client.GetCompletions(context.Background(), req)
		if err != nil {
			if connect.CodeOf(err) == connect.CodeUnauthenticated && refreshSession() == nil {
				req.Header().Set("Authorization", "Bearer "+sessionToken)
				resp, _ = client.GetCompletions(context.Background(), req)
			}
			if resp == nil {
				return nil
			}
		}

		var suggestions []prompt.Suggest
		for _, s := range resp.Msg.Suggestions {
			suggestions = append(suggestions, prompt.Suggest{Text: s})
		}

		autocompleteCache[contextKey] = cacheEntry{suggestions: suggestions, timestamp: time.Now()}
		return prompt.FilterHasPrefix(suggestions, currentWord, true)
	}

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("theoros> "),
		prompt.OptionTitle("Theoros Interactive Session"),
		prompt.OptionPrefixTextColor(prompt.Cyan),
	)
	p.Run()

	return nil
}
