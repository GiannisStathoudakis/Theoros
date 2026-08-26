package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	"golang.org/x/crypto/argon2"
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
// CRYPTO ENGINE
// ==========================================
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func encrypt(data []byte, password string) []byte {
	// Generate a secure, random 16-byte salt
	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)

	// Derive the key using the new random salt
	block, _ := aes.NewCipher(deriveKey(password, salt))
	gcm, _ := cipher.NewGCM(block)

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// [Salt][Nonce + Ciphertext]
	return append(salt, ciphertext...)
}

func decrypt(data []byte, password string) ([]byte, error) {
	// Ensure the file is at least long enough to hold a 16-byte salt + 12-byte nonce
	if len(data) < 28 {
		return nil, fmt.Errorf("corrupted or invalid file")
	}

	// Extract the 16-byte salt from the very beginning of the file
	salt := data[:16]

	//Derive the key using the extracted salt
	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Separate the Nonce and the Ciphertext
	nonceSize := gcm.NonceSize()
	nonce := data[16 : 16+nonceSize]
	ciphertext := data[16+nonceSize:]

	// Decrypt
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
func getPassword(promptMsg string) string {
	fmt.Print(promptMsg)
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

func emptyCompleter(d prompt.Document) []prompt.Suggest {
	return nil
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

		rawInput := prompt.Input("> ", emptyCompleter)
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
			rawURL := prompt.Input("Enter Cluster URL (e.g., theoros.site.com): ", emptyCompleter)
			baseURL := strings.TrimSpace(rawURL)

			if baseURL == "" {
				continue
			}

			if strings.HasPrefix(baseURL, "http://") {
				fmt.Println("\nError: Plain HTTP is strictly prohibited by Theoros security policy. Please use HTTPS.")
				time.Sleep(2 * time.Second)
				continue
			}

			// Auto-prefix with HTTPS if missing
			if !strings.HasPrefix(baseURL, "https://") {
				baseURL = "https://" + baseURL
			}

			fmt.Print("Probing server... ")

			probeClient := &http.Client{
				Timeout: 3 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Allows probing self-signed certs
				},
			}

			resp, err := probeClient.Get(baseURL)

			if err != nil {
				fmt.Println("Failed (Could not reach server). Ensure your cluster is accessible over HTTPS.")
				time.Sleep(2 * time.Second)
				continue
			}

			fmt.Println("Success.")
			if resp != nil {
				resp.Body.Close()
			}

			// Ask if they are using self-signed certs for local labs
			rawCert := prompt.Input("Is the certificate self-signed? (y/n): ", emptyCompleter)
			certInput := strings.ToLower(strings.TrimSpace(rawCert))
			insecure := certInput == "y" || certInput == "yes"

			// Get API Key and Login
			newKey := strings.TrimSpace(getPassword("Enter API Key: "))

			customHttpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
				},
			}

			client := v1connect.NewKubernetesServiceClient(customHttpClient, baseURL)

			// Auto-Setup Flow Magic
			loginResp, loginErr := client.Login(context.Background(), connect.NewRequest(&pb.LoginRequest{Token: newKey}))
			if loginErr != nil {
				feedbackMsg = "Authentication failed. Invalid API Key."
				continue
			}

			if newKey == "th-admin-setup" {
				fmt.Println("\n[Security] Default bootstrap token detected!")
				fmt.Println("Rotating to a new secure token automatically...")

				tempToken := loginResp.Msg.Token
				req := connect.NewRequest(&pb.ResetUserRequest{Username: "admin"})
				req.Header().Set("Authorization", "Bearer "+tempToken)

				resetResp, resetErr := client.ResetUser(context.Background(), req)
				if resetErr != nil {
					feedbackMsg = "Failed to auto-rotate default token: " + resetErr.Error()
					continue
				}

				newKey = resetResp.Msg.Token
				fmt.Printf("\nSuccess! Your new permanent token is:\n%s\n(It has been saved to your vault automatically)\n", newKey)
				time.Sleep(3 * time.Second)
			}

			cfg.Connections = append(cfg.Connections, Connection{URL: baseURL, Key: newKey, Insecure: insecure})
			saveConfig(cfg, masterPassword)
			feedbackMsg = "Connection added successfully!"

			continue
		}

		// Connect to Existing Cluster
		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(cfg.Connections) {
			feedbackMsg = "Invalid input. Please type a valid number from the list above."
			continue
		}

		if err = startInteractiveSession(cfg.Connections[idx-1], &cfg, masterPassword); err != nil {
			feedbackMsg = err.Error()
		}
	}
}

// ==========================================
// INTERACTIVE SESSION ENGINE
// ==========================================
func startInteractiveSession(conn Connection, cfg *Config, masterPassword string) error {
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
	fmt.Printf("Connected to %s\n", conn.URL)

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
			fmt.Println("                Theoros CLI Help                ")
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
				case "reset":
					if len(parts) != 3 {
						fmt.Println("Usage: user reset <username>")
						return
					}
					req := connect.NewRequest(&pb.ResetUserRequest{Username: parts[2]})
					req.Header().Set("Authorization", "Bearer "+sessionToken)
					var resp *connect.Response[pb.ResetUserResponse]

					if resp, err = client.ResetUser(context.Background(), req); err == nil {
						if resp.Msg.Flag {
							// This means they reset THEIR OWN token!
							// Update the vault in memory and save to disk silently
							for i, configConn := range cfg.Connections {
								if configConn.URL == conn.URL {
									cfg.Connections[i].Key = resp.Msg.Token
									conn.Key = resp.Msg.Token
									saveConfig(*cfg, masterPassword)
									break
								}
							}
							fmt.Printf("Your token was reset! Your local Theoros vault was updated automatically.\n(New Token: %s)\n", resp.Msg.Token)
						} else {
							// They reset someone else's token
							fmt.Printf("Token reset for '%s':\n%s\nSend this to them securely!\n", parts[2], resp.Msg.Token)
						}
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
		}

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
			// ROUTE A: WebSockets
			if stateErr == nil {
				term.Restore(fd, healthyState)
			}

			// Enforces secure wss:// strictly.
			wsURL := strings.Replace(conn.URL, "https://", "wss://", 1) + "/ws/exec"

			dialer := *websocket.DefaultDialer
			if conn.Insecure {
				dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}

			headers := http.Header{}
			headers.Add("Authorization", "Bearer "+sessionToken)

			ws, _, err := dialer.Dial(wsURL, headers)
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

			go func() {
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

			for {
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
			}

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
					{Text: "reset", Description: "Reset a user's token"},
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
