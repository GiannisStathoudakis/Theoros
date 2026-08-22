# Theoros

## What is Theoros?
**Theoros** is a zero-trust, interactive terminal and remote-execution agent for Kubernetes.

Distributing highly-privileged `kubeconfig` files to hosts presents significant security challenges. Theoros is designed to eliminate this risk. The agent executes commands on behalf of the user and streams the results back to the terminal. This architecture removes the need for local `kubeconfig` files or complex VPN setups, providing clean, zero-trust access to the cluster.

Built entirely with security in mind, Theoros operates on a strict split architecture between a local client and an in-cluster agent.

---

## Architecture & Features

### 1. The Client (Interactive Terminal)
* **Built Like a Password Manager:** The client natively supports multiple clusters. Instead of juggling Kubeconfigs, it acts like a secure vault, heavily encrypting the target URLs and authentication tokens for all your environments in one place.
* **TAB Functionality:** The interactive prompt features robust TAB auto-completion and syntax highlighting, making navigating cluster resources fast and intuitive.
* **Client-Side User Management:** Administrators can seamlessly generate, list, and manage user identities and access tokens directly from the client interface.

### 2. The Server (In-Cluster Agent)
* **Lightweight Go Pod:** The server is a highly efficient Go binary running as a standard pod. There is no need for users to edit or manage any `kubeconfig` files—administrators simply deploy the server and it runs.
* **Connect-RPC Powered:** The system leverages the Connect-RPC framework for fast, reliable, and highly compatible communication between the client and the cluster.
* **Standard Web Security:** To ensure maximum compatibility and security, Theoros does not manage its own certificates. Traffic and SSL/TLS termination must be routed through your standard Ingress controller or Gateway API.

---

## Quick Start & Deployment

Theoros is designed to drop cleanly into existing Kubernetes environments:

### 1. Create the Credentials Secret
Before deploying the server, you must provide a Kubernetes Secret to store the core credentials. Create a secret named `theoros-cred` containing your admin username and password separated by a colon (`:`):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: theoros-cred
  namespace: theoros
type: Opaque
stringData:
  # Format must be "username:password"
  credentials: "admin:super_secret_password"
```
*(Note: If you are using ExternalSecrets or Vault, simply map your backend values to the `credentials` key in the target secret).*

### 2. Deploy the Server
Use the provided Helm chart to deploy the lightweight Go pod into your cluster.

### 3. Route Traffic
Expose the server using your preferred Ingress controller or Gateway API to handle SSL termination.

### 4. Connect the Client
Add the cluster's routing URL and your credentials to the local Theoros client, and begin securely executing commands.

---

## Managing Users (Client CLI)

Once connected as an administrator, you can manage team access directly from the client's interactive prompt. When you add a new user, Theoros will immediately generate and return the token that user needs to authenticate.

**Add a new user:**
```bash
> user generate john.doe
User 'john.doe' created successfully.
Auth Token: th_token_abc123def456...  # Share this securely with the user
```

**List all active users:**
```bash
> user list
admin
john.doe
jane.smith
```

**Delete/Revoke a user:**
```bash
> user delete john.doe
User 'john.doe' has been successfully removed.
```

---

## Installation (Client)

The Theoros client is fully cross-platform (Windows, macOS, and Linux). 

If you have Go installed on your machine, you can build the client directly from source:

```bash
# Clone the repository
git clone https://github.com/GiannisStathoudakis/Theoros.git
cd Theoros

# Build the client
go build -o theoros ./cmd/client/main.go

# Run it!
./theoros    # On Linux/macOS
theoros.exe  # On Windows
```

---

## 🚀 Roadmap

While secure `kubectl` remote execution is fully functional today, Theoros is actively expanding into a complete observability command center. Planned data source integrations include:

* **Log Streaming:** Native integration with **Grafana Loki** and **VictoriaLogs** to securely view, filter, and stream cluster logs directly within the terminal.
* **Metrics Querying:** Direct integration with **Prometheus** (and similar metric backends) to query cluster health, monitor application builds, and view resource usage without leaving the command line.
