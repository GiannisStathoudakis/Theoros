# Theoros

## What is Theoros?
**Theoros** is an interactive terminal and remote-execution agent for Kubernetes.

Distributing highly-privileged `kubeconfig` files to host machines presents significant security challenges. Theoros is designed to eliminate this risk. The agent executes commands on behalf of the user and streams the results back to the terminal. This architecture removes the need for local `kubeconfig` files, providing clean, zero-trust access to the cluster.

> **Security & Privilege Model:** Theoros is built for **Trusted DevOps and Platform Engineering teams**. It operates on a shared-privilege model, meaning all authenticated users mapped in the Theoros database share the RBAC permissions of the Theoros in-cluster ServiceAccount (typically ClusterAdmin). It is meant to replace distributed admin `kubeconfigs`, not to provide granular RBAC for individual developers.

---

## Architecture & Security Features

Built entirely with security in mind, Theoros operates on a strict split architecture between a local client and an in-cluster agent.

### 1. The Client (Interactive Terminal)
* **Secure Local Vault:** The client natively supports multiple clusters. Instead of juggling plaintext Kubeconfigs, it acts like a secure vault, heavily encrypting your cluster URLs and authentication tokens locally using **AES-GCM 256** and **Argon2** key derivation.
* **Strict HTTPS:** The client strictly enforces TLS/HTTPS connections to prevent plaintext credential leaks or Man-in-the-Middle downgrade attacks.
* **TAB Functionality:** The interactive prompt features robust TAB auto-completion and syntax highlighting, making navigating cluster resources fast and intuitive.
* **Client-Side User Management:** Administrators can seamlessly generate, list, and manage user identities and access tokens directly from the client interface.

### 2. The Server (In-Cluster Agent)
* **Zero-Trust Bootstrapping:** The server auto-generates a one-time setup token upon installation, but completely locks down cluster execution until the client cryptographically rotates it to a permanent token.
* **100% Stateless & HA Ready:** Theoros uses native Kubernetes Secrets for user identities and cryptographic signing keys. Scale to 3+ replicas for High Availability without needing persistent volumes (`PVCs`) or external databases.
* **Application-Level Audit Logging:** Because standard Kubernetes audit logs only see the Theoros ServiceAccount, the Theoros server inherently logs the exact User, Action, and Command for every execution, stream, and interactive TTY session to the pod's standard output.

---

## Quick Start & Deployment

Theoros is designed to drop cleanly into existing Kubernetes environments with zero external dependencies.

### 1. Deploy the Server
Use the provided Helm chart to deploy the lightweight Go pod into your cluster. No external secrets or database configurations are required.

### 2. Connect & Auto-Setup
Add the cluster's routing URL and your credentials to the local Theoros client. 
For your very first login, use the default bootstrap credentials:
* **Username:** `admin` (implied by the token)
* **API Token:** `th-admin-setup`

*Note: The Theoros Client will automatically detect the bootstrap token, securely rotate it with the server, and save the newly generated permanent token into your local encrypted vault without any manual intervention.*

### 3. Route Traffic & Security Best Practices
Expose the server using your preferred Ingress controller or Gateway API to handle SSL termination. The server communicates via standard HTTP/1.1 and HTTP/2, alongside WebSockets, over the Connect-RPC framework.

**Security Recommendation:** Because Theoros provides direct remote-execution access to your cluster, we highly recommend exposing the server's ingress or gateway api route **only to internal private networks or behind a VPN**. Keeping the endpoint off the public internet ensures that unauthorized actors cannot scan, probe, or attempt to interact with your cluster's entry point.

---

## Managing Users (Client CLI)

Once connected as an administrator, you can manage team access directly from the client's interactive prompt. When you add a new user, Theoros will immediately generate and return the token that user needs to authenticate.

**Add a new team member:**
```bash
> user generate john.doe
Token generated for 'john.doe':
th-john.doe-f2d68e8b096828f4c8a9b282bbaa650ecc93f7f1
Copy this now!
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

**Resetting another team member's token:**
```bash
> user reset john.doe
Token reset for 'john.doe':
th-john.doe-f2d68e8b...
Send this to them securely!
```
**Resetting your own token (updates your vault automatically):**
```bash
> user reset john.doe
Your token was reset! Your local Theoros vault was updated automatically.
(New Token: th-john.doe-abc123def456...)
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

---

## License

This project is open-source and licensed under the [MIT License](LICENSE).
