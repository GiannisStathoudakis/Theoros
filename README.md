# Theoros

## What is Theoros?
**Theoros** is a Proof of Concept (PoC) architectural project demonstrating how to build a **Zero-Trust, Identity-Aware Proxy** for Kubernetes cluster operations.

This project was built to address a fundamental security philosophy: **The Kubernetes API Server (port 6443) should never be exposed to humans, VPNs, or the public internet.** 

Instead of distributing highly privileged `kubeconfig` files—which present a massive security and lifecycle management risk—Theoros demonstrates an alternative architecture. It drops a strict API Gateway in front of cluster operations, acting as a secure "jump box." Users authenticate via secure, personal access tokens (similar to GitHub Personal Access Tokens) over standard HTTPS (port 443), while the native Kubernetes API remains completely hidden behind internal firewalls.

> **Architectural Disclaimer:** Theoros is an experimental implementation of the **API Gateway / Proxy Pattern** used by enterprise tools like Teleport. It is designed for **Trusted DevOps and Platform Engineering teams** to demonstrate attack surface reduction. It operates on a shared-privilege execution model to prove the concept of hiding the control plane, rather than serving as a production-ready RBAC replacement.

---

## The Security Thesis (Why build this?)

Traditional Kubernetes deployments often expose the API server to a corporate VPN, relying on network-level trust. If an attacker breaches the VPN, the entire K8s API surface area is exposed to probing and zero-day exploits.

**The Theoros Architecture solves this by:**
1. **Network Invisibility:** The external firewall drops all human traffic to port 6443. The control plane is isolated to internal machine-to-machine traffic only.
2. **Protocol Inspection:** By forcing operational traffic through an Envoy Gateway/Ingress on port 443, traffic can be rate-limited, inspected, and protected by standard WAF rules before it ever reaches the cluster.
3. **Zero Credential Distribution:** `kubeconfigs` are eliminated. If a developer's laptop is compromised, there are no static Kubernetes certificates to steal. 

---

## Features & Implementation

Built entirely in Go, Theoros operates on a strict split architecture between a local client and an in-cluster agent to execute the proxy pattern.

### 1. The Client (Interactive Terminal)
* **Secure Local Vault:** Natively supports multiple clusters. Instead of plaintext Kubeconfigs, it encrypts your cluster URLs and personal access tokens locally using **AES-GCM 256** and **Argon2** key derivation.
* **Strict HTTPS:** Enforces TLS connections to prevent plaintext credential leaks or Man-in-the-Middle downgrade attacks.
* **TAB Functionality:** The interactive prompt features robust TAB auto-completion and syntax highlighting via WebSockets, making navigating cluster resources fast and intuitive.
* **Client-Side User Management:** Administrators can seamlessly generate, list, and manage user identities and token hashes directly from the client interface.

### 2. The Server (In-Cluster Agent)
* **API Wrapper:** Wraps the native `k8s.io/cli-runtime` source code directly inside the Go binary, safely translating client REST/WebSocket requests into internal API executions.
* **GitHub-Style Authentication:** User authentication relies on secure hashed tokens (comparable to GitHub Personal Access Tokens). Upon a successful login challenge, the server issues a short-lived, stateless **JWT** for session efficiency, while user credentials remain securely salted and hashed using **bcrypt** in a Kubernetes Secret database.
* **100% Stateless & HA Ready:** Theoros uses native Kubernetes Secrets for user password hashes and cryptographic signing keys. Scale to 3+ replicas for High Availability without needing persistent volumes (`PVCs`).
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

**Security Recommendation:** Because Theoros provides direct remote-execution access to your cluster, we highly recommend exposing the server's Ingress or Gateway API route **only to internal private networks or behind a VPN**. Keeping the endpoint off the public internet ensures that unauthorized actors cannot scan, probe, or attempt to interact with your cluster's entry point.

---

## Managing Users (Client CLI)

Once connected as an administrator, you can manage team access directly from the client's interactive prompt. When you add a new user, Theoros will immediately generate and return the token that user needs to authenticate.

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
