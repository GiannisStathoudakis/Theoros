> **Theoros** *(Greek: Θεωρός)* - An observer, an envoy, or one who travels to consult an oracle. 
> 
> *Status: 🚧 Currently Under Construction 🚧*

## Overview
**Theoros** is a zero-trust, interactive terminal client and remote-execution agent for Kubernetes. 

Built entirely in Go, it replaces the need for distributing highly-privileged `kubeconfig` files to developer laptops. Instead, users authenticate via a secure client to a lightweight Go agent running inside the cluster. The agent executes commands on their behalf via the official Kubernetes `client-go` library, proxying the results back through any standard Ingress controller or Gateway API.

---

## System Architecture & Security

Theoros is designed with a strict "SecOps" mindset. The architecture is split into two components: the local Client and the in-cluster Server.

### 1. The Client (Interactive Terminal)
* **No Kubeconfigs:** The client knows nothing about Kubernetes certificates. It acts purely as a dumb terminal sending RPC requests.
* **AES-256 Encrypted Vault:** User credentials and tokens are stored in an encrypted local file (`~/.theoros/vault.enc`), unlocked by a single master password upon terminal startup.
* **Interactive REPL:** Built using `c-bata/go-prompt` to provide a Zsh-style interactive dropdown, context-aware autocomplete, and syntax highlighting.

### 2. The Network (Reverse Proxy & Connect-RPC)
* **Ingress / Gateway API:** All traffic routes through a standard reverse proxy (e.g., Nginx, Traefik, HAProxy, or Envoy), which handles SSL/TLS termination using standard web certificates.
* **Legacy-Compatible RPC:** Unlike standard gRPC—which strictly requires HTTP/2 multiplexing and specialized load balancers—communication uses the [Connect RPC](https://connectrpc.com/) framework. Because Connect gracefully supports standard HTTP/1.1 alongside HTTP/2, Theoros works out-of-the-box with older or traditional infrastructure without requiring complex end-to-end HTTP/2 tunneling setups.
* **Dual-Tier Authentication:** 
  * Users are issued a long-lived API Token (acting as their identity).
  * The client exchanges this token for a **short-lived JWT** for actual command execution.
  * The REPL silently handles background JWT rotation so the user experience is never interrupted.

### 3. The Server (In-Cluster Agent)
* **Helm & RBAC:** The server is deployed via a Helm chart, which provisions the necessary `ServiceAccount`, `Roles`, and `RoleBindings`.
* **In-Cluster Execution:** The Go server uses `rest.InClusterConfig()` to communicate directly with the Kubernetes Control Plane, meaning the server itself requires no hardcoded passwords.
* **Encrypted Token Storage:** The server securely stores the API tokens in an encrypted format. For maximum security, the master encryption key is passed via a Kubernetes Secret at deployment time, completely avoiding plaintext environment variables.
* **Server Management CLI:** User identities and their associated tokens are managed via a dedicated server-side CLI. Administrators can easily execute commands within the pod to provision access for new users or instantly revoke tokens.

---

## 🚀 Future Capabilities

While the core focus is currently Kubernetes remote execution, Theoros is designed to become a unified observability terminal:

* **Logs Integration (`l` mode):** API integration with Grafana Loki (and eventually VictoriaLogs) to stream logs natively in the terminal, featuring color-coded filtering for warnings (`-w`) and errors (`-e`).
* **Metrics Integration (`m` mode):** Support for Prometheus, Mimir and VictoriaMetrics data sources, allowing users to query cluster health and resource usage with built-in formatting (e.g., passing `-h` to auto-convert bytes into human-readable formats) without leaving the command line.