# Theoros (Θεωρός)

> **🚧 UNDER ACTIVE CONSTRUCTION 🚧**  
> *This project is actively being developed as a hands-on journey to master Go, cloud-native architectures, gRPC streaming, and Kubernetes systems programming.*

---

## 🏛️ What Does *Theoros* Mean?

In ancient Greece, a **Theoros** (Greek: *Θεωρός*) was an official state envoy or sacred observer sent to witness events, inspect sanctuaries, or consult the oracle. It is the ancient root of the modern word **theory** (*viewing, contemplation, observation*).

This project acts as your personal digital *Theoros*: an observer sent deep into your Kubernetes cluster to inspect health, stream telemetry, and report back the truth of what is happening inside.

---

## Project Purpose

`theoros` is a personal DevOps project built from scratch to learn and master:
* Building high-performance, concurrent Go microservices and CLI tools.
* Binary multiplexed streaming using **gRPC** and **Protocol Buffers**.
* Modern cloud-native ingress routing via the **Kubernetes Gateway API (`GRPCRoute`)**.
* Direct integration with internal cluster APIs (**Loki LogQL**, **VictoriaMetrics PromQL**, and **Kubernetes `client-go`**).
* **Dyslexia-friendly terminal UX** with high-contrast styling and structured formatting to eliminate monochromatic text fatigue.

---

## Roadmap & Architecture

```text
[ Local CLI (REPL) ] 
       │
       ▼ (gRPC Stream over TLS 1.3 / Gateway API)
[ In-Cluster Theoros Server Pod ]
       ├── Loki (Real-time LogQL Stream)
       ├── Kubernetes API (Namespaces, Pods, Events, PVCs)
       └── VictoriaMetrics (PromQL Metrics)
```

---

### Phase 1: Real-Time Log Observability (Current Focus)

* **Interactive REPL Shell:** Starts a dedicated terminal session (`theoros>`) that maintains a persistent gRPC connection.
* **Token Authentication & Local Vault:** Zero certificate file hassle. Authenticates via a high-entropy token stored locally in an encrypted vault (`~/.ssh/theoros/credentials.enc`) protected by your passphrase.
* **Live Loki Streaming:** Stream logs over gRPC with custom LogQL filters (e.g., `--level ERROR,WARN --since 1h`).
* **Dyslexia-Friendly Visuals:** High-contrast badges (`[ERROR]`, `[WARN]`), muted timestamps, and auto-indented, syntax-colored JSON via [Charm Lip Gloss](https://github.com/charmbracelet/lipgloss).
* **Instant Dynamic Tab-Completion:** In-memory caching of active namespaces and pods for smooth TAB suggestions in the prompt.

---

### Future Phases & Planned Features

* [ ] **Module A: Smart PVC & Volume Diagnostics**  
  Add `diagnose volume <pvc>` to automatically inspect StorageClasses, PV bindings, and Kubernetes `Events` to explain *why* a volume mount failed in plain English.
* [ ] **Module B: VictoriaMetrics Integration**  
  Stream historical CPU/Memory saturation trends and spike alerts directly into the terminal without opening heavy web dashboards.
* [ ] **Module C: In-Cluster Watcher & Discord Alerts**  
  A background daemon using `client-go` Informers to watch cluster events. Features an in-memory **5-minute debounce timer** before dispatching rich embed alerts to Discord (preventing temporary restart spam).
* [ ] **Module D: Full-Screen Interactive TUI**  
  Evolve the REPL into an interactive full-screen dashboard (built with [Bubble Tea](https://github.com/charmbracelet/bubbletea)) to manage pods, stream logs, and view metrics like a personalized `k9s`.

---

## Tech Stack

* **Language:** Go (Golang)
* **Communication:** gRPC / Protocol Buffers v3
* **Routing & Security:** Kubernetes Gateway API (`GRPCRoute`), AES-256-GCM / Argon2id
* **Observability:** Grafana Loki, VictoriaMetrics, Kubernetes `client-go`
* **Terminal UX:** `c-bata/go-prompt`, `charmbracelet/lipgloss`, `tidwall/pretty`