# 🛡️ Secure AI Edge Gateway

A high-performance, ultra-low-latency Layer-7 reverse proxy and security firewall designed specifically for local, on-premise LLM clusters (`vLLM`, `llama.cpp`, `Ollama`). 

Built in pure Go with zero external dependencies, this gateway acts as a centralized security checkpoint inside your secure corporate network to regulate, monitor, and protect your local AI processing infrastructure.

---

## ✨ Core Features

* **⚡ Sub-Millisecond Token Streaming:** Implements zero-copy network socket manipulation using Go `io.Pipe` primitives. Processes Server-Sent Events (SSE) token chunks in real-time with negligible latency overhead.
* **🔒 Outbound PII Masking:** Uses streaming regex heuristic evaluation matrices to identify and mask sensitive corporate assets (SSNs, Credit Cards, API Keys, Internal IDs) on the fly before they leave the gateway edge.
* **🛑 Inbound Jailbreak & Prompt Injection Defense:** Features a low-overhead inspection matrix to intercept and drop malicious instruction bypasses or character roleplay exploits (e.g., DAN attacks) at the front gate.
* **📊 Token-Bucket Rate Limiting:** Enforces granular, thread-safe rate-limiting tracking **Tokens Per Minute (TPM)** per user or IP tier, instead of traditional requests-per-minute (RPM).
* **👥 Multi-Tenant Group Policies:** Supports dynamic, role-based admin configurations (e.g., separate rules and token budgets for external clients vs. internal developers).
* **📈 Native Prometheus Telemetry:** Exposes an OpenMetrics-compliant endpoint natively out-of-the-box for instant tracking via corporate Grafana instances.

---

## 🏗️ Architecture

```
[ Internal Corporate Clients ]
              │
              ▼ (HTTPS / OpenAI API Schema)
┌────────────────────────────────────────────────────────┐
│             SECURE AI EDGE GATEWAY (Port 8080)          │
│                                                        │
│  1. Inbound Guard (Jailbreak / Threat Matrix Scan)     │
│  2. Token Rate Limiter (Token-Bucket allocation check) │
│  3. Outbound PII Stripper (Aho-Corasick Token Filter)  │
│  4. Native Prometheus Exporter Engine (Port 9090)      │
└────────────────────────────────────────────────────────┘
              │
              ▼ (Load-Balanced SSE Token Streams)
   [ vLLM / llama.cpp Infrastructure Cluster (Port 8000) ]
```

---

## 🚀 Quick Start

### 1. Installation
Download the single, statically linked compiled binary optimized for your operating system platform from our Releases page.

### 2. Configure System Rules
Create a `config.json` file in the same directory as the executable binary:

```json
{
  "license_key": "YOUR_ENTERPRISE_LICENSE_KEY",
  "listen_address": ":8080",
  "llm_backend_url": "http://localhost:8000",
  "admin_policies": {
    "groups": {
      "default_external": {
        "max_tokens_capacity": 50000,
        "tokens_refill_per_sec": 100,
        "enforce_strict_security": true
      },
      "internal_developers": {
        "max_tokens_capacity": 200000,
        "tokens_refill_per_sec": 1000,
        "enforce_strict_security": false
      }
    },
    "custom_pii_rules": {
      "US_SOCIAL_SECURITY": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
      "VISA_MASTERCARD": "\\b\\d{3}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
    }
  },
  "security": {
    "inbound_blocked_keywords": ["system override", "ignore previous instructions"],
    "jailbreak_regex_patterns": [
      "(?i)(ignore|bypass|override)\\s+(all\\s+)?(previous|prior)\\s+(instructions|directives)"
    ]
  }
}
```

### 3. Run the Appliance
Execute the compiled gateway core:

```bash
# On Linux / macOS
./ai-gateway

# On Windows Server
.\\ai-gateway.exe
```

---

## 📈 Monitoring & Telemetry Integration

The gateway natively exposes standard enterprise-ready metrics logs on port `:9090/metrics`.

1. Point your corporate **Prometheus** scraper setup to scrape `http://<gateway-ip>:9090/metrics`.
2. Open your corporate **Grafana** dashboard interface.
3. Click on **Dashboards** ➡️ **New** ➡️ **Import**.
4. Upload the pre-configured `dashboard.json` file bundled inside this repository.

You will instantly have a production dashboard monitoring live token consumption charts, active socket connections, and real-time security incident timelines.

---

## 💳 Enterprise Licensing & Support

This product operates under an Open-Core model. Basic proxy routing and request logging features are available for open evaluation. High-performance streaming PII scrubbing, dynamic regex evaluation clusters, token-bucket allocation controls, and multi-tenant admin policies require an active production enterprise license key.

To obtain your enterprise validation license key instantly via automated delivery channels, visit our Self-Serve Commercial Gateway Checkout Portal to activate your account.

---

## ⚙️ How It Works (Under the Hood)

The Secure AI Edge Gateway acts as a high-performance Layer-7 inline firewall sitting directly between your client applications and your open-source inference servers (`vLLM`, `llama.cpp`).

1. **Connection Intake & Scaling:** When a client sends a request, the gateway multiplexes the connection using lightweight Go Goroutines, consuming just ~2KB of RAM per session.
2. **Inbound Token-Bucket Check:** The gateway intercepts the packet at the TCP socket layer and cross-references the Client IP with a thread-safe memory manager (`sync.RWMutex`). It calculates real-time token balances using a microsecond time-delta math formula. If the user's Token-Bucket budget is empty, the connection is instantly rejected with an `HTTP 429 Too Many Requests` error.
3. **Inbound Threat Analysis:** Valid connections pass through a pre-compiled multi-pattern regex heuristics matrix to detect and drop natural language jailbreaks or prompt injections in microseconds.
4. **Zero-Copy Stream Interception:** As the backend AI answers via Server-Sent Events (SSE), the gateway utilizes an in-memory `io.Pipe()` conduit and a `bufio.Scanner` line tracker. It evaluates chunks of incoming text line-by-line. If a sensitive pattern matches an admin-defined rule (e.g., an SSN or corporate API key), it modifies the packet data *in RAM* on the fly, replacing the leak with a `[REDACTED]` stamp before it reaches the wire transmission card.

---

## 💳 Licensing & Cost Structure

This product operates under an **Open-Core** licensing model. The basic reverse-proxy and request logging framework are available for free under the permissive MIT License. Enterprise-grade security policies, data masking filters, and usage trackers require a commercial license key.

### 📊 Tiered Pricing Model

| Feature Matrix | 🍃 Open-Source Core (Free) | 🏢 Enterprise Tier ($250/mo) |
| :--- | :--- | :--- |
| **Max Capacity** | Up to 1,000 requests/day | Unlimited Concurrent Streams |
| **L7 Reverse Proxy** | ✅ Included | ✅ Included |
| **Prometheus Telemetry** | ✅ Included | ✅ Included |
| **Inbound Jailbreak Guard** | ❌ None (Open Pass) | ✅ Pre-Compiled Regex Heuristics |
| **Outbound PII Filter** | ❌ None (Unmasked) | ✅ Real-Time Regex Data Redaction |
| **Token-Bucket Rate Limiter**| ❌ None (No TPM Track) | ✅ Per-Group Token Balances (TPM) |
| **Role-Based Policies** | ❌ Single Global Policy | ✅ Multi-Tenant Group Routing |
| **Technical Support** | GitHub Issues Community | 24/7 SLA Priority Developer Support |

*To activate your production instances instantly via automated checkout delivery, visit our [![Buy Access via Polar](https://polar.sh)](https://buy.polar.sh/polar_cl_fp7n03guxR834X60OpVcwUfQKR9HD66K8HqD72ogqCp) to generate your cryptographically signed activation license key.*
