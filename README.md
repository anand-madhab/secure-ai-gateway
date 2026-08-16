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
