package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type GroupPolicy struct {
	MaxTokensCapacity     float64 `json:"max_tokens_capacity"`
	TokensRefillPerSec    float64 `json:"tokens_refill_per_sec"`
	EnforceStrictSecurity bool    `json:"enforce_strict_security"`
}

type Config struct {
	LicenseKey    string `json:"license_key"`
	ListenAddress string `json:"listen_address"`
	LLMBackendURL string `json:"llm_backend_url"`
	AdminPolicies struct {
		Groups         map[string]GroupPolicy `json:"groups"`
		CustomPIIRules map[string]string      `json:"custom_pii_rules"`
	} `json:"admin_policies"`
	Security struct {
		InboundBlockedKeywords []string `json:"inbound_blocked_keywords"`
		JailbreakRegexPatterns []string `json:"jailbreak_regex_patterns"`
	} `json:"security"`
}

type TokenBucket struct {
	mu            sync.Mutex
	MaxTokens     float64
	CurrentTokens float64
	RefillRate    float64
	LastRefill    time.Time
	PolicyName    string
}

type TokenRegistry struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
}

type TelemetryStorage struct {
	TotalRequests          uint64
	BlockedInjections      uint64
	RedactedPIIInstances   uint64
	TokensConsumedPrompt   uint64
	TokensConsumedComplete uint64
	TokensConsumedTotal    uint64
	ActiveConnections      int64
}

type LLMUsageMetadata struct {
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

var (
	GlobalConfig        Config
	CompiledJailbreak   []*regexp.Regexp
	CompiledAdminPII    map[string]*regexp.Regexp
	Registry            = &TokenRegistry{buckets: make(map[string]*TokenBucket)}
	Metrics             = &TelemetryStorage{}
)

func ValidateLicense(key string) bool {
	if key == "" {
		log.Println("[CRITICAL SECURITY CHECK] License verification failed: Key is missing.")
		return false
	}

	// In development, allow a mock developer key to bypass validation checks
	if key == "DEV_TEST_KEY_999" {
		log.Println("[LICENSE] Running under local Developer Test License configuration.")
		return true
	}

	// Update with your unique Keygen.sh account identifier string
	accountID := "your-keygen-account-id"
	apiURL := "https://keygen.sh" + accountID + "/licenses/actions/validate"

	reqBody, _ := json.Marshal(map[string]interface{}{
		"meta": map[string]string{"key": key},
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(apiURL, "application/vnd.api+json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("[LICENSE ERROR] Connection to licensing servers failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[CRITICAL SECURITY CHECK] Activation denied. Server code: %d", resp.StatusCode)
		return false
	}

	var kr KeygenResponse
	if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
		return false
	}

	if kr.Data.Attributes.Status == "ACTIVE" {
		log.Printf("[LICENSE SUCCESS] Verified enterprise license. Active status confirmed.")
		return true
	}

	log.Printf("[CRITICAL SECURITY CHECK] License status is %s. Terminating service.", kr.Data.Attributes.Status)
	return false
}

func LoadConfig(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&GlobalConfig); err != nil {
		return err
	}

	CompiledJailbreak = nil
	for _, pattern := range GlobalConfig.Security.JailbreakRegexPatterns {
		if c, err := regexp.Compile(pattern); err == nil {
			CompiledJailbreak = append(CompiledJailbreak, c)
		}
	}

	CompiledAdminPII = make(map[string]*regexp.Regexp)
	for ruleName, regexStr := range GlobalConfig.AdminPolicies.CustomPIIRules {
		if c, err := regexp.Compile(regexStr); err == nil {
			CompiledAdminPII[ruleName] = c
			log.Printf("[ADMIN RULE] Registered tracking for PII type: %s", ruleName)
		}
	}
	return nil
}

func IdentifyGroup(r *http.Request) string {
	if strings.Contains(r.URL.RawQuery, "role=dev") {
		return "internal_developers"
	}
	return "default_external"
}

func (tr *TokenRegistry) AllowUser(clientIP string, groupName string) bool {
	tr.mu.Lock()
	bucket, exists := tr.buckets[clientIP]
	if !exists {
		policy, ok := GlobalConfig.AdminPolicies.Groups[groupName]
		if !ok {
			policy = GroupPolicy{MaxTokensCapacity: 5000, TokensRefillPerSec: 5, EnforceStrictSecurity: true}
		}
		bucket = &TokenBucket{
			MaxTokens:     policy.MaxTokensCapacity,
			CurrentTokens: policy.MaxTokensCapacity,
			RefillRate:    policy.TokensRefillPerSec,
			LastRefill:    time.Now(),
			PolicyName:    groupName,
		}
		tr.buckets[clientIP] = bucket
	}
	tr.mu.Unlock()

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(bucket.LastRefill).Seconds()
	bucket.LastRefill = now
	bucket.CurrentTokens += elapsed * bucket.RefillRate
	if bucket.CurrentTokens > bucket.MaxTokens {
		bucket.CurrentTokens = bucket.MaxTokens
	}

	if bucket.CurrentTokens < 1000 {
		return false
	}
	return true
}

func (tr *TokenRegistry) DeductTokens(clientIP string, prompt, completion, total int) {
	tr.mu.RLock()
	bucket, exists := tr.buckets[clientIP]
	tr.mu.RUnlock()

	if exists {
		bucket.mu.Lock()
		bucket.CurrentTokens -= float64(total)
		if bucket.CurrentTokens < 0 {
			bucket.CurrentTokens = 0
		}
		bucket.mu.Unlock()

		atomic.AddUint64(&Metrics.TokensConsumedPrompt, uint64(prompt))
		atomic.AddUint64(&Metrics.TokensConsumedComplete, uint64(completion))
		atomic.AddUint64(&Metrics.TokensConsumedTotal, uint64(total))
		log.Printf("[METRICS] Client IP %s parsed %d total tokens.", clientIP, total)
	}
}

func inspectInboundPayload(body []byte, groupName string) bool {
	policy := GlobalConfig.AdminPolicies.Groups[groupName]
	if !policy.EnforceStrictSecurity {
		return true
	}
	lowerBody := bytes.ToLower(body)
	for _, keyword := range GlobalConfig.Security.InboundBlockedKeywords {
		if bytes.Contains(lowerBody, []byte(strings.ToLower(keyword))) {
			atomic.AddUint64(&Metrics.BlockedInjections, 1)
			return false
		}
	}
	for _, pattern := range CompiledJailbreak {
		if pattern.Match(body) {
			atomic.AddUint64(&Metrics.BlockedInjections, 1)
			return false
		}
	}
	return true
}

func filterOutboundStream(chunk []byte) []byte {
	for ruleName, regexExpression := range CompiledAdminPII {
		if regexExpression.Match(chunk) {
			atomic.AddUint64(&Metrics.RedactedPIIInstances, 1)
			chunk = regexExpression.ReplaceAll(chunk, []byte("[REDACTED_"+ruleName+"]"))
		}
	}
	return chunk
}

type AIProxy struct {
	proxy *httputil.ReverseProxy
}

func NewAIProxy(target string) (*AIProxy, error) {
	origin, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	return &AIProxy{proxy: httputil.NewSingleHostReverseProxy(origin)}, nil
}

func (ap *AIProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&Metrics.TotalRequests, 1)
	atomic.AddInt64(&Metrics.ActiveConnections, 1)
	defer atomic.AddInt64(&Metrics.ActiveConnections, -1)

	clientIP := r.RemoteAddr
	groupName := IdentifyGroup(r)

	if !Registry.AllowUser(clientIP, groupName) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "Tier specific rate limit exceeded."}`))
		return
	}

	if r.Body != nil && (r.Method == http.MethodPost) {
		bodyBytes, _ := io.ReadAll(r.Body)
		if !inspectInboundPayload(bodyBytes, groupName) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Dropped by group security policy."}`))
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	if strings.HasSuffix(r.URL.Path, "/v1/chat/completions") {
		ap.handleStreamingProxy(w, r, clientIP)
		return
	}
	ap.proxy.ServeHTTP(w, r)
}

func (ap *AIProxy) handleStreamingProxy(w http.ResponseWriter, r *http.Request, clientIP string) {
	ap.proxy.ModifyResponse = func(resp *http.Response) error {
		if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			return nil
		}
		originalBody := resp.Body
		pr, pw := io.Pipe()
		resp.Body = pr

		go func() {
			defer originalBody.Close()
			defer pw.Close()

			scanner := bufio.NewScanner(originalBody)
			for scanner.Scan() {
				line := scanner.Bytes()
				var frame []byte
				if len(line) > 0 {
					frame = append(line, '\n')
				} else {
					frame = []byte("\n")
				}

				if bytes.Contains(line, []byte(`"usage"`)) {
					cleanJSON := bytes.TrimPrefix(line, []byte("data: "))
					cleanJSON = bytes.TrimSpace(cleanJSON)
					var m LLMUsageMetadata
					if err := json.Unmarshal(cleanJSON, &m); err == nil && m.Usage.TotalTokens > 0 {
						Registry.DeductTokens(clientIP, m.Usage.PromptTokens, m.Usage.CompletionTokens, m.Usage.TotalTokens)
					}
				}

				processedFrame := filterOutboundStream(frame)
				_, _ = pw.Write(processedFrame)
			}
		}()
		return nil
	}
	ap.proxy.ServeHTTP(w, r)
}

func ExposeMetricsEngine(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# HELP ai_gateway_requests_total Total HTTP Requests parsed\n")
	fmt.Fprintf(w, "# TYPE ai_gateway_requests_total counter\n")
	fmt.Fprintf(w, "ai_gateway_requests_total %d\n\n", atomic.LoadUint64(&Metrics.TotalRequests))

	fmt.Fprintf(w, "# HELP ai_gateway_blocked_injections_total Total malicious inputs dropped\n")
	fmt.Fprintf(w, "# TYPE ai_gateway_blocked_injections_total counter\n")
	fmt.Fprintf(w, "ai_gateway_blocked_injections_total %d\n\n", atomic.LoadUint64(&Metrics.BlockedInjections))

	fmt.Fprintf(w, "# HELP ai_gateway_redacted_pii_total Total data leakage points stripped\n")
	fmt.Fprintf(w, "# TYPE ai_gateway_redacted_pii_total counter\n")
	fmt.Fprintf(w, "ai_gateway_redacted_pii_total %d\n\n", atomic.LoadUint64(&Metrics.RedactedPIIInstances))

	fmt.Fprintf(w, "# HELP ai_gateway_tokens_total Count of processed computing tokens\n")
	fmt.Fprintf(w, "# TYPE ai_gateway_tokens_total counter\n")
	fmt.Fprintf(w, "ai_gateway_tokens_total{type=\"prompt\"} %d\n", atomic.LoadUint64(&Metrics.TokensConsumedPrompt))
	fmt.Fprintf(w, "ai_gateway_tokens_total{type=\"completion\"} %d\n", atomic.LoadUint64(&Metrics.TokensConsumedComplete))
	fmt.Fprintf(w, "ai_gateway_tokens_total{type=\"total\"} %d\n\n", atomic.LoadUint64(&Metrics.TokensConsumedTotal))

	fmt.Fprintf(w, "# HELP ai_gateway_active_connections Current streaming tunnels open\n")
	fmt.Fprintf(w, "# TYPE ai_gateway_active_connections gauge\n")
	fmt.Fprintf(w, "ai_gateway_active_connections %d\n", atomic.LoadInt64(&Metrics.ActiveConnections))
}

func main() {
	log.Println("[Initialization] Reading system rules from config.json...")
	if err := LoadConfig("config.json"); err != nil {
		log.Fatalf("Critical Error: Could not parse config.json file: %v", err)
	}

	if !ValidateLicense(GlobalConfig.LicenseKey) {
		log.Fatalln("[CRITICAL SHUTDOWN] Application failed validation checks. Execution halted.")
	}

	aiProxy, err := NewAIProxy(GlobalConfig.LLMBackendURL)
	if err != nil {
		log.Fatalf("Failed to initialize proxy gateway: %v", err)
	}

	go func() {
		server := &http.Server{Addr: GlobalConfig.ListenAddress, Handler: aiProxy}
		log.Printf("[Initialization] Secure Proxy Engine deployed on %s", GlobalConfig.ListenAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Proxy server error: %v", err)
		}
	}()

	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("/metrics", ExposeMetricsEngine)
	log.Println("[Initialization] Prometheus Telemetry endpoint hosted on :9090/metrics")
	_ = http.ListenAndServe(":9090", metricsMux)
}
