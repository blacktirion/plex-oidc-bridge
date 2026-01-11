package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/golang-jwt/jwt/v5"
)

const (
	plexAPIBaseURL = "https://plex.tv/api/v2"
	productName    = "PlexOIDCBridge"
	productVersion = "0.0.1"
	clientID       = "plex-oidc-bridge-docker"
	maxStateSize   = 4096
	maxNonceSize   = 4096
	maxSessions    = 1000
	maxAuthCodes   = 1000
	rateLimitBurst = 10
)

type Config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

var (
	rsaPrivateKey     *rsa.PrivateKey
	rsaPublicKey      *rsa.PublicKey
	oidcSessions      = make(map[string]*OIDCSession) // Map random session id -> OIDC Session
	authCodes         = make(map[string]*AuthCodeVal) // Map auth_code -> User Info
	sessionMutex      sync.RWMutex
	globalBaseURL     string
	globalConfig      Config
	sessionTTL        time.Duration
	authCodeTTL       time.Duration
	rateLimitWindow   = time.Minute
	rateLimiters      = make(map[string]*rateLimiter)
	trustProxyHeaders bool
)

type OIDCSession struct {
	PinID        string
	State        string
	Nonce        string
	RedirectURI  string
	OriginalHost string
	ExpiresAt    time.Time
}

type AuthCodeVal struct {
	Email       string
	Username    string
	Nonce       string
	Subject     string
	ClientID    string
	RedirectURI string
	ExpiresAt   time.Time
}

type rateLimiter struct {
	count       int
	windowStart time.Time
}

type PinResponse struct {
	ID        int    `json:"id"`
	Code      string `json:"code"`
	AuthToken string `json:"authToken"`
}

type UserResponse struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Thumb    string `json:"thumb"`
	UUID     string `json:"uuid"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

func main() {
	// Setup config directory
	configDir := "config"
	if err := os.MkdirAll(configDir, 0700); err != nil {
		log.Fatalf("Failed to create config dir: %v", err)
	}

	// 1. Initialize RSA Keys
	if err := initKeys(configDir); err != nil {
		log.Fatalf("Failed to initialize RSA keys: %v", err)
	}

	// 2. Initialize Client Config
	if err := initConfig(configDir); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	// 3. Configure TTLs
	sessionTTL = loadTTL("SESSION_TTL_MINUTES", 10)
	authCodeTTL = loadTTL("AUTH_CODE_TTL_MINUTES", 10)

	// 4. Trust proxy headers if explicitly enabled
	trustProxyHeaders = strings.EqualFold(os.Getenv("TRUST_PROXY_HEADERS"), "true")
	if trustProxyHeaders {
		log.Println("TRUST_PROXY_HEADERS enabled: respecting X-Forwarded-For and X-Real-IP")
	}

	// 5. Start cleanup ticker for expired sessions/codes
	go startCleanupTicker()

	http.HandleFunc("/.well-known/openid-configuration", handleDiscovery)
	http.HandleFunc("/.well-known/jwks.json", handleJWKS)
	http.HandleFunc("/authorize", handleAuthorize) // OIDC Start
	http.HandleFunc("/token", handleToken)         // OIDC Token Exchange
	http.HandleFunc("/userinfo", handleUserInfo)   // OIDC User Info
	http.HandleFunc("/callback", handleCallback)   // Plex Callback

	// Test Handlers - Only enabled if env var is set
	if os.Getenv("ENABLE_TEST_ENDPOINTS") == "true" {
		log.Println("Enabling /test endpoints for debugging.")
		http.HandleFunc("/test", handleTestLogin)
		http.HandleFunc("/test/callback", handleTestCallback)
	}

	// Legacy root handler to fail gracefully or show info
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "<h1>Plex OIDC Bridge</h1><p>This is an OIDC Provider. Point Cloudflare Access here.</p>")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Calculate Global Base URL once
	globalBaseURL = os.Getenv("PUBLIC_URL")
	if globalBaseURL == "" {
		log.Fatalf("PUBLIC_URL is required. Set PUBLIC_URL to the externally reachable base URL (e.g., https://auth.example.com)")
	} else {
		globalBaseURL = strings.TrimSuffix(globalBaseURL, "/")
	}

	log.Printf("Server starting on port %s...", port)

	// Print Configuration for Cloudflare
	fmt.Println("==================================================================")
	fmt.Println("PLEX OIDC BRIDGE CONFIGURATION")
	fmt.Println("==================================================================")
	fmt.Printf("App ID (Client ID) : %s\n", globalConfig.ClientID)
	fmt.Printf("Client Secret      : %s\n", "(hidden)")
	fmt.Printf("Auth URL           : %s/authorize\n", globalBaseURL)
	fmt.Printf("Token URL          : %s/token\n", globalBaseURL)
	fmt.Printf("JWKS URL (Certs)   : %s/.well-known/jwks.json\n", globalBaseURL)
	fmt.Printf("Discovery URL      : %s/.well-known/openid-configuration\n", globalBaseURL)
	fmt.Println("==================================================================")

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           nil,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Initialization & Config
// -----------------------------------------------------------------------------

func initKeys(dir string) error {
	keyPath := fmt.Sprintf("%s/oidc.key", dir)

	// Try to load existing key
	if _, err := os.Stat(keyPath); err == nil {
		log.Printf("Loading RSA key from %s", keyPath)
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			return fmt.Errorf("failed to parse PEM block containing the key")
		}
		rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		rsaPublicKey = &rsaPrivateKey.PublicKey
		if err := os.Chmod(keyPath, 0600); err != nil {
			log.Printf("WARNING: failed to set permissions on %s: %v", keyPath, err)
		}
		return nil
	}

	// Generate new key
	log.Printf("Generating new RSA keypair and saving to %s", keyPath)
	var err error
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsaPublicKey = &rsaPrivateKey.PublicKey

	// Save
	keyBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	f, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, pemBlock); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		log.Printf("WARNING: failed to set permissions on %s: %v", keyPath, err)
	}
	return nil
}

func initConfig(dir string) error {
	path := fmt.Sprintf("%s/clients.json", dir)

	// Load from Env if present
	envID := os.Getenv("OIDC_CLIENT_ID")
	envSecret := os.Getenv("OIDC_CLIENT_SECRET")
	envRedirects := parseRedirects(os.Getenv("ALLOWED_REDIRECT_URIS"))

	// Try to load file
	if _, err := os.Stat(path); err == nil {
		log.Printf("Loading client config from %s", path)
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(fileBytes, &globalConfig); err != nil {
			return fmt.Errorf("invalid clients config: %w", err)
		}
	}

	// If env vars are set, they override file (or file didn't exist)
	if envID != "" {
		globalConfig.ClientID = envID
	}
	if envSecret != "" {
		globalConfig.ClientSecret = envSecret
	}
	if len(envRedirects) > 0 {
		globalConfig.RedirectURIs = envRedirects
	}

	globalConfig.RedirectURIs = cleanRedirectList(globalConfig.RedirectURIs)

	// If nothing is set anywhere, generate defaults
	if globalConfig.ClientID == "" {
		globalConfig.ClientID = generateRandomString(24)
	}
	if globalConfig.ClientSecret == "" {
		globalConfig.ClientSecret = generateRandomString(32)
	}

	// Save back to file to ensure persistence
	fileBytes, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, fileBytes, 0600)
}

func parseRedirects(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		if canon, ok := canonicalizeRedirect(p); ok {
			res = append(res, canon)
		}
	}
	return res
}

func cleanRedirectList(list []string) []string {
	res := make([]string, 0, len(list))
	for _, p := range list {
		if canon, ok := canonicalizeRedirect(p); ok {
			res = append(res, canon)
		}
	}
	return res
}

func normalizeRedirect(uri string) string {
	return strings.Trim(uri, " \t\r\n\"'`“”‘’")
}

func canonicalizeRedirect(uri string) (string, bool) {
	clean := normalizeRedirect(uri)
	if clean == "" {
		return "", false
	}
	u, err := url.Parse(clean)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || u.User != nil {
		return "", false
	}
	return u.String(), true
}

func loadTTL(envName string, defaultMinutes int) time.Duration {
	val := os.Getenv(envName)
	if val == "" {
		return time.Duration(defaultMinutes) * time.Minute
	}
	mins, err := strconv.Atoi(val)
	if err != nil || mins <= 0 {
		log.Printf("Invalid %s=%s, defaulting to %d minutes", envName, val, defaultMinutes)
		return time.Duration(defaultMinutes) * time.Minute
	}
	return time.Duration(mins) * time.Minute
}

func startCleanupTicker() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		cleanupExpired()
	}
}

func cleanupExpired() {
	now := time.Now()
	sessionMutex.Lock()
	for pinID, sess := range oidcSessions {
		if now.After(sess.ExpiresAt) {
			delete(oidcSessions, pinID)
		}
	}
	for code, val := range authCodes {
		if now.After(val.ExpiresAt) {
			delete(authCodes, code)
		}
	}
	for key, rl := range rateLimiters {
		if now.Sub(rl.windowStart) > 2*rateLimitWindow {
			delete(rateLimiters, key)
		}
	}
	sessionMutex.Unlock()
}

func allowRequest(endpoint string, r *http.Request) bool {
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	key := endpoint + "|" + ip
	now := time.Now()

	sessionMutex.Lock()
	rl, ok := rateLimiters[key]
	if !ok || now.Sub(rl.windowStart) >= rateLimitWindow {
		rl = &rateLimiter{count: 0, windowStart: now}
		rateLimiters[key] = rl
	}
	if rl.count >= rateLimitBurst {
		sessionMutex.Unlock()
		return false
	}
	rl.count++
	sessionMutex.Unlock()
	return true
}

func clientIP(r *http.Request) string {
	if trustProxyHeaders {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				candidate := strings.TrimSpace(parts[0])
				if net.ParseIP(candidate) != nil {
					return candidate
				}
			}
		}
		realIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if realIP != "" && net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	return r.RemoteAddr
}

func sanitizeForLog(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func secretsEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func validateAudience(aud interface{}, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func isRedirectAllowed(uri string) bool {
	if len(globalConfig.RedirectURIs) == 0 {
		return false
	}
	canon, ok := canonicalizeRedirect(uri)
	if !ok {
		return false
	}
	for _, allowed := range globalConfig.RedirectURIs {
		if canon == allowed {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// OIDC Endpoints
// -----------------------------------------------------------------------------
func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	baseURL := getBaseURL(r)
	resp := map[string]interface{}{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"userinfo_endpoint":      baseURL + "/userinfo",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},
		"scopes_supported": []string{
			"openid", "email", "profile",
		},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "email", "preferred_username",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := JWK{
		Kty: "RSA",
		Kid: "1", // Simplified Key ID
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPublicKey.E)).Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWKS{Keys: []JWK{jwk}})
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !allowRequest("/authorize", r) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	// 1. Parse OIDC parameters
	oidcClientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	if len(state) > maxStateSize || len(nonce) > maxNonceSize {
		http.Error(w, "State or nonce too large", http.StatusBadRequest)
		return
	}

	canonRedirect, ok := canonicalizeRedirect(redirectURI)
	log.Printf("/authorize request client_id=%s redirect_uri_clean=%s state_len=%d", oidcClientID, sanitizeForLog(canonRedirect, 256), len(state))
	if !ok {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	if oidcClientID != globalConfig.ClientID {
		log.Printf("/authorize reject client_id mismatch: got=%s expected=%s", sanitizeForLog(oidcClientID, 64), sanitizeForLog(globalConfig.ClientID, 64))
		http.Error(w, "Invalid client_id", http.StatusUnauthorized)
		return
	}

	if !isRedirectAllowed(canonRedirect) {
		log.Printf("/authorize reject redirect_uri not allowed: got=%s expected_any_of=%v", sanitizeForLog(canonRedirect, 256), globalConfig.RedirectURIs)
		http.Error(w, "Unregistered redirect_uri", http.StatusUnauthorized)
		return
	}

	// 2. Start Plex Auth Flow
	pin, err := createPlexPIN()
	if err != nil {
		http.Error(w, "Failed to contact Plex", http.StatusBadGateway)
		return
	}

	// 3. Store OIDC State mapped to random session ID (opaque to client)
	sid := generateRandomString(48)
	sessionMutex.Lock()
	if len(oidcSessions) >= maxSessions {
		sessionMutex.Unlock()
		http.Error(w, "Too many active sessions", http.StatusTooManyRequests)
		return
	}
	oidcSessions[sid] = &OIDCSession{
		PinID:        fmt.Sprintf("%d", pin.ID),
		State:        state,
		Nonce:        nonce,
		RedirectURI:  canonRedirect,
		OriginalHost: r.Host,
		ExpiresAt:    time.Now().Add(sessionTTL),
	}
	sessionMutex.Unlock()

	// 4. Build Plex Redirect URL and set Cookie
	baseURL := getBaseURL(r)
	callbackURL := fmt.Sprintf("%s/callback", baseURL)
	http.SetCookie(w, &http.Cookie{
		Name:     "plex_sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(baseURL, "https"),
		SameSite: http.SameSiteLaxMode,
	})

	forwardURL := url.QueryEscape(callbackURL)
	plexAuthURL := fmt.Sprintf("https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s&context[device][product]=%s",
		clientID, url.QueryEscape(pin.Code), forwardURL, url.QueryEscape(productName))

	http.Redirect(w, r, plexAuthURL, http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if !allowRequest("/token", r) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Protect against oversized POST bodies
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		http.Error(w, "Unsupported grant_type", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	canonRedirect, ok := canonicalizeRedirect(redirectURI)
	if !ok {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	log.Printf("/token request grant_type=%s client_id=%s redirect_uri=%s", grantType, sanitizeForLog(r.FormValue("client_id"), 64), sanitizeForLog(canonRedirect, 256))

	// Validate Client
	// 1. Check Basic Auth
	clientID, clientSecret, ok := r.BasicAuth()

	// 2. Fallback to POST parameters if Basic Auth missing
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID != globalConfig.ClientID || !secretsEqual(clientSecret, globalConfig.ClientSecret) {
		log.Printf("/token reject client creds mismatch: got_id=%s expected_id=%s got_secret_set=%t", sanitizeForLog(clientID, 64), sanitizeForLog(globalConfig.ClientID, 64), clientSecret != "")
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	sessionMutex.Lock()
	val, ok := authCodes[code]
	if !ok {
		sessionMutex.Unlock()
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	now := time.Now()
	if now.After(val.ExpiresAt) {
		delete(authCodes, code)
		sessionMutex.Unlock()
		http.Error(w, "Expired code", http.StatusBadRequest)
		return
	}

	if val.ClientID != clientID || val.RedirectURI != canonRedirect {
		sessionMutex.Unlock()
		http.Error(w, "Invalid code binding", http.StatusUnauthorized)
		return
	}

	delete(authCodes, code)
	sessionMutex.Unlock()

	// Generate JWT
	baseURL := getBaseURL(r)
	subject := val.Subject
	if subject == "" {
		subject = val.Email
	}

	claims := jwt.MapClaims{
		"iss":                baseURL,
		"sub":                subject,
		"aud":                val.ClientID,
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"email":              val.Email,
		"email_verified":     true,
		"preferred_username": val.Username,
		"name":               val.Username,
		"nonce":              val.Nonce,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"

	tokenString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokenString, // We use the same for now, or could be opaque
		"id_token":     tokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Parse Bearer token
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	token, err := parser.Parse(parts[1], func(t *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	})

	if err != nil || token == nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) < now {
		http.Error(w, "Token expired", http.StatusUnauthorized)
		return
	}

	iss, ok := claims["iss"].(string)
	if !ok || iss != globalBaseURL {
		http.Error(w, "Invalid issuer", http.StatusUnauthorized)
		return
	}

	aud := claims["aud"]
	if !validateAudience(aud, globalConfig.ClientID) {
		http.Error(w, "Invalid audience", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":                claims["sub"],
		"email":              claims["email"],
		"preferred_username": claims["preferred_username"],
	})
}

// -----------------------------------------------------------------------------
// Plex Logic
// -----------------------------------------------------------------------------

func createPlexPIN() (*PinResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", plexAPIBaseURL+"/pins?strong=true", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", productName)
	req.Header.Set("X-Plex-Version", productVersion)
	req.Header.Set("X-Plex-Client-Identifier", clientID)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var pin PinResponse
	if err := json.NewDecoder(resp.Body).Decode(&pin); err != nil {
		return nil, err
	}
	return &pin, nil
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if !allowRequest("/callback", r) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	// 1. Get session ID from cookie
	cookie, err := r.Cookie("plex_sid")
	if err != nil {
		http.Error(w, "Session expired or invalid", http.StatusBadRequest)
		return
	}
	sid := cookie.Value

	// 2. Retrieve OIDC Session
	sessionMutex.RLock()
	oidcSession, ok := oidcSessions[sid]
	sessionMutex.RUnlock()

	if !ok {
		http.Error(w, "OIDC Session not found", http.StatusBadRequest)
		return
	}

	if time.Now().After(oidcSession.ExpiresAt) {
		sessionMutex.Lock()
		delete(oidcSessions, sid)
		sessionMutex.Unlock()
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	// 3. Check Plex PIN
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/pins/%s", plexAPIBaseURL, oidcSession.PinID), nil)
	if err != nil {
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", productName)
	req.Header.Set("X-Plex-Version", productVersion)
	req.Header.Set("X-Plex-Client-Identifier", clientID)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		http.Error(w, "Failed to verify PIN", http.StatusUnauthorized)
		return
	}

	var pin PinResponse
	if err := json.NewDecoder(resp.Body).Decode(&pin); err != nil {
		http.Error(w, "Failed to parse Plex response", http.StatusBadGateway)
		return
	}

	if pin.AuthToken == "" {
		http.Error(w, "Details: Plex denied access", http.StatusUnauthorized)
		return
	}

	// 4. Get User Details
	user, err := getUserDetails(pin.AuthToken)
	if err != nil {
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// 5. Generate Internal Auth Code
	authCode := generateRandomString(32)
	sessionMutex.Lock()
	if len(authCodes) >= maxAuthCodes {
		sessionMutex.Unlock()
		http.Error(w, "Too many active auth codes", http.StatusTooManyRequests)
		return
	}
	authCodes[authCode] = &AuthCodeVal{
		Email:       user.Email,
		Username:    user.Username,
		Nonce:       oidcSession.Nonce,
		Subject:     user.UUID,
		ClientID:    globalConfig.ClientID,
		RedirectURI: oidcSession.RedirectURI,
		ExpiresAt:   time.Now().Add(authCodeTTL),
	}
	// Clean up session
	delete(oidcSessions, sid)
	sessionMutex.Unlock()

	// 6. Redirect back to Cloudflare
	cbURL, err := url.Parse(oidcSession.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect", http.StatusBadRequest)
		return
	}
	q := cbURL.Query()
	q.Set("code", authCode)
	q.Set("state", oidcSession.State)
	cbURL.RawQuery = q.Encode()

	http.SetCookie(w, &http.Cookie{
		Name:     "plex_sid",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(getBaseURL(r), "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.Redirect(w, r, cbURL.String(), http.StatusFound)
}

func getUserDetails(token string) (*UserResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", plexAPIBaseURL+"/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", productName)
	req.Header.Set("X-Plex-Version", productVersion)
	req.Header.Set("X-Plex-Client-Identifier", clientID)
	req.Header.Set("X-Plex-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	var userResp UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, err
	}

	return &userResp, nil
}

func getBaseURL(r *http.Request) string {
	if globalBaseURL != "" {
		return globalBaseURL
	}
	// Fallback to request host
	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s", protocol, r.Host)
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

// -----------------------------------------------------------------------------
// Test Mode Logic
// -----------------------------------------------------------------------------

func handleTestLogin(w http.ResponseWriter, r *http.Request) {
	baseURL := getBaseURL(r)
	testRedirect := baseURL + "/test/callback"
	if !isRedirectAllowed(testRedirect) {
		http.Error(w, "Test redirect not allowed; add it to ALLOWED_REDIRECT_URIS", http.StatusForbidden)
		return
	}
	// Construct valid OIDC request with configured client_id
	redirect := fmt.Sprintf("%s/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20profile%%20email&state=teststate&nonce=testnonce", baseURL, globalConfig.ClientID, url.QueryEscape(testRedirect))
	http.Redirect(w, r, redirect, http.StatusFound)
}

func handleTestCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code returned", http.StatusBadRequest)
		return
	}

	// Exchange for token
	baseURL := getBaseURL(r)

	vals := url.Values{}
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", code)
	vals.Set("redirect_uri", baseURL+"/test/callback")
	vals.Set("client_id", globalConfig.ClientID)
	vals.Set("client_secret", globalConfig.ClientSecret)

	resp, err := http.PostForm(baseURL+"/token", vals)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	escapedBody := html.EscapeString(string(body))

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Test Complete</h1>")
	fmt.Fprintf(w, "<h2>Token Response</h2><pre>%s</pre>", escapedBody)

	// Parse ID Token to show claims
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse token response: %v", err), http.StatusBadGateway)
		return
	}

	if idToken, ok := tokenResp["id_token"].(string); ok {
		fmt.Fprintf(w, "<h2>ID Token Claims</h2>")
		// decode parts
		parts := strings.Split(idToken, ".")
		if len(parts) > 1 {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			// Prettify json
			var prettyJSON bytes.Buffer
			json.Indent(&prettyJSON, payload, "", "  ")
			fmt.Fprintf(w, "<pre>%s</pre>", html.EscapeString(prettyJSON.String()))
		}
	}
}
