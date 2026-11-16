package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/crypto/ssh"
)

const (
	testClientID = "test-client"
	testUser     = "svc-deploy"
	testPassword = "app-password-123"
)

// fakeAuthentik mimics the behaviour observed with authentik 2026.8.5 and the
// scope mapping from authentik/: client_credentials with username/password,
// nonce copied into the ID token, RS256, 1h lifetime.
type fakeAuthentik struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	mode     string // "", "omit-nonce", "wrong-nonce", "wrong-aud"
	lifetime time.Duration
	requests int
}

var nonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func newFakeAuthentik(t *testing.T) *fakeAuthentik {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAuthentik{t: t, key: key, lifetime: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/application/o/opkssh/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/application/o/opkssh/jwks/", f.jwks)
	mux.HandleFunc("/application/o/token/", f.token)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)

	// opkssh-m2m uses its own client; the opkssh verifier uses the default transport.
	oldFactory, oldTransport := httpClientFactory, http.DefaultTransport
	httpClientFactory = func(timeout time.Duration) *http.Client {
		c := f.srv.Client()
		c.Timeout = timeout
		return c
	}
	http.DefaultTransport = f.srv.Client().Transport
	t.Cleanup(func() { httpClientFactory, http.DefaultTransport = oldFactory, oldTransport })
	return f
}

func (f *fakeAuthentik) issuer() string { return f.srv.URL + "/application/o/opkssh/" }

func (f *fakeAuthentik) setMode(m string) { f.mu.Lock(); f.mode = m; f.mu.Unlock() }

func (f *fakeAuthentik) discovery(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":         f.issuer(),
		"token_endpoint": f.srv.URL + "/application/o/token/",
		"jwks_uri":       f.issuer() + "jwks/",
	})
}

func (f *fakeAuthentik) jwks(w http.ResponseWriter, r *http.Request) {
	k, err := jwk.Import(&f.key.PublicKey)
	if err != nil {
		f.t.Error(err)
		return
	}
	k.Set(jwk.KeyIDKey, "k1")
	k.Set(jwk.AlgorithmKey, jwa.RS256())
	k.Set(jwk.KeyUsageKey, "sig")
	set := jwk.NewSet()
	set.AddKey(k)
	json.NewEncoder(w).Encode(set)
}

func (f *fakeAuthentik) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	mode, lifetime := f.mode, f.lifetime
	f.mu.Unlock()
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != testClientID ||
		r.PostForm.Get("username") != testUser || r.PostForm.Get("password") != testPassword {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": f.issuer(), "aud": testClientID, "sub": "649937e6",
		"iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(lifetime).Unix(),
		"preferred_username": testUser, "groups": []string{"ssh-users"},
	}
	nonce := r.PostForm.Get("nonce")
	scopes := strings.Fields(r.PostForm.Get("scope"))
	hasScope := false
	for _, s := range scopes {
		hasScope = hasScope || s == "opkssh_nonce"
	}
	if hasScope && nonceRe.MatchString(nonce) {
		claims["nonce"] = nonce
	}
	switch mode {
	case "omit-nonce":
		delete(claims, "nonce")
	case "wrong-nonce":
		claims["nonce"] = strings.Repeat("A", 43)
	case "wrong-aud":
		claims["aud"] = "other-client"
	}
	payload, _ := json.Marshal(claims)
	hdr := jws.NewHeaders()
	hdr.Set(jws.KeyIDKey, "k1")
	hdr.Set(jws.TypeKey, "JWT")
	idt, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), f.key, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		f.t.Error(err)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "opaque", "token_type": "Bearer", "expires_in": 28800, "id_token": string(idt),
	})
}

type testEnv struct {
	f       *fakeAuthentik
	dir     string
	key     string
	pwFile  string
	baseArg []string
}

func newEnv(t *testing.T) *testEnv {
	f := newFakeAuthentik(t)
	dir := filepath.Join(t.TempDir(), "keys")
	pw := filepath.Join(t.TempDir(), "pw")
	// Trailing newline as commonly produced by tools; must be trimmed.
	if err := os.WriteFile(pw, []byte(testPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "id_m2m")
	return &testEnv{f: f, dir: dir, key: key, pwFile: pw,
		baseArg: []string{"-issuer", f.issuer(), "-client-id", testClientID, "-key", key}}
}

func (e *testEnv) run(t *testing.T, cmd string, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{cmd}, e.baseArg...)
	if cmd == "login" {
		args = append(args, "-username", testUser, "-password-file", e.pwFile)
	}
	args = append(args, extra...)
	var out, errb bytes.Buffer
	rc := run(args, &out, &errb)
	return rc, out.String(), errb.String()
}

func TestLoginVerifyStatusAndRenewal(t *testing.T) {
	e := newEnv(t)
	rc, out, errs := e.run(t, "login")
	if rc != 0 {
		t.Fatalf("login rc=%d out=%s err=%s", rc, out, errs)
	}
	for _, p := range []string{e.key, certPath(e.key)} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: err=%v mode=%v", p, err, st.Mode())
		}
	}
	if st, _ := os.Stat(e.dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
	cert1, _ := os.ReadFile(certPath(e.key))
	if !bytes.HasPrefix(cert1, []byte("ecdsa-sha2-nistp256-cert-v01@openssh.com ")) || !bytes.HasSuffix(cert1, []byte(" openpubkey\n")) {
		t.Fatalf("unexpected certificate format: %.80s", cert1)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cert1)
	if err != nil {
		t.Fatal(err)
	}
	c := pub.(*ssh.Certificate)
	if c.CertType != ssh.UserCert || len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "opkssh-wildcard" {
		t.Fatalf("cert fields: type=%d principals=%v", c.CertType, c.ValidPrincipals)
	}
	if _, ok := c.Permissions.Extensions["openpubkey-pkt"]; !ok {
		t.Fatal("openpubkey-pkt extension missing")
	}

	// Same code path as opkssh verify on a server.
	if rc, out, errs := e.run(t, "verify", "-group", "ssh-users"); rc != 0 || !strings.Contains(out, "verify OK") {
		t.Fatalf("verify rc=%d out=%s err=%s", rc, out, errs)
	}
	if rc, _, errs := e.run(t, "verify", "-group", "other-group"); rc != 1 || !strings.Contains(errs, "other-group") {
		t.Fatalf("verify with wrong group: rc=%d err=%s", rc, errs)
	}
	if rc, _, _ := e.run(t, "status"); rc != 0 {
		t.Fatalf("status rc=%d", rc)
	}
	if rc, _, errs := e.run(t, "status", "-issuer", "https://other.example/"); rc != 1 || !strings.Contains(errs, "expected") {
		t.Fatalf("status with other issuer: rc=%d err=%s", rc, errs)
	}
	if rc, _, _ := e.run(t, "status", "-min-remaining", "2h"); rc != 1 {
		t.Fatalf("status with 2h minimum should return 1, rc=%d", rc)
	}

	// Still valid: no new request, file unchanged.
	before := e.f.requests
	if rc, out, _ := e.run(t, "login"); rc != 0 || !strings.Contains(out, "still valid") {
		t.Fatalf("second login rc=%d out=%s", rc, out)
	}
	cert2, _ := os.ReadFile(certPath(e.key))
	if e.f.requests != before || !bytes.Equal(cert1, cert2) {
		t.Fatal("unnecessary renewal")
	}
	// Remaining lifetime below threshold: renew.
	if rc, out, _ := e.run(t, "login", "-min-remaining", "2h"); rc != 0 || !strings.Contains(out, "new certificate") {
		t.Fatalf("renewal rc=%d out=%s", rc, out)
	}
	cert3, _ := os.ReadFile(certPath(e.key))
	if bytes.Equal(cert1, cert3) {
		t.Fatal("certificate not renewed")
	}
	// -force: always renew.
	if rc, out, _ := e.run(t, "login", "-force"); rc != 0 || !strings.Contains(out, "new certificate") {
		t.Fatalf("force rc=%d out=%s", rc, out)
	}
	if entries, _ := os.ReadDir(e.dir); len(entries) != 2 {
		t.Fatalf("temporary files left over: %v", entries)
	}
}

func TestKeyMismatchIsDetectedAndRenewed(t *testing.T) {
	e := newEnv(t)
	if rc, _, errs := e.run(t, "login"); rc != 0 {
		t.Fatal(errs)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(other, "")
	os.WriteFile(e.key, pem.EncodeToMemory(blk), 0o600)

	if rc, _, errs := e.run(t, "status"); rc != 1 || !strings.Contains(errs, "does not match") {
		t.Fatalf("status rc=%d err=%s", rc, errs)
	}
	if rc, _, _ := e.run(t, "verify"); rc != 1 {
		t.Fatalf("verify should fail, rc=%d", rc)
	}
	if rc, out, _ := e.run(t, "login"); rc != 0 || !strings.Contains(out, "new certificate") {
		t.Fatalf("login should renew: rc=%d out=%s", rc, out)
	}
	if rc, _, errs := e.run(t, "verify"); rc != 0 {
		t.Fatalf("verify after renewal: %s", errs)
	}
}

func TestTokenWithoutKeyBindingIsRejected(t *testing.T) {
	for _, mode := range []string{"omit-nonce", "wrong-nonce", "wrong-aud"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			e.f.setMode(mode)
			rc, _, errs := e.run(t, "login")
			t.Logf("error: %s", strings.TrimSpace(errs))
			if rc != 1 || !strings.Contains(errs, "opkssh login") {
				t.Fatalf("rc=%d err=%s", rc, errs)
			}
			if _, err := os.Stat(certPath(e.key)); !os.IsNotExist(err) {
				t.Fatal("no certificate may be written on failure")
			}
		})
	}
}

func TestWrongPasswordDoesNotLeak(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(e.pwFile, []byte("wrong-secret"), 0o600)
	rc, out, errs := e.run(t, "login")
	if rc != 1 || !strings.Contains(errs, "invalid_grant") {
		t.Fatalf("rc=%d err=%s", rc, errs)
	}
	if strings.Contains(out+errs, "wrong-secret") {
		t.Fatal("password leaked into output")
	}
}

func TestTamperedPKTokenFailsVerify(t *testing.T) {
	e := newEnv(t)
	if rc, _, errs := e.run(t, "login"); rc != 0 {
		t.Fatal(errs)
	}
	// Tamper with the groups claim of the signed ID token, re-sign the client
	// part (cic) with the real key and rebuild the certificate. Only the OP
	// signature is invalid afterwards.
	lc, err := loadCert(e.key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(lc.pkt.OpToken), ".")
	var claims map[string]any
	json.Unmarshal(lc.pkt.Payload, &claims)
	claims["groups"] = []string{"ssh-users", "superadmin"}
	newPayload, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(newPayload)
	tamperedOp := []byte(strings.Join(parts, "."))

	raw, _ := os.ReadFile(e.key)
	signer, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	cic, err := lc.pkt.GetCicValues()
	if err != nil {
		t.Fatal(err)
	}
	cicToken, err := cic.Sign(signer.(*ecdsa.PrivateKey), jose.ES256, tamperedOp)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := pktoken.New(tamperedOp, cicToken)
	if err != nil {
		t.Fatal(err)
	}
	line, _, err := buildCert(tampered, signer.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(certPath(e.key), line, 0o600)
	rc, _, errs := e.run(t, "verify")
	t.Logf("error: %s", strings.TrimSpace(errs))
	if rc != 1 || !strings.Contains(errs, "verification failed") {
		t.Fatalf("tampered PK token was accepted (rc=%d)", rc)
	}
}

func TestRejectsPlainHTTPIssuer(t *testing.T) {
	e := newEnv(t)
	args := []string{"login", "-issuer", "http://example.invalid/application/o/opkssh/", "-client-id", testClientID,
		"-key", e.key, "-username", testUser, "-password-file", e.pwFile}
	var out, errb bytes.Buffer
	if rc := run(args, &out, &errb); rc != 1 || !strings.Contains(errb.String(), "https") {
		t.Fatalf("rc=%d err=%s", rc, errb.String())
	}
}

func TestUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	for _, k := range []string{"OPKSSH_M2M_ISSUER", "OPKSSH_M2M_CLIENT_ID", "OPKSSH_M2M_USERNAME", "OPKSSH_M2M_PASSWORD_FILE", "OPKSSH_M2M_KEY"} {
		t.Setenv(k, "")
	}
	if rc := run(nil, &out, &errb); rc != 2 {
		t.Fatalf("no command: rc=%d", rc)
	}
	if rc := run([]string{"bogus"}, &out, &errb); rc != 2 {
		t.Fatalf("unknown command: rc=%d", rc)
	}
	errb.Reset()
	if rc := run([]string{"login"}, &out, &errb); rc != 2 {
		t.Fatalf("login without options: rc=%d", rc)
	}
	for _, opt := range []string{"-key", "-issuer", "-client-id", "-username", "-password-file"} {
		if !strings.Contains(errb.String(), opt) {
			t.Errorf("missing option %s not reported: %s", opt, errb.String())
		}
	}
	errb.Reset()
	if rc := run([]string{"status"}, &out, &errb); rc != 2 || strings.Contains(errb.String(), "-issuer") {
		t.Fatalf("status needs only -key: rc=%d err=%s", rc, errb.String())
	}
	// Environment variables satisfy required options.
	t.Setenv("OPKSSH_M2M_KEY", filepath.Join(t.TempDir(), "k"))
	errb.Reset()
	if rc := run([]string{"status"}, &out, &errb); rc != 1 {
		t.Fatalf("status with key from env (no cert yet) should be rc=1, got %d: %s", rc, errb.String())
	}
}

func TestReadPassword(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	var errb bytes.Buffer
	os.WriteFile(p, []byte("  secret\r\n"), 0o644)
	pw, err := readPassword(p, &errb)
	if err != nil || string(pw) != "secret" || !strings.Contains(errb.String(), "WARNING") {
		t.Fatalf("pw=%q err=%v warn=%q", pw, err, errb.String())
	}
	os.WriteFile(p, []byte("a\nb\n"), 0o600)
	if _, err := readPassword(p, &errb); err == nil {
		t.Fatal("multi-line password file should fail")
	}
	os.WriteFile(p, []byte("\n"), 0o600)
	if _, err := readPassword(p, &errb); err == nil {
		t.Fatal("empty password file should fail")
	}
}

// Safety net: the nonce sent by the tool matches the format accepted by the
// authentik scope mapping (43 characters base64url).
func TestNonceFormatMatchesAuthentikMapping(t *testing.T) {
	e := newEnv(t)
	if rc, _, errs := e.run(t, "login"); rc != 0 {
		t.Fatal(errs)
	}
	lc, _ := loadCert(e.key)
	if !nonceRe.MatchString(lc.claims.Nonce) {
		t.Fatalf("nonce %q does not match the mapping regex", lc.claims.Nonce)
	}
	if _, err := base64.RawURLEncoding.DecodeString(lc.claims.Nonce); err != nil {
		t.Fatal(err)
	}
}
