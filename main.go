// opkssh-m2m performs an unattended opkssh login using the OAuth 2.0
// client_credentials grant of an OpenID Provider (tested with authentik).
//
// It generates a fresh ECDSA P-256 key, obtains an ID token whose nonce is
// bound to that key, and writes the key plus an opkssh SSH certificate
// (<key>-cert.pub). A plain "ssh -i <key>" picks up the certificate.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/opkssh/policy"
)

var version = "dev"

const defaultScopes = "openid profile email opkssh_nonce"

type config struct {
	issuer       string
	clientID     string
	username     string
	passwordFile string
	password     []byte
	scopes       string
	keyPath      string
	minRemaining time.Duration
	timeout      time.Duration
	force        bool
	group        string
}

// httpClientFactory can be replaced in tests.
var httpClientFactory = func(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `opkssh-m2m `+version+` - unattended opkssh login via OAuth client_credentials

  opkssh-m2m login  -issuer URL -client-id ID -username USER -password-file FILE -key PATH [options]
      Renews key and certificate if none exists, the certificate does not match
      the key or issuer, or less than -min-remaining of its lifetime is left.
  opkssh-m2m status -key PATH [-issuer URL] [-min-remaining DURATION]
      Shows identity and remaining lifetime. Exits 0 only if the key matches,
      the issuer matches (if given) and enough lifetime is left. Offline.
  opkssh-m2m verify -issuer URL -client-id ID -key PATH [-group NAME]
      Verifies the certificate with the opkssh server-side verifier code, as a
      server with the providers line "<issuer> <client_id> oidc" would.
      Needs network access (JWKS).
  opkssh-m2m version

Options can also be set via environment variables:
  OPKSSH_M2M_ISSUER, OPKSSH_M2M_CLIENT_ID, OPKSSH_M2M_USERNAME,
  OPKSSH_M2M_PASSWORD_FILE, OPKSSH_M2M_KEY, OPKSSH_M2M_SCOPES

Exit codes: 0 ok, 1 error, 2 usage error.
`)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func newFlagSet(name string, cfg *config, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.issuer, "issuer", envOr("OPKSSH_M2M_ISSUER", ""), "OpenID issuer URL, exactly as in the discovery document")
	fs.StringVar(&cfg.clientID, "client-id", envOr("OPKSSH_M2M_CLIENT_ID", ""), "OAuth client ID (same as in /etc/opk/providers)")
	fs.StringVar(&cfg.keyPath, "key", envOr("OPKSSH_M2M_KEY", ""), "private key path; the certificate is <key>-cert.pub")
	fs.DurationVar(&cfg.minRemaining, "min-remaining", 15*time.Minute, "minimum remaining lifetime before renewal")
	fs.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "timeout for network operations")
	return fs
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cfg := &config{}
	var fs *flag.FlagSet
	switch args[0] {
	case "login":
		fs = newFlagSet("login", cfg, stderr)
		fs.StringVar(&cfg.username, "username", envOr("OPKSSH_M2M_USERNAME", ""), "service account username")
		fs.StringVar(&cfg.passwordFile, "password-file", envOr("OPKSSH_M2M_PASSWORD_FILE", ""), "file containing the service account's app password/token")
		fs.StringVar(&cfg.scopes, "scopes", envOr("OPKSSH_M2M_SCOPES", defaultScopes), "requested scopes")
		fs.BoolVar(&cfg.force, "force", false, "always log in again")
	case "status":
		fs = newFlagSet("status", cfg, stderr)
	case "verify":
		fs = newFlagSet("verify", cfg, stderr)
		fs.StringVar(&cfg.group, "group", "", "require this value in the groups claim (empty: no check)")
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}
	if missing := missingOptions(args[0], cfg); len(missing) > 0 {
		fmt.Fprintf(stderr, "missing required option(s): %s\n", strings.Join(missing, ", "))
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	var err error
	switch args[0] {
	case "login":
		err = cmdLogin(ctx, cfg, stdout, stderr)
	case "status":
		err = cmdStatus(cfg, stdout)
	case "verify":
		err = cmdVerify(ctx, cfg, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	return 0
}

func missingOptions(cmd string, cfg *config) []string {
	var m []string
	if cfg.keyPath == "" {
		m = append(m, "-key")
	}
	if cmd == "login" || cmd == "verify" {
		if cfg.issuer == "" {
			m = append(m, "-issuer")
		}
		if cfg.clientID == "" {
			m = append(m, "-client-id")
		}
	}
	if cmd == "login" {
		if cfg.username == "" {
			m = append(m, "-username")
		}
		if cfg.passwordFile == "" {
			m = append(m, "-password-file")
		}
	}
	return m
}

func readPassword(path string, stderr io.Writer) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(stderr, "WARNING: %s is accessible by group/others (%04o)\n", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pw := bytes.TrimSpace(raw)
	if len(pw) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	if bytes.ContainsAny(pw, "\r\n") {
		return nil, fmt.Errorf("%s contains more than one line", path)
	}
	return pw, nil
}

func describe(w io.Writer, c *tokenClaims, now time.Time) {
	fmt.Fprintf(w, "identity:   %s (sub %s)\n", c.PreferredUsername, c.Subject)
	fmt.Fprintf(w, "issuer:     %s\n", c.Issuer)
	fmt.Fprintf(w, "groups:     %s\n", strings.Join(c.Groups, ","))
	fmt.Fprintf(w, "expires:    %s (in %s)\n", c.expiresAt().UTC().Format(time.RFC3339),
		c.expiresAt().Sub(now).Truncate(time.Second))
}

func cmdLogin(ctx context.Context, cfg *config, stdout, stderr io.Writer) error {
	now := time.Now()
	if !cfg.force {
		if lc, err := loadCert(cfg.keyPath); err == nil && lc.keyMatch &&
			lc.claims.Issuer == cfg.issuer && lc.claims.expiresAt().Sub(now) >= cfg.minRemaining {
			fmt.Fprintln(stdout, "existing certificate is still valid, not renewing")
			describe(stdout, lc.claims, now)
			return nil
		}
	}
	pw, err := readPassword(cfg.passwordFile, stderr)
	if err != nil {
		return err
	}
	cfg.password = pw

	httpClient := httpClientFactory(cfg.timeout)
	op, err := newM2MOp(ctx, cfg, httpClient)
	if err != nil {
		return err
	}
	signer, err := util.GenKeyPair(jose.ES256)
	if err != nil {
		return fmt.Errorf("key generation: %w", err)
	}
	opk, err := client.New(op, client.WithSigner(signer, jose.ES256))
	if err != nil {
		return err
	}
	// Auth verifies the PK token right away (signature, aud, nonce binding).
	pkt, err := opk.Auth(ctx)
	if err != nil {
		return fmt.Errorf("opkssh login: %w", err)
	}
	claims, err := claimsFromPKT(pkt)
	if err != nil {
		return err
	}
	lifetime := claims.expiresAt().Sub(now)
	if lifetime <= 0 {
		return errors.New("received token is already expired (check the clock)")
	}
	if lifetime < cfg.minRemaining {
		fmt.Fprintf(stderr, "WARNING: token lifetime %s is shorter than -min-remaining %s; every run will renew\n",
			lifetime.Truncate(time.Second), cfg.minRemaining)
	}
	certLine, keyPEM, err := buildCert(pkt, signer)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	if err := writeKeyAndCert(cfg.keyPath, keyPEM, certLine); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	fmt.Fprintf(stdout, "new certificate written: %s\n", certPath(cfg.keyPath))
	describe(stdout, claims, now)
	return nil
}

func cmdStatus(cfg *config, stdout io.Writer) error {
	lc, err := loadCert(cfg.keyPath)
	if err != nil {
		return err
	}
	now := time.Now()
	describe(stdout, lc.claims, now)
	if !lc.keyMatch {
		return errors.New("private key is missing or does not match the certificate")
	}
	if cfg.issuer != "" && lc.claims.Issuer != cfg.issuer {
		return fmt.Errorf("certificate was issued by %q, expected %q", lc.claims.Issuer, cfg.issuer)
	}
	if rem := lc.claims.expiresAt().Sub(now); rem < cfg.minRemaining {
		return fmt.Errorf("remaining lifetime %s is below %s", rem.Truncate(time.Second), cfg.minRemaining)
	}
	return nil
}

// cmdVerify uses the same code path as "opkssh verify" on a server
// (policy.ProviderPolicy -> verifier for a generic issuer, expiration "oidc").
// The auth_id mapping (group -> local account) is only approximated by -group.
func cmdVerify(ctx context.Context, cfg *config, stdout io.Writer) error {
	lc, err := loadCert(cfg.keyPath)
	if err != nil {
		return err
	}
	if !lc.keyMatch {
		return errors.New("private key is missing or does not match the certificate")
	}
	pp := &policy.ProviderPolicy{}
	pp.AddRow(policy.ProvidersRow{Issuer: cfg.issuer, ClientID: cfg.clientID, ExpirationPolicy: "oidc"})
	v, err := pp.CreateVerifier(discover.DiscoveryCacheConfig{})
	if err != nil {
		return err
	}
	if _, err := lc.smuggler.VerifySshPktCert(ctx, *v); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	if cfg.group != "" && !slices.Contains(lc.claims.Groups, cfg.group) {
		return fmt.Errorf("group %q not in groups claim", cfg.group)
	}
	describe(stdout, lc.claims, time.Now())
	fmt.Fprintln(stdout, "verify OK (signature, issuer, client ID, nonce binding, expiry, group)")
	return nil
}
