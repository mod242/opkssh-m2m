package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
)

// m2mOp is an OpenPubkey OpenIdProvider for the OAuth client_credentials
// grant with a service account (username + app password), as offered by
// authentik.
//
// Key binding: the hash of the client instance claims (cic) is sent as the
// form parameter "nonce". The OP must copy it into the nonce claim of the ID
// token (for authentik: a scope mapping, see authentik/README.md). This is
// exactly the binding opkssh verify requires for a generic OIDC issuer
// (commit type NONCE_CLAIM).
type m2mOp struct {
	issuer        string
	clientID      string
	username      string
	password      []byte
	scopes        string
	tokenEndpoint string
	httpClient    *http.Client
	finder        discover.PublicKeyFinder
}

var _ providers.OpenIdProvider = (*m2mOp)(nil)

const maxResponseBytes = 1 << 20

type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
	JwksURI       string `json:"jwks_uri"`
}

func newM2MOp(ctx context.Context, cfg *config, httpClient *http.Client) (*m2mOp, error) {
	if !strings.HasPrefix(cfg.issuer, "https://") {
		return nil, fmt.Errorf("issuer must use https: %s", cfg.issuer)
	}
	doc, err := fetchDiscovery(ctx, cfg.issuer, httpClient)
	if err != nil {
		return nil, err
	}
	if doc.Issuer != cfg.issuer {
		return nil, fmt.Errorf("discovery returned issuer %q, expected %q", doc.Issuer, cfg.issuer)
	}
	if !strings.HasPrefix(doc.TokenEndpoint, "https://") {
		return nil, fmt.Errorf("token_endpoint is not https: %q", doc.TokenEndpoint)
	}
	op := &m2mOp{
		issuer:        cfg.issuer,
		clientID:      cfg.clientID,
		username:      cfg.username,
		password:      cfg.password,
		scopes:        cfg.scopes,
		tokenEndpoint: doc.TokenEndpoint,
		httpClient:    httpClient,
	}
	op.finder = discover.PublicKeyFinder{
		JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
			return discover.GetJwksByIssuer(ctx, issuer, httpClient)
		},
	}
	return op, nil
}

func fetchDiscovery(ctx context.Context, issuer string, httpClient *http.Client) (*discoveryDoc, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("discovery: invalid JSON: %w", err)
	}
	return &doc, nil
}

func (o *m2mOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	nonce, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("cic hash: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", o.clientID)
	form.Set("username", o.username)
	form.Set("password", string(o.password))
	form.Set("scope", o.scopes)
	form.Set("nonce", string(nonce))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.httpClient.Do(req)
	if err != nil {
		// url.Error contains only the URL, never the form body.
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	var tr struct {
		IDToken          string `json:"id_token"`
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK || tr.Error != "" {
		msg := tr.Error
		if msg == "" {
			msg = "unknown error"
		}
		if tr.ErrorDescription != "" {
			msg += ": " + tr.ErrorDescription
		}
		return nil, fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, msg)
	}
	if tr.IDToken == "" {
		return nil, errors.New("token response has no id_token (was scope openid requested?)")
	}
	return &simpleoidc.Tokens{IDToken: []byte(tr.IDToken), AccessToken: []byte(tr.AccessToken)}, nil
}

func (o *m2mOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return o.finder.ByToken(ctx, o.issuer, token, true)
}

func (o *m2mOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return o.finder.ByKeyID(ctx, o.issuer, keyID, true)
}

func (o *m2mOp) Issuer() string { return o.issuer }

// VerifyIDToken checks like opkssh verify does for a generic issuer:
// signature, iss, aud == client_id and nonce == hash of the cic.
func (o *m2mOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	return providers.NewProviderVerifier(o.issuer, providers.ProviderVerifierOpts{
		CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
		ClientID:          o.clientID,
		DiscoverPublicKey: &o.finder,
	}).VerifyIDToken(ctx, idt, cic)
}
