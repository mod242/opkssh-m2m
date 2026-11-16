package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/sshcert"
	"golang.org/x/crypto/ssh"
)

// Same as opkssh login: sshd rejects certificates without principals; the
// actual authorization decision is made by opkssh verify based on auth_id.
var certPrincipals = []string{"opkssh-wildcard"}

const certComment = "openpubkey"

func certPath(keyPath string) string { return keyPath + "-cert.pub" }

// buildCert creates a self-signed SSH user certificate carrying the PK token
// in the openpubkey-pkt extension, like opkssh login does.
func buildCert(pkt *pktoken.PKToken, signer crypto.Signer) (certLine, keyPEM []byte, err error) {
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		return nil, nil, fmt.Errorf("unsupported key type %T", signer)
	}
	smuggler, err := sshcert.New(pkt, nil, certPrincipals)
	if err != nil {
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}
	algSigner, ok := sshSigner.(ssh.AlgorithmSigner)
	if !ok {
		return nil, nil, errors.New("SSH signer does not support algorithm selection")
	}
	mas, err := ssh.NewSignerWithAlgorithms(algSigner, []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}
	sshCert, err := smuggler.SignCert(mas)
	if err != nil {
		return nil, nil, err
	}
	certLine = bytes.TrimRight(ssh.MarshalAuthorizedKey(sshCert), "\n")
	certLine = append(certLine, []byte(" "+certComment+"\n")...)

	block, err := ssh.MarshalPrivateKey(signer, "opkssh-m2m")
	if err != nil {
		return nil, nil, err
	}
	return certLine, pem.EncodeToMemory(block), nil
}

// writeKeyAndCert writes both files atomically (temp + rename) with mode 0600.
// The directory is created with 0700 if needed and must not be group- or
// world-writable.
func writeKeyAndCert(keyPath string, keyPEM, certLine []byte) error {
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("directory %s is group- or world-writable", dir)
	}
	keyTmp, err := writeTemp(dir, keyPEM)
	if err != nil {
		return err
	}
	certTmp, err := writeTemp(dir, certLine)
	if err != nil {
		os.Remove(keyTmp)
		return err
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		os.Remove(keyTmp)
		os.Remove(certTmp)
		return err
	}
	if err := os.Rename(certTmp, certPath(keyPath)); err != nil {
		os.Remove(certTmp)
		return err
	}
	return nil
}

func writeTemp(dir string, data []byte) (name string, err error) {
	f, err := os.CreateTemp(dir, ".opkssh-m2m-*")
	if err != nil {
		return "", err
	}
	name = f.Name()
	defer func() {
		if err != nil {
			os.Remove(name)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		f.Close()
		return "", err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return name, nil
}

// tokenClaims are the claims needed for display and renewal decisions.
type tokenClaims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          any      `json:"aud"`
	IssuedAt          int64    `json:"iat"`
	Expiry            int64    `json:"exp"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
	Nonce             string   `json:"nonce"`
}

func (c tokenClaims) expiresAt() time.Time { return time.Unix(c.Expiry, 0) }

func claimsFromPKT(pkt *pktoken.PKToken) (*tokenClaims, error) {
	var c tokenClaims
	if err := json.Unmarshal(pkt.Payload, &c); err != nil {
		return nil, fmt.Errorf("ID token claims: %w", err)
	}
	return &c, nil
}

// loadedCert is an existing key/certificate pair.
type loadedCert struct {
	smuggler *sshcert.SshCertSmuggler
	pkt      *pktoken.PKToken
	claims   *tokenClaims
	keyMatch bool
}

// loadCert reads the certificate and its PK token. Nothing is verified
// cryptographically here (that is done by the verify command or the target
// server); it is only used to decide whether a renewal is needed.
func loadCert(keyPath string) (*loadedCert, error) {
	raw, err := os.ReadFile(certPath(keyPath))
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("file does not contain an SSH certificate")
	}
	sm := &sshcert.SshCertSmuggler{SshCert: cert}
	pkt, err := sm.GetPKToken()
	if err != nil {
		return nil, fmt.Errorf("no valid PK token in certificate: %w", err)
	}
	claims, err := claimsFromPKT(pkt)
	if err != nil {
		return nil, err
	}
	lc := &loadedCert{smuggler: sm, pkt: pkt, claims: claims}

	keyRaw, err := os.ReadFile(keyPath)
	if err == nil {
		if signer, perr := ssh.ParsePrivateKey(keyRaw); perr == nil {
			lc.keyMatch = bytes.Equal(signer.PublicKey().Marshal(), cert.Key.Marshal())
		}
	}
	return lc, nil
}
