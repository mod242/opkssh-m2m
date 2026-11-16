# opkssh-m2m

Unattended [opkssh](https://github.com/openpubkey/opkssh) logins for machines:
CI jobs, cron jobs, deployment or certificate-push tasks that need SSH access
without a browser.

`opkssh-m2m` uses the OAuth 2.0 `client_credentials` grant with a service account
and produces the same kind of SSH certificate as `opkssh login`. The target
servers need **no changes**: an unmodified opkssh (tested with v0.19.2) accepts the
certificate through its regular generic-issuer path.

It has been tested with **authentik** as OpenID Provider. Other providers work
only if they can be configured to echo a client-supplied `nonce` into the ID
token of a `client_credentials` response (see [How it works](#how-it-works)).

> Status: young project, used in production for one setup. Feedback welcome.
> Not affiliated with the opkssh/OpenPubkey or authentik projects.

## How it works

`opkssh verify` accepts an ID token for a generic OIDC issuer only if its
`nonce` claim commits to the user's SSH public key (the hash of OpenPubkey's
*client instance claims*). Interactive logins get this binding from the
authorization code flow. `client_credentials` has no nonce, so:

1. `opkssh-m2m` generates a fresh ECDSA P-256 key, like `opkssh login`.
2. It sends the commitment hash as an extra form parameter `nonce` to the token
   endpoint, together with the service account's username and app password,
   and requests the scope `opkssh_nonce`.
3. An authentik **scope mapping** copies that `nonce` into the ID token and
   shortens the token lifetime to 1 hour.
4. OpenPubkey builds and immediately verifies the PK token (signature, `aud`,
   nonce binding).
5. `opkssh-m2m` writes the private key and a self-signed SSH certificate carrying
   the PK token (`<key>` and `<key>-cert.pub`, both `0600`). `ssh -i <key>` uses
   the certificate automatically.

The SSH certificate itself is valid "forever"; the server enforces the ID
token's `exp` (expiration policy `oidc`), exactly as for interactive logins.

Background and discussion: opkssh PR
[#520](https://github.com/openpubkey/opkssh/pull/520) (client credentials flow).

## Setup

1. **authentik:** follow [`authentik/README.md`](authentik/README.md)
   (service account, scope mapping, application policy).
2. **Servers:** nothing new if your provider is already configured for
   interactive opkssh logins. The service account is authorized like any user,
   for example via a group rule:

   ```
   # /etc/opk/providers
   https://auth.example.com/application/o/opkssh/ <client_id> oidc
   # /etc/opk/auth_id
   deploy oidc:groups:ssh-users https://auth.example.com/application/o/opkssh/
   ```

3. **Client:** store the app password in a file readable only by the job
   (`0400`/`0600`, a trailing newline is ignored) and install `opkssh-m2m`.

## Usage

```sh
export OPKSSH_M2M_ISSUER=https://auth.example.com/application/o/opkssh/
export OPKSSH_M2M_CLIENT_ID=<client_id>
export OPKSSH_M2M_USERNAME=svc-deploy
export OPKSSH_M2M_PASSWORD_FILE=/run/secrets/opkssh-app-password
export OPKSSH_M2M_KEY=/run/opkssh/id_m2m

# Before each SSH connection (or batch): renews only if the certificate is
# missing, does not match the key/issuer, or has less than 15 min left.
opkssh-m2m login
ssh -i "$OPKSSH_M2M_KEY" deploy@server.example.com

opkssh-m2m status                    # offline; exit 0 = valid for at least 15 min
opkssh-m2m verify -group ssh-users   # runs the opkssh server verifier locally (needs network)
```

| Option | Environment | Commands |
|---|---|---|
| `-issuer` | `OPKSSH_M2M_ISSUER` | login, verify (status: optional check) |
| `-client-id` | `OPKSSH_M2M_CLIENT_ID` | login, verify |
| `-username` | `OPKSSH_M2M_USERNAME` | login |
| `-password-file` | `OPKSSH_M2M_PASSWORD_FILE` | login |
| `-scopes` | `OPKSSH_M2M_SCOPES` | login (default `openid profile email opkssh_nonce`) |
| `-key` | `OPKSSH_M2M_KEY` | all |
| `-min-remaining` | | login, status (default `15m`) |
| `-force` | | login |
| `-group` | | verify |
| `-timeout` | | all (default `30s`) |

Exit codes: `0` ok, `1` error, `2` usage error. The password is never printed.

## Security notes

- The app password is a long-lived secret that can mint SSH access for the
  service account. Treat it like a private key: secret store, minimal
  permissions, expiry date, rotation.
- Enabling `client_credentials` on the provider you use for interactive logins
  lets **any** user with an app password obtain tokens without browser/MFA,
  unless you restrict it. The policy in `authentik/` allows non-interactive
  grants only for the service account. The application's policy engine mode
  must be `all`.
- Echoing a client-supplied nonce in `client_credentials` is not standard
  OAuth/OIDC. The `exp` override relies on authentik merging scope mapping
  claims after the standard claims; if a future authentik version changes that,
  tokens fall back to the access token lifetime (`opkssh-m2m login` prints the
  expiry, so this is visible).
- OpenPubkey uses [memguard](https://github.com/awnumar/memguard), which locks
  memory (`mlock`). Very restrictive container limits may need adjusting.

## Verifying releases

Release archives come with `checksums.txt` and a GitHub build provenance
attestation:

```sh
sha256sum -c --ignore-missing checksums.txt
gh attestation verify opkssh-m2m_<version>_linux_amd64.tar.gz --repo mod242/opkssh-m2m
```

Each archive includes the licenses of all linked third-party modules in
`third_party_licenses/`.

## Development

```sh
go test ./...                 # fake authentik over TLS + opkssh's real verifier code
go tool govulncheck ./...
```

The tests check the certificate format, file permissions, idempotent renewal,
key mismatch detection, and that tokens without a valid nonce binding, with a
wrong audience, or with a tampered payload are rejected by opkssh's verifier.

Dependencies are updated weekly by Dependabot; minor and patch updates are
merged automatically once CI passes. Releases are cut manually by pushing a
`v*` tag.

## License

MIT, see [LICENSE](LICENSE). Third-party licenses: see release archives or run
`scripts/third-party-licenses.sh`.
