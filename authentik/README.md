# authentik setup

Tested with authentik 2026.8.5. The steps assume an existing OAuth2/OpenID
provider and application that you already use for interactive opkssh logins.
Names used below (adjust to your setup):

- service account `svc-deploy`
- SSH group `ssh-users`
- application/provider slug `opkssh`

## 1. Scope mapping

*Customization → Property Mappings → Create → Scope Mapping*

- Name: `opkssh nonce (client_credentials)`
- Scope name: `opkssh_nonce`
- Expression: [`scope-mapping-opkssh_nonce.py`](scope-mapping-opkssh_nonce.py)

The mapping only acts on `client_credentials` requests that carry a
well-formed nonce (43 characters base64url). Interactive logins are unaffected.
Without it, the ID token has no `nonce` and opkssh rejects the certificate
(`missing commitment claim nonce`).

The mapping also sets `exp` to 1 hour after authentication. Adjust `3600` if
your jobs need a different lifetime; keep it short.

## 2. Provider

*Applications → Providers → (your opkssh provider) → Edit*

- Add the scope mapping `opkssh_nonce` to the selected scopes.
- Add `client_credentials` to the allowed grant types (API field `grant_types`).
- Keep the default `profile` mapping if your server rules use the `groups` claim.

No client secret is needed for `client_credentials` with username + app password.

## 3. Service account

*Directory → Users → Create Service account*

- Username: `svc-deploy`. Leave *Create group* unchecked, keep *Expiring*
  enabled and set an expiry date for the generated app password (token).
- Add the account to `ssh-users` (or whichever group your `auth_id` rules use).
- Copy the app password **once** into the secret store of your job. Do not
  write it with a trailing newline into places that do not trim it (e.g. `curl -d @file`);
  `opkssh-m2m` itself trims it.

## 4. Restrict non-interactive grants

Enabling `client_credentials` on the provider also allows **every** user with
an app password to get an ID token without the browser/MFA flow. Restrict it:

*Customization → Policies → Create → Expression Policy*

- Expression: [`policy-restrict-non-interactive.py`](policy-restrict-non-interactive.py)
  (set `SERVICE_ACCOUNT` and `SSH_GROUP`).

*Applications → Applications → opkssh → Policy / Group / User Bindings*

- Bind the policy.
- Remove direct group bindings that would otherwise grant access on their own
  (the policy already checks the group).
- Set **Policy engine mode** to `all`. With `any`, a single passing binding
  (for example an old group binding) would bypass the restriction.

## 5. Test

```sh
opkssh-m2m login  -issuer https://auth.example.com/application/o/opkssh/ \
  -client-id <client_id> -username svc-deploy \
  -password-file ./app-password -key ./id_m2m
opkssh-m2m verify -issuer https://auth.example.com/application/o/opkssh/ \
  -client-id <client_id> -key ./id_m2m -group ssh-users
```

Expected: `expires` about 1 hour from now, the group in `groups`, and
`verify OK`. Then check that a normal user's app password is rejected
(`invalid_grant` or access denied) and that interactive `opkssh login` still works.

## Rollback

1. Provider: remove `client_credentials` from the grant types and remove the
   `opkssh_nonce` mapping.
2. Application: restore the previous bindings and policy engine mode.
3. Delete the policy and the scope mapping.
4. Deactivate or delete the service account (this also revokes its app password).
