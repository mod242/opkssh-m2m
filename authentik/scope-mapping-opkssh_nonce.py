# authentik scope mapping, scope name "opkssh_nonce".
# Only for client_credentials: copies the opkssh nonce (base64url SHA3-256 of
# the client instance claims, 43 characters) into the ID token and limits the
# token lifetime to 1 hour.
req = request.http_request
if req is None or req.POST.get("grant_type") != "client_credentials":
    return None
nonce = req.POST.get("nonce", "")
if not regex_match(nonce, r"^[A-Za-z0-9_-]{43}$"):
    return None
return {"nonce": nonce, "exp": int(token.auth_time.timestamp()) + 3600}
