# authentik expression policy, bound to the opkssh application
# (policy engine mode "all").
# Humans may only log in interactively (browser, MFA); non-interactive grants
# are allowed for the named service account only.
SERVICE_ACCOUNT = "svc-deploy"   # adjust
SSH_GROUP = "ssh-users"          # adjust

grant = request.context.get("oauth_grant_type")
if grant in ("client_credentials", "password"):
    return request.user.username == SERVICE_ACCOUNT and ak_is_group_member(request.user, name=SSH_GROUP)
return ak_is_group_member(request.user, name=SSH_GROUP)
