# bids-hook
Tiny CI server to run bids-validator using Gitea webhooks


## Deployment

Results are placed in `%(GITEA_CUSTOM)/public/bids-validator/`;
this folder needs to be writable (and ideally created first and owned)
by the user running this daemon.

It assumes the URL `%(ROOT_URL)s/static/assets/` loads from
Gitea's `%(GITEA_CUSTOM)/public/`; it is **not** compatible
with configuring Gitea's `%(STATIC_URL_PREFIX)` so that
static files are hosted on a different server or CDN.

`%(GITEA_TOKEN)` must be from an admin account with the "all" scope for two reasons:

1. To install the webhook that notifies on pushes
2. To be able to post status icons on any repo without being a member of all repos

Perhaps in the future Gitea will offer even more finely-grained scopes, but today is not that day.
