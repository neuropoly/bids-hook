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
