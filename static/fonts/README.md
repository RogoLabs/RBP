# Fonts

`inter-latin.woff2` is Inter, latin subset, variable weight 100 to 900, taken from
Google Fonts (`v20`) and served from this repository rather than from
`fonts.gstatic.com`.

**Why self-hosted.** The site previously loaded Inter through a render-blocking
`<link>` to `fonts.googleapis.com`, plus two `preconnect` hints. The audience is
CNAs and security teams, a meaningful share of them behind proxies that block
third-party font hosts, so the site's typography depended on a request some
readers were never going to complete. It is also a third-party request on every
page of a site whose whole subject is transparency.

**One file, not four.** Google's CSS declares five weights for the latin subset
and serves the *same* variable font for all of them; the four this site uses
(400, 500, 600, 700) were byte-identical downloads. So there is one 48 KB file and
one `@font-face` with `font-weight: 100 900`. The site never used the 300 weight
it was asking for.

**Licence.** SIL Open Font License 1.1. Full text in `LICENSE-Inter.txt`.
Upstream: https://github.com/rsms/inter

**Regenerating.** Fetch the Google Fonts CSS with a browser user-agent, take any
`/* latin */` face's `woff2` URL, and save it here. The `unicode-range` in
`static/css/rbp.css` must match the one that CSS declares for the latin subset.
