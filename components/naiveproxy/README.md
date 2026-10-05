# NaiveProxy server

This is Caddy v2.11.7 plus the official `klzgrad/forwardproxy` Naive server plugin,
verified stable tag `v2.11.2-naive`, commit `d62c80d3dd2c706b6b87579844d2397bddd18317`.
It is not the separate Chromium-based NaiveProxy client. The plugin retains its
original Caddy module path, so the Go `replace` directive is intentional.

The minimal entrypoint and dependency lock were generated with official xcaddy
v0.4.7, then committed here so builds never resolve a moving plugin branch or
regenerate dependencies. Use `scripts/build-components.sh naiveproxy` with the
pinned Go compiler. `go version -m build/naiveproxy-linux-amd64` exposes the exact
replacement commit used in the binary.
