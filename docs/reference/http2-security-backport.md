# HTTP/2 security backport

This branch is based on Chainguard's `controller-v1.15.14` release
(`4044746332b4d38c5944745bb439f3bf75379cca`). It retains the existing
NGINX 1.27.1 patch stack and adds these upstream fixes:

| CVE | Upstream fix | Backport |
| --- | --- | --- |
| CVE-2026-123007 | [Account for queued DATA when validating WINDOW_UPDATE](https://github.com/nginx/nginx/commit/e27f5fa84fe6e98505e70bc543b748747dad0a3b) | `51_nginx-1.27.1-CVE-2026-123007.patch` |
| CVE-2026-123633 | [Clear reusable status when creating a stream](https://github.com/nginx/nginx/commit/2df48a501d0fb8212b7d39dffeeff5876332ba59) | `52_nginx-1.27.1-CVE-2026-123633.patch` |

## Build and publish

Run the manually triggered [Build patched HTTP2 controller image workflow](../../.github/workflows/lunar-http2-image.yml), or:

```sh
gh workflow run lunar-http2-image.yml --repo blacksails/ingress-nginx \
  --ref lunar/backport-nginx-http2-rce
```

It builds and tests a `linux/amd64` image before pushing
`ghcr.io/blacksails/ingress-nginx-controller:v1.15.14-lunar.1`.
The run summary records the image digest. Pin that digest when deploying.
A registry push does not guarantee anonymous pull access: check the package's
visibility and configure pull credentials if it is private.

The workflow uses the repository's existing NGINX-base and controller
Dockerfiles; it does not layer a new nginx binary onto an existing vendor image.
All bundled dynamic modules are rebuilt against the patched headers because
CVE-2026-123007's fix changes the HTTP/2 connection structure layout.
The original NGINX version string remains 1.27.1; identify this build by its
controller version, source revision and image digest instead.

## Tests

```sh
make -C images/nginx test TESTS="t/h2_security.t t/harness.t h2_http2.t h2_keepalive.t h2_request_body.t h2_priority.t h2_ssl.t h2_ssl_verify_client.t proxy.t"
# Negative control: both security assertions should fail without the fixes.
make -C images/nginx test NGINX_TESTS_FLAVOR=pristine TESTS=t/h2_security.t
```

The regression checks cover queued-DATA window validation and non-reusable
status during stream creation after fragmented HEADERS. They do not attempt
RCE. The test image uses AddressSanitizer and excludes third-party modules;
the publishing workflow separately smoke-tests the final image's modules,
Lua initialization, HTTP serving, UID 101 and legacy shutdown binary path.

## Deployment limits

This is a community build of the public Chainguard fork on Alpine, **not**
Chainguard's private Wolfi image, and it does not carry Chainguard's signing,
SBOM, attestation or support guarantees. It only adds the two CVE fixes above;
it is not a claim that the entire image is free of vulnerabilities.

The legacy `/usr/local/openresty/nginx/sbin/nginx` shutdown path is retained
as a symlink. Stage in a non-production cluster and verify routing, metrics,
TLS/mTLS, SSL passthrough, HTTP/2/gRPC and graceful rollout before production.
This repository and publishing workflow do not modify any cluster.
