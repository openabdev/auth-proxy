# Runtime images for the size comparison. The binaries are static musl builds
# (cargo zigbuild --release --target x86_64-unknown-linux-musl); rustls with
# compiled-in web PKI roots, so no CA bundle or libc is needed in the image.
#   docker build --platform linux/amd64 -f docker/Dockerfile --target a     -t ap-spike-a .
#   docker build --platform linux/amd64 -f docker/Dockerfile --target authz -t ap-spike-authz .
# Option B also needs envoyproxy/envoy:distroless-v1.40.2 (or v1.40.2).
FROM scratch AS a
COPY target/x86_64-unknown-linux-musl/release/ap-proxy /ap-proxy
USER 65532:65532
ENTRYPOINT ["/ap-proxy", "/etc/ap/config.json"]

FROM scratch AS authz
COPY target/x86_64-unknown-linux-musl/release/ap-authz /ap-authz
USER 65532:65532
ENTRYPOINT ["/ap-authz", "serve", "/etc/ap/config.json"]
