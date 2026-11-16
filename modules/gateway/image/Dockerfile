# SPDX-License-Identifier: Apache-2.0
# The lab's own LLM gateway (orchestrator/cmd/gateway, ADR-0038) as an image, built from a
# checkout of this repository: the module's role runs it from a pinned reference to the image this
# file builds, so what runs is the code at the commit the image was built from, together with the
# same go.sum CI's gateway-conformance job built and tested. Build context: the repository root.
#   docker build -f modules/gateway/image/Dockerfile -t hnx-llm-gateway:<version>-<commit> .
# The gateway imports the standard library only, so the build fetches nothing from a module proxy
# (GOFLAGS=-mod=readonly, GOTOOLCHAIN=local: the image's Go must be the module's). The runtime image
# is empty but for the binary, a health probe (an HTTP GET of /healthz on the port it is given,
# built here from a few lines of Go: the runtime has no shell and no curl) and the certificate bundle the build image carries,
# which the calls to a cloud provider's API verify against. It runs as an unprivileged numeric
# user and the module's compose service makes its root filesystem read-only.
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off CGO_ENABLED=0
WORKDIR /src/orchestrator
COPY orchestrator/go.mod orchestrator/go.sum /src/orchestrator/
COPY orchestrator /src/orchestrator
RUN mkdir /out \
 && go build -trimpath -ldflags='-s -w' -o /out/llm-gateway ./cmd/gateway
RUN mkdir /probe \
 && printf '%s\n' \
      'package main' \
      'import ("net/http"; "os")' \
      'func main() {' \
      '  if len(os.Args) != 2 { os.Exit(2) }' \
      '  r, err := http.Get("http://localhost:" + os.Args[1] + "/healthz")' \
      '  if err != nil || r.StatusCode != 200 { os.Exit(1) }' \
      '}' > /probe/main.go \
 && cd /probe && GOFLAGS= go build -trimpath -ldflags='-s -w' -o /out/healthcheck main.go

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/llm-gateway /usr/local/bin/llm-gateway
COPY --from=build /out/healthcheck /usr/local/bin/healthcheck
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/llm-gateway"]
