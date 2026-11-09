# SPDX-License-Identifier: Apache-2.0
# The orchestration controller (orchestrator/cmd/controller), built from this checkout with the
# module's own pinned go.sum (GOFLAGS=-mod=readonly, GOTOOLCHAIN=local: the image's Go must be
# the module's), and the lab's configuration and entrypoint (config/orchestrator/,
# orchestrator/entrypoint.sh).  The image is both the build and the runtime: the lab's exec runner
# runs /bin/sh sessions.  Build context is the repository root:
#   docker build -f compose/lab-in-a-box/orchestrator/Dockerfile .
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off CGO_ENABLED=0
WORKDIR /src/orchestrator
COPY orchestrator/go.mod orchestrator/go.sum /src/orchestrator/
RUN go mod download
COPY orchestrator /src/orchestrator
RUN go build -trimpath -o /usr/local/bin/controller ./cmd/controller \
 && go clean -cache -modcache \
 && groupadd --system --gid 10030 hnx-orchestrator \
 && useradd --system --uid 10030 --gid 10030 --no-create-home hnx-orchestrator \
 && install -d -o hnx-orchestrator -g hnx-orchestrator -m 0700 /var/lib/orchestrator
# root-owned and read-only to the controller: its configuration and its one profile
COPY compose/lab-in-a-box/config/orchestrator /etc/orchestrator
COPY compose/lab-in-a-box/orchestrator/entrypoint.sh /app/entrypoint.sh
USER 10030:10030
