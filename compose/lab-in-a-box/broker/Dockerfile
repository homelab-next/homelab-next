# SPDX-License-Identifier: Apache-2.0
# The broker end-to-end services (broker, status-hub, broker-edge in docker-compose.yml): this
# checkout with the mcp and nats extras (nats: the broker's outbox relay), hash-pinned like CI
# (constraints/ci.txt), and the system users the
# example production manifest maps (examples/broker/manifest.production.yml).  Build context is
# the repository root:
#   docker build -f compose/lab-in-a-box/broker/Dockerfile .
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONPATH=/src
WORKDIR /src
COPY constraints/bootstrap.txt constraints/ci.txt /src/constraints/
COPY pyproject.toml /src/
# pip from bootstrap.txt (--require-hashes); the project's requirements and the mcp and nats
# extras under ci.txt, whose hashes pip enforces; nothing is installed from this checkout
# (PYTHONPATH=/src)
RUN python -m pip install --no-cache-dir --require-hashes --no-deps -r constraints/bootstrap.txt \
 && python -c "import tomllib; p = tomllib.load(open('pyproject.toml', 'rb'))['project']; x = p['optional-dependencies']; print('\n'.join(dict.fromkeys(p['dependencies'] + x['mcp'] + x['nats'])))" > /tmp/requirements.txt \
 && python -m pip install --no-cache-dir -c constraints/ci.txt -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt
# one system user per peer of the socket: the broker, the triage and reader agents (callers), the
# hub (the approval relay); 10013 is deliberately nobody's.  The clients' group may reach the
# socket; the broker's own group may only traverse its data root (the edge stats a lane file).
# The broker's outbox relay is its own user, hnx-broker-relay: through its group it may traverse
# the state directory (0710) and read outbox/ (2750: new files inherit the group, 0640), and it
# owns relay/ (2750: the broker's group reads the markers, to prune the outbox).  Everything else in
# the state directory (approvals/, claims/, the digest key, ...) stays 0700 the broker's.
RUN groupadd --system --gid 10020 hnx-broker-clients \
 && groupadd --system --gid 10010 hnx-broker \
 && useradd --system --uid 10010 --gid 10010 --no-create-home hnx-broker \
 && groupadd --system --gid 10011 hnx-agent-triage \
 && useradd --system --uid 10011 --gid 10011 -G hnx-broker-clients --no-create-home hnx-agent-triage \
 && groupadd --system --gid 10012 hnx-hub \
 && useradd --system --uid 10012 --gid 10012 -G hnx-broker-clients --no-create-home hnx-hub \
 && groupadd --system --gid 10014 hnx-agent-reader \
 && useradd --system --uid 10014 --gid 10014 -G hnx-broker-clients --no-create-home hnx-agent-reader \
 && groupadd --system --gid 10015 hnx-broker-relay \
 && useradd --system --uid 10015 --gid 10015 --no-create-home hnx-broker-relay \
 && install -d -o hnx-broker -g hnx-broker-clients -m 0750 /run/hnx-broker \
 && install -d -o hnx-broker -g hnx-broker-relay -m 0710 /var/lib/hnx-broker \
 && install -d -o hnx-broker -g hnx-broker-relay -m 0710 /var/lib/hnx-broker/state \
 && install -d -o hnx-broker -g hnx-broker-relay -m 2750 /var/lib/hnx-broker/state/outbox \
 && install -d -o hnx-broker-relay -g hnx-broker -m 2750 /var/lib/hnx-broker/state/relay \
 && install -d -o hnx-broker -g hnx-broker -m 0750 /srv/agents \
 && install -d -o hnx-hub -g hnx-hub -m 0700 /var/lib/hnx-hub
COPY homelabnext /src/homelabnext
COPY conformance /src/conformance
COPY schemas /src/schemas
COPY profiles /src/profiles
COPY examples /src/examples
COPY compose/lab-in-a-box/broker_e2e.py /src/compose/lab-in-a-box/broker_e2e.py
COPY compose/lab-in-a-box/broker/events-relay.yml /src/compose/lab-in-a-box/broker/events-relay.yml
USER 10010
CMD ["python", "-m", "homelabnext.cli", "broker", "--help"]
