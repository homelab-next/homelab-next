# SPDX-License-Identifier: Apache-2.0
# The context retrieval service (homelabnext/context_service, modules/context) as an image, built from a
# checkout of this repository: there is no published image to pin, so what runs is the code at the commit
# the image was built from, the hashed dependency set of requirements.txt and the embedding model pinned
# file by file (homelabnext/context/semantic_model.py: a 40-hex revision, a sha256 and a size per file).
#   docker build -f modules/context/image/Dockerfile -t hnx-context:<version>-<commit12> .
# Build context: the repository root (the Dockerfile.dockerignore beside this file sends only what is
# copied below). The base is pinned by digest (python 3.11.14, Debian 13 slim); git (the sources are
# fetched with it, inside the container) comes from the Debian archive as it was on the snapshot date
# below, at an exact version, verified by apt against the archive's signed release files. Every wheel is
# hash-checked (--require-hashes). The model is fetched once, here, and verified; at run time nothing is
# downloaded but the configured git sources.
FROM python:3.11.14-slim-trixie@sha256:c8271b1f627d0068857dce5b53e14a9558603b527e46f1f901722f935b786a39
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN printf '%s\n' \
      'Types: deb' 'URIs: http://snapshot.debian.org/archive/debian/20261101T000000Z' \
      'Suites: trixie trixie-updates' 'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' '' \
      'Types: deb' 'URIs: http://snapshot.debian.org/archive/debian-security/20261101T000000Z' \
      'Suites: trixie-security' 'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends git=1:2.47.3-0+deb13u1 \
 && rm -rf /var/lib/apt/lists/*
COPY modules/context/image/requirements.txt /tmp/requirements.txt
RUN python -m pip install --require-hashes --no-deps --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt
# the pinned embedding model, fetched and verified file by file (the service checks it again at
# start); the fetcher is standard library only, so it runs before the code is copied (a code change
# does not fetch the model again)
COPY homelabnext/context/semantic_model.py /tmp/semantic_model.py
RUN python /tmp/semantic_model.py /opt/hnx-context/model && rm /tmp/semantic_model.py \
 && chmod -R a+rX,go-w /opt/hnx-context
WORKDIR /app
COPY homelabnext /app/homelabnext
# nothing is downloaded at run time but the sources; every writable path is the /data mount and the
# library caches under it
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HOME=/data/home XDG_CACHE_HOME=/data/cache \
    PYTHONPATH=/app USER=context LOGNAME=context
USER 65532:65532
EXPOSE 8094
ENTRYPOINT ["python", "-m", "homelabnext.context_service"]
CMD ["serve"]
