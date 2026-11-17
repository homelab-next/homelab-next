# SPDX-License-Identifier: Apache-2.0
# The cloned-voice speech service (homelabnext/tts_service) as an image, built from a checkout of this
# repository: there is no published image to pin, so what runs is the code at the commit the image was
# built from together with the hashed dependency set of requirements-<backend>.txt.
#   docker build -f modules/tts/image/Dockerfile --build-arg BACKEND=cpu -t hnx-tts:<version>-<commit12> .
# BACKEND is cpu or cuda (torch's CUDA 12.8 build). Build context: the repository root (the
# Dockerfile.dockerignore beside this file sends only what is copied below).
# The base is pinned by digest (python 3.11.14, Debian 13 slim). Every wheel is hash-checked
# (--require-hashes) and nothing is fetched at run time: the model is the model store's files, mounted
# read-only, and the container is started offline.
FROM python:3.11.17-slim-trixie@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377
ARG BACKEND=cpu
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY modules/tts/image/requirements-${BACKEND}.txt /tmp/requirements.txt
# wheels only, but for docopt (a pure-python package that is published as a source archive only)
RUN python -m pip install --require-hashes --no-deps --only-binary=:all: --no-binary=docopt -r /tmp/requirements.txt && rm /tmp/requirements.txt
WORKDIR /app
COPY homelabnext/tts_service /app/tts_service
# nothing may be downloaded at run time, and every writable path is the one /cache mount (USER: the
# container runs as an id with no account, and torch asks for a user name to name its cache directory)
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HOME=/cache/home XDG_CACHE_HOME=/cache/xdg \
    NUMBA_CACHE_DIR=/cache/numba MPLCONFIGDIR=/cache/mpl TORCH_HOME=/cache/torch \
    TORCHINDUCTOR_CACHE_DIR=/cache/inductor TRITON_CACHE_DIR=/cache/triton USER=tts LOGNAME=tts \
    TTS_BACKEND=${BACKEND}
USER 65532:65532
EXPOSE 8091
ENTRYPOINT ["python", "-m", "tts_service"]
CMD ["serve"]
