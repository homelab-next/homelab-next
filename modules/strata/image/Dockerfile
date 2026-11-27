# SPDX-License-Identifier: Apache-2.0
# Strata (https://github.com/Niko1221/Strata, MIT) built from a pinned release for one NVIDIA GA100 card
# (sm_80: the CMP 170HX), as the image the module `strata` runs. The recipe (README.md, "The image") builds it
# from the module directory alone: the context is modules/strata (Dockerfile.dockerignore sends only the role's
# files/image/: entrypoint.sh and healthcheck.py, which the role's variables are the contract of), the source comes
# from GitHub at a release TAG and is refused unless the tag resolves to the pinned COMMIT.
#
# Stages 2 and 3 are the upstream's tools/docker/Dockerfile.src at that commit (engine compiled in docker,
# the engine component package verified, the Terminal built as the release archive), cut down to the one
# engine this lab runs: CUDA 13, sm_80 only (real code, plus PTX for sm_80), no picture reader, no Hy4 or
# Inkling shape engines, no STRATA_NATIVE: the image runs on any x86-64 CPU with AVX2. The final stage is the
# lab's own: no model download (the weights are the model store's, mounted read-only), no key made on first
# start, a starter script that holds the settings to named variables, a health probe and no root.
# Both base images are pinned by the digest of their multi-architecture index.
ARG CUDA_IMAGE=nvidia/cuda:13.0.0-devel-ubuntu24.04@sha256:1e8ac7a54c184a1af8ef2167f28fa98281892a835c981ebcddb1fad04bdd452d
ARG RUNTIME_BASE=ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
ARG STRATA_TAG=v0.2.22
ARG STRATA_COMMIT=b28ca95e3e6847f2d5e317994f253b66716deeaa

# ---- 1. the source: the tag must resolve to the pinned commit, or the build stops
FROM ${CUDA_IMAGE} AS source
ARG STRATA_TAG
ARG STRATA_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    git init -q /src; cd /src; \
    git remote add origin https://github.com/Niko1221/Strata.git; \
    git fetch -q --depth 1 origin "refs/tags/${STRATA_TAG}:refs/tags/${STRATA_TAG}"; \
    got=$(git rev-parse "${STRATA_TAG}^{commit}"); \
    [ "$got" = "${STRATA_COMMIT}" ] || { echo "tag ${STRATA_TAG} is ${got}, the recipe pins ${STRATA_COMMIT}"; exit 1; }; \
    git checkout -q --detach "${STRATA_COMMIT}"; \
    rm -rf .git

# ---- 2. compile the engine for sm_80 and make its component package (tools/docker/Dockerfile.src, stage 1)
FROM ${CUDA_IMAGE} AS engine-build
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PATH=/venv/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates libgomp1 libatomic1 python3 python3-pip python3-venv unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY --from=source /src /src
ARG CUDA_ARCHITECTURES="80"
# The build tools are installed by hash (the wheels' sha256, taken from PyPI for cmake 4.4.3 and ninja 1.13.2); the upstream's
# runtime requirements are pinned by version only, are build-time only and ship in no image layer (the engine package is
# the binary and the libraries collect_libs.py names; the Terminal stage installs its own wheels by hash from the upstream's lock)
RUN python3 -m venv /venv \
 && printf '%s\n' \
      'cmake==4.4.3 --hash=sha256:bae3c4954623ec4d62e62c70443f0da7988b733111c2871fcc6a31ead5137e20' \
      'ninja==1.13.2 --hash=sha256:65a24341b5ac09fcadcc37082660be40a94174e51a937fabf6e2cae26225fa2c' > /tmp/build-tools.txt \
 && /venv/bin/pip install --no-cache-dir --require-hashes --no-deps --only-binary=:all: -r /tmp/build-tools.txt \
 && /venv/bin/pip install --no-cache-dir -r terminal/requirements.txt
RUN set -e; \
    real=""; for a in $(echo "$CUDA_ARCHITECTURES" | tr ';,' '  '); do real="$real;${a}-real"; done; real=${real#;}; \
    last=$(echo "$CUDA_ARCHITECTURES" | tr ';,' '  ' | awk '{print $NF}'); \
    /venv/bin/cmake -G Ninja -S engine -B build -DCMAKE_BUILD_TYPE=Release -DSTRATA_ENABLE_CUDA=ON -DSTRATA_BUILD_TESTS=OFF \
        -DSTRATA_EXPERIMENTAL_SM60=OFF -DSTRATA_BUILD_HY4=OFF -DSTRATA_BUILD_INKLING=OFF \
        -DSTRATA_NATIVE_EXPERTS=ON -DSTRATA_PORTABLE=ON -DSTRATA_Q6K_EXPERTS=ON \
        "-DCMAKE_CUDA_ARCHITECTURES=${real};${last}-virtual"; \
    . tools/packaging/engine_targets.sh; targets=$(engine_targets /venv/bin/cmake build); \
    /venv/bin/cmake --build build --target $targets -j "$(nproc)"
RUN set -e; \
    mkdir -p /stage /engine; \
    cp build/strata /stage/; \
    [ -f build/libstrata_kq.so ] && cp build/libstrata_kq.so /stage/ || true; \
    ver=$(sed -n 's/^[[:space:]]*project([^)]*VERSION[[:space:]]*\([0-9][0-9.]*\).*/\1/p' engine/CMakeLists.txt | head -1); \
    cudafull=$(nvcc --version | sed -n 's/.*release \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1); cudamajor=${cudafull%%.*}; \
    echo "{\"version\": \"$ver\", \"source\": \"docker build\", \"archs\": \"$CUDA_ARCHITECTURES\", \"cuda\": \"$cudafull\", \"portable\": true}" > /stage/BUILD.json; \
    python3 tools/packaging/collect_libs.py --binary build/strata --search /usr/local/cuda/lib64 --out /stage --also 'libcublasLt.so*'; \
    archs=""; for a in $(echo "$CUDA_ARCHITECTURES" | tr ';,' '  '); do archs="$archs --arch sm_$a"; done; \
    last=$(echo "$CUDA_ARCHITECTURES" | tr ';,' '  ' | awk '{print $NF}'); \
    python3 tools/packaging/package_engine.py --src /stage --backend cuda --version "$ver" --out /engine $archs --arch "compute_$last" \
        --min-driver nvidia=580.65 --variant cuda$cudamajor --platform linux-x86_64 --build-id "docker-source-${ver}-cuda${cudafull}" \
        --include SYSTEM-LIBS.txt --include 'libstrata_kq*'; \
    for d in /engine/*/; do \
      python3 tools/packaging/package_engine.py --verify "$d"; \
      python3 tools/packaging/binary_deps.py "$d"; \
    done

# ---- 3. the Terminal (the release archive, built here; tools/docker/Dockerfile.src, stage 2)
FROM ${RUNTIME_BASE} AS terminal
ARG STRATA_COMMIT
ENV STRATA_BUILD_COMMIT=${STRATA_COMMIT} DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=source /src /src/
RUN python3 /src/tools/packaging/package_terminal.py --out /out --cache /cache \
 && mkdir -p /opt/strata \
 && tar -xzf /out/strata-terminal-*-linux-x86_64.tar.gz -C /opt/strata \
 && mv /opt/strata/strata-terminal-* /opt/strata/terminal \
 && /opt/strata/terminal/bin/strata --version
RUN test -f /opt/strata/terminal/third_party/strata-gguf-py/gguf/__init__.py

# ---- 4. the runtime image (the lab's own)
FROM ${RUNTIME_BASE}
ARG STRATA_TAG
ARG STRATA_COMMIT
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends tini ca-certificates libgomp1 libatomic1 libnuma1 zlib1g \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
COPY --from=terminal /opt/strata/terminal /opt/strata/terminal
COPY --from=engine-build /engine/ /opt/strata/components/engine/
COPY roles/strata/files/image/entrypoint.sh roles/strata/files/image/healthcheck.py /opt/strata/
RUN chmod 0755 /opt/strata/entrypoint.sh /opt/strata/healthcheck.py \
 && set -e; \
    for d in /opt/strata/components/engine/*/; do \
      miss=$(find "$d" -type f \( -name 'strata*' -o -name '*.so' -o -name '*.so.*' \) ! -name '*.json' ! -name '*.txt' | while read -r f; do \
               head -c4 "$f" | grep -q ELF || continue; \
               LD_LIBRARY_PATH="$d" ldd "$f" 2>/dev/null | grep 'not found' | grep -v -E 'libcuda\.so|libnvidia|libnvcuvid' | sed "s|^|$(basename "$f"): |"; \
             done | sort -u); \
      if [ -n "$miss" ]; then echo "MISSING LIBRARIES in $d"; echo "$miss"; exit 1; fi; \
      echo "libraries of $d resolve inside this image"; \
    done
# /data is the one writable path (the module bind-mounts its own directory there); the id the container runs as is the module's
ENV STRATA_COMPONENTS_DIR=/opt/strata/components STRATA_INSTALL_DIR=/data/install XDG_STATE_HOME=/data/state \
    XDG_CONFIG_HOME=/data/config HOME=/data/home PORT=8080 LANG=C.UTF-8 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 \
    PYTHONDONTWRITEBYTECODE=1 STRATA_IN_DOCKER=1 HF_HUB_OFFLINE=1 \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility
LABEL org.opencontainers.image.title="Strata (sm_80)" \
      org.opencontainers.image.source="https://github.com/Niko1221/Strata" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${STRATA_TAG}" \
      org.opencontainers.image.revision="${STRATA_COMMIT}"
USER 61001:61001
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=8s --start-period=2h --retries=3 CMD ["/opt/strata/healthcheck.py"]
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/strata/entrypoint.sh"]
