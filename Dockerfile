# syntax=docker/dockerfile:1
#
# hid-collect — collector + triage for Windows kernel drivers shipped with HID
# peripherals, pulled from touslesdrivers.com. Collects, extracts and
# content-addresses .sys files, analyses them statically (PE, imports, strings,
# signer cert class, KMDF/device surface), gates them by policy (pipeline.triage)
# and — optionally — follows DriverEntry with Ghidra headless (pipeline.disasm).
#
#   docker build -t hid-collect:latest .
#   docker compose run --rm collect
#
# Stdlib-only Python; runtime deps are 7-Zip (archive + installer extraction),
# curl (fallback downloader) and osslsigncode (signature verification). Ghidra +
# JDK and Playwright + Chromium are optional, gated by WITH_GHIDRA / WITH_PLAYWRIGHT.

FROM python:3.13-slim-bookworm

ARG WITH_PLAYWRIGHT=0
ARG WITH_GHIDRA=0
# Ghidra release to fetch when WITH_GHIDRA=1. Pin the version + dated build tag
# so the image is reproducible. Ghidra 11.x needs a JDK 21; Debian bookworm has
# no openjdk-21 package, so we fetch the Temurin 21 tarball (Ghidra's own
# recommended JDK) rather than apt. JDK_TAG is the release tag, JDK_FILE the
# filename's version form (same version, '+' vs '_').
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_BUILD=20250219
ARG JDK_TAG=21.0.5+11
ARG JDK_FILE=21.0.5_11

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        p7zip-full curl ca-certificates osslsigncode \
 && rm -rf /var/lib/apt/lists/*

# Playwright + Chromium: optional, controlled by WITH_PLAYWRIGHT=1 at build time.
# Needed only when driving the msupdate-catalog paginator through a real browser
# (PDT_MSC_MAX_PAGES > 1). Default off keeps the image lean (~130MB vs ~1GB).
# `playwright install --with-deps chromium` grabs ~190MB of browser plus a bunch
# of apt libs (libxkbcommon, libnss3, libdrm, mesa, fonts); pip install adds the
# Python module.
RUN if [ "$WITH_PLAYWRIGHT" = "1" ]; then \
      pip install --no-cache-dir "playwright>=1.47" \
      && playwright install --with-deps chromium \
      && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# Ghidra + JDK: optional, controlled by WITH_GHIDRA=1 at build time. Needed only
# for the disassembly stage (`pipeline.disasm`), which follows DriverEntry to
# prove mouse-injection / symlink reachability. Default off keeps the image lean
# (~130MB); on, it adds a headless JDK (~340MB) + Ghidra (~500MB unpacked).
RUN if [ "$WITH_GHIDRA" = "1" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends unzip \
      && arch="$(dpkg --print-architecture)" \
      && case "$arch" in amd64) ja=x64;; arm64) ja=aarch64;; *) ja="$arch";; esac \
      && jdk_tag="$(printf '%s' "$JDK_TAG" | sed 's/+/%2B/')" \
      && curl -fsSL "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${jdk_tag}/OpenJDK21U-jdk_${ja}_linux_hotspot_${JDK_FILE}.tar.gz" -o /tmp/jdk.tgz \
      && mkdir -p /opt/jdk && tar -xzf /tmp/jdk.tgz -C /opt/jdk --strip-components=1 && rm /tmp/jdk.tgz \
      && url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" \
      && curl -fsSL "$url" -o /tmp/ghidra.zip \
      && unzip -q /tmp/ghidra.zip -d /opt \
      && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
      && rm /tmp/ghidra.zip \
      && apt-get purge -y unzip && apt-get autoremove -y \
      && rm -rf /var/lib/apt/lists/*; \
    fi

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PDT_GHIDRA_HOME=/opt/ghidra \
    JAVA_HOME=/opt/jdk \
    PATH=/opt/jdk/bin:$PATH

WORKDIR /work
COPY . /work

# Fail the build early if the import graph is broken.
RUN python -m pipeline.collect --list >/dev/null && echo "pipeline imports OK"

ENTRYPOINT ["python", "-m"]
CMD ["pipeline.collect", "--list"]
