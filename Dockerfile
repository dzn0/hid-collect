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
# Ghidra release to fetch when WITH_GHIDRA=1. Pin both the version and the
# dated build tag so the image is reproducible.
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_BUILD=20250219

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
      && apt-get install -y --no-install-recommends openjdk-21-jdk-headless unzip \
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
    PDT_GHIDRA_HOME=/opt/ghidra

WORKDIR /work
COPY . /work

# Fail the build early if the import graph is broken.
RUN python -m pipeline.collect --list >/dev/null && echo "pipeline imports OK"

ENTRYPOINT ["python", "-m"]
CMD ["pipeline.collect", "--list"]
