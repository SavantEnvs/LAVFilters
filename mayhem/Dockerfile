# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form, PREFERRED) — builds ON TOP of the org C/C++ base
# image (ghcr.io/savantenvs/base). The base already provides debian + clang/llvm +
# libFuzzer/afl++ + the identities + the build-contract ENV, so this only adds the
# per-commit build (built on top of the prebuilt base, rather than building the toolchain in-image).
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

# The org base, pinned to a fixed DATE-tagged base (YYYYMMDD; shared by all integrations
# minted against it). Use the current dated tag; pin by digest in production: ...base@sha256:<digest>.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); do NOT bake it as an ENV — an
# empty value breaks clang ("must be a non-negative decimal integer") both here and for
# any in-image rebuild. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# To change it for a build (e.g. ASan-only, or add MSan): --build-arg SANITIZER_FLAGS="...".
# Declare it WITHOUT a default (no '='): an undefaulted ARG lets the base ENV flow through to
# build.sh when not passed, and an explicit --build-arg overrides it. (An empty default — `=` —
# would instead shadow the base ENV and silently wipe the sanitizers.)
ARG SANITIZER_FLAGS
# Coverage (optional, off by default): instrument the TEST build to measure how much of the project
# the suite exercises — --build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping".
# Empty by default (no effect on the normal oracle build); build.sh appends it to the test build only.
ARG COVERAGE_FLAGS=
# Build parallelism (optional). build.sh falls back to nproc when unset: --build-arg MAYHEM_JOBS=8
ARG MAYHEM_JOBS=

# If mayhem/build.sh needs EXTRA apt packages, install them as root before the build
# (re-pin to SOURCE_DATE_EPOCH first for reproducibility — repro-sources-list.sh ships
# in the base):
#   USER root
#   RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
#       apt-get update && apt-get install -yq --no-install-recommends <pkgs> \
#    && rm -rf /var/lib/apt/lists/*
#   USER mayhem

# LAV's FFmpeg fork (the `ffmpeg` submodule, pinned to the commit the submodule records), built
# once into /opt/toolchains/deps (SPEC §6.2 item 19): static, uninstrumented, -gdwarf-3, only the
# parts the LAVFilters parsers call (AC-3/DTS/MLP/VC-1 parser helpers, the bit reader, av_malloc).
# The full source stays in $d/src — the parsers include FFmpeg-internal headers (get_bits.h, ...).
# The CI checkout does not fetch submodules, so this is the only copy; build.sh reads it offline.
USER root
ARG FFMPEG_COMMIT=80af591ccd0fe1a80a32f054bbe5de2dafabace5
RUN d=/opt/toolchains/deps/ffmpeg-lav-80af591 && mkdir -p "$d/src" "$d/include/libavutil" "$d/lib" /tmp/ffbuild \
 && git -C "$d/src" init -q \
 && git -C "$d/src" fetch -q --depth 1 https://gitea.1f0.de/LAV/FFmpeg.git "${FFMPEG_COMMIT}" \
 && git -C "$d/src" checkout -q FETCH_HEAD \
 && test "$(git -C "$d/src" rev-parse HEAD)" = "${FFMPEG_COMMIT}" \
 && rm -rf "$d/src/.git" \
 && cd /tmp/ffbuild \
 && "$d/src/configure" --cc=clang --cxx=clang++ --disable-everything --disable-programs --disable-doc \
      --disable-x86asm --disable-autodetect --enable-static --disable-shared --disable-avdevice \
      --disable-avformat --disable-avfilter --disable-swscale --disable-swresample \
      --enable-parser=ac3,dca,vc1,mlp --extra-cflags="-g -gdwarf-3" --disable-stripping \
 && make -j"$(nproc)" libavutil/libavutil.a libavcodec/libavcodec.a \
 && cp libavcodec/libavcodec.a libavutil/libavutil.a "$d/lib/" \
 && cp config.h config_components.h "$d/include/" \
 && cp libavutil/avconfig.h libavutil/ffversion.h "$d/include/libavutil/" \
 && cd / && rm -rf /tmp/ffbuild && chmod -R a+rX,go-w "$d"
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git
# history) is copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Anything a Dockerfile step materializes into the tree (downloaded fixtures, generated headers,
# vendored deps) MUST be committed or (re)created by build.sh: rlenv's patch grader runs
# `git clean -ffdX` before every graded build, so a gitignored, untracked file is gone by then and
# every honest patch scores zero (SPEC §6.2 item 16; verify-repo.sh checks it).
#
# OPTIONAL compile-cache pre-fill (SPEC §6.2 item 18). Bases minted with /opt/mayhem/ccache/prefill
# run the build under rlenv's pinned ccache, so the patch grader's first (otherwise cold) rebuild is
# warm — this is what keeps large C/C++ targets inside the build time limit. Older bases fall back to
# the plain build; a missing or stale pre-fill only costs a cold cache. Never enable ccache in
# build.sh or via ENV/PATH, and keep the compiler resolving by name (CC=clang) or nothing is cached.
RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

# Run the project's functional tests at build time IF the repo ships them (mayhem/test.sh is
# optional — omit it only when the repo has no tests meaningful for RL). A failing suite fails the
# image build, so the commit image is guaranteed to build AND pass its own tests.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
