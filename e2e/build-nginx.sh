#!/usr/bin/env bash
#
# Build nginx from source with the websockify module added, so the e2e tests
# have a binary to run against. Prints the path to the built nginx binary.
#
# Usage:
#   NGINX_VERSION=1.25.3 ./build-nginx.sh [build-dir]
#
set -euo pipefail

NGINX_VERSION="${NGINX_VERSION:-1.25.3}"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${MODULE_DIR}/e2e/.nginx-build}"

SRC_DIR="${BUILD_DIR}/nginx-release-${NGINX_VERSION}"
PREFIX="${BUILD_DIR}/install"

mkdir -p "${BUILD_DIR}"

if [ ! -d "${SRC_DIR}" ]; then
    # nginx.org is the canonical source; GitHub mirror is used as a fallback.
    tarball="${BUILD_DIR}/nginx.tar.gz"
    if ! curl -fSL "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o "${tarball}" 2>/dev/null; then
        curl -fSL "https://codeload.github.com/nginx/nginx/tar.gz/refs/tags/release-${NGINX_VERSION}" -o "${tarball}"
    fi
    tar -xzf "${tarball}" -C "${BUILD_DIR}"
    # nginx.org tarballs unpack to nginx-<ver>; normalise both layouts.
    if [ -d "${BUILD_DIR}/nginx-${NGINX_VERSION}" ] && [ ! -d "${SRC_DIR}" ]; then
        mv "${BUILD_DIR}/nginx-${NGINX_VERSION}" "${SRC_DIR}"
    fi
fi

# The release-tag tarball ships configure under auto/, the dist tarball at root.
configure="./configure"
[ -x "${SRC_DIR}/configure" ] || configure="auto/configure"

cd "${SRC_DIR}"
"${configure}" \
    --prefix="${PREFIX}" \
    --add-module="${MODULE_DIR}" \
    --without-http_rewrite_module \
    --without-http_gzip_module >/dev/null
make -j"$(getconf _NPROCESSORS_ONLN)" >/dev/null
make install >/dev/null

echo "${PREFIX}/sbin/nginx"
