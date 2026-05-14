#!/usr/bin/env bash
# Idempotent host prep for low-memory EC2 instances (e.g. t3.medium).
# Ensures enough swap to survive Rust release builds and constrains host-side
# cargo to a safe job count. Safe to run on every deploy.
set -euo pipefail

SWAPFILE="${SWAPFILE:-/swapfile}"
SWAP_SIZE="${SWAP_SIZE:-4G}"
CARGO_JOBS="${CARGO_JOBS:-2}"

# When invoked under sudo, $HOME points to /root. We want the cargo
# config to land in the invoking user's home so the workflow (which
# runs as ec2-user over SSH) reads the same file.
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  TARGET_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
  TARGET_USER="${SUDO_USER}"
else
  TARGET_HOME="${HOME}"
  TARGET_USER="$(id -un)"
fi

echo "=== ec2-prepare-host: ensure swap (${SWAP_SIZE} at ${SWAPFILE}) ==="
if swapon --show=NAME --noheadings | grep -qx "${SWAPFILE}"; then
  echo "swap already active at ${SWAPFILE}"
else
  if [ ! -f "${SWAPFILE}" ]; then
    sudo fallocate -l "${SWAP_SIZE}" "${SWAPFILE}" || \
      sudo dd if=/dev/zero of="${SWAPFILE}" bs=1M count=$((${SWAP_SIZE%G} * 1024))
    sudo chmod 600 "${SWAPFILE}"
    sudo mkswap "${SWAPFILE}"
  fi
  sudo swapon "${SWAPFILE}"
  if ! grep -qE "^${SWAPFILE}\s" /etc/fstab; then
    echo "${SWAPFILE} none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
  fi
  echo "swap enabled at ${SWAPFILE}"
fi

echo "=== ec2-prepare-host: ensure ${TARGET_HOME}/.cargo/config.toml jobs=${CARGO_JOBS} ==="
mkdir -p "${TARGET_HOME}/.cargo"
CARGO_CFG="${TARGET_HOME}/.cargo/config.toml"
if [ ! -f "${CARGO_CFG}" ] || ! grep -qE '^\[build\]' "${CARGO_CFG}"; then
  cat >> "${CARGO_CFG}" <<EOF

[build]
jobs = ${CARGO_JOBS}
EOF
  echo "wrote [build] jobs=${CARGO_JOBS} to ${CARGO_CFG}"
  # If we're running under sudo, restore ownership so the invoking
  # user (and cargo running as that user) can read/write the config.
  if [ "${TARGET_USER}" != "$(id -un)" ]; then
    chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}/.cargo"
  fi
else
  echo "${CARGO_CFG} already has [build] section, leaving as-is"
fi

echo "=== ec2-prepare-host: memory snapshot ==="
free -h
