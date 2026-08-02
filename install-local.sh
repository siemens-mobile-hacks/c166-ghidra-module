#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ghidra_dir="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
properties_file="${ghidra_dir}/Ghidra/application.properties"

if [[ ! -f "${properties_file}" ]]; then
	printf 'Ghidra application properties not found: %s\n' "${properties_file}" >&2
	printf 'Set GHIDRA_INSTALL_DIR to the Ghidra installation directory.\n' >&2
	exit 1
fi

property() {
	local key="$1"
	awk -F= -v key="${key}" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
		"${properties_file}"
}

ghidra_version="$(property application.version)"
ghidra_release="$(property application.release.name)"

if [[ -z "${ghidra_version}" || -z "${ghidra_release}" ]]; then
	printf 'Unable to determine the Ghidra version from: %s\n' "${properties_file}" >&2
	exit 1
fi

config_base="${XDG_CONFIG_HOME:-${HOME}/.config}"
ghidra_user_dir="${GHIDRA_USER_DIR:-${config_base}/ghidra/ghidra_${ghidra_version}_${ghidra_release}}"
extension_dir="${ghidra_user_dir}/Extensions/c166-ghidra-module"
target_jar="${extension_dir}/lib/c166-ghidra-module.jar"

if [[ ! -f "${target_jar}" ]]; then
	printf 'Installed extension JAR not found: %s\n' "${target_jar}" >&2
	printf 'Install the extension once through Ghidra, or set GHIDRA_USER_DIR.\n' >&2
	exit 1
fi

GHIDRA_INSTALL_DIR="${ghidra_dir}" "${project_dir}/gradlew" -p "${project_dir}" buildExtension

archive="$({
	find "${project_dir}/dist" -maxdepth 1 -type f \
		-name "ghidra_${ghidra_version}_${ghidra_release}_*_c166-ghidra-module.zip" \
		-printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"

if [[ -z "${archive}" || ! -f "${archive}" ]]; then
	printf 'Build did not produce a matching extension archive.\n' >&2
	exit 1
fi

staging_dir="$(mktemp -d)"
cleanup() {
	rm -rf -- "${staging_dir}"
}
trap cleanup EXIT

unzip -q "${archive}" -d "${staging_dir}"
staged_extension="${staging_dir}/c166-ghidra-module"
staged_jar="${staged_extension}/lib/c166-ghidra-module.jar"

if [[ ! -f "${staged_jar}" ]]; then
	printf 'Archive does not contain the expected extension JAR: %s\n' "${archive}" >&2
	exit 1
fi

backup_root="${ghidra_user_dir}/ExtensionBackups"
mkdir -p "${backup_root}"
backup_dir="${backup_root}/c166-ghidra-module.$(date +%Y%m%d-%H%M%S)"
if [[ -e "${backup_dir}" ]]; then
	printf 'Backup path already exists: %s\n' "${backup_dir}" >&2
	exit 1
fi

mv -- "${extension_dir}" "${backup_dir}"
if ! mv -- "${staged_extension}" "${extension_dir}"; then
	mv -- "${backup_dir}" "${extension_dir}"
	printf 'Installation failed; restored the previous extension.\n' >&2
	exit 1
fi

printf 'Updated: %s\n' "${extension_dir}"
printf 'Backup:  %s\n' "${backup_dir}"
printf 'Restart Ghidra to load the new classes.\n'
