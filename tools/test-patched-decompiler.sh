#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ghidra_dir="${GHIDRA_INSTALL_DIR:?GHIDRA_INSTALL_DIR must point to patched Ghidra}"
headless="${ghidra_dir}/support/analyzeHeadless"
properties_file="${ghidra_dir}/Ghidra/application.properties"

if [[ ! -x "${headless}" || ! -f "${properties_file}" ]]; then
	printf 'Patched Ghidra installation not found: %s\n' "${ghidra_dir}" >&2
	exit 1
fi

property() {
	local key="$1"
	awk -F= -v key="${key}" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
		"${properties_file}"
}

ghidra_version="$(property application.version)"
ghidra_release="$(property application.release.name)"
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

test_root="$(mktemp -d)"
cleanup() {
	if [[ "${KEEP_TEST_ROOT:-0}" == 1 ]]; then
		printf 'Preserved test directory: %s\n' "${test_root}" >&2
	else
		rm -rf -- "${test_root}"
	fi
}
trap cleanup EXIT

test_home="${test_root}/home"
config_dir="${test_root}/config"
settings_root="${config_dir}/$(id -un)-ghidra"
extension_dir="${settings_root}/ghidra_${ghidra_version}_${ghidra_release}/Extensions"
mkdir -p "${extension_dir}"
unzip -q "${archive}" -d "${extension_dir}"

headless_log="${test_root}/headless.log"
set +e
HOME="${test_home}" XDG_CONFIG_HOME="${config_dir}" "${headless}" \
	"${test_root}" C166FarPointerDecompilerTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:LE:16:tasking-classic-large \
	-cspec tasking-classic-large \
	-noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166FarPointerDecompilerTest.java \
	-postScript C166IndirectReturnDecompilerTest.java \
	-deleteProject 2>&1 | tee "${headless_log}"
headless_status=${PIPESTATUS[0]}
set -e

if (( headless_status != 0 )) ||
	grep -Eq 'REPORT SCRIPT ERROR|Abort due to Headless analyzer error' "${headless_log}"; then
	printf 'Patched decompiler regression test failed.\n' >&2
	exit 1
fi

non_c166_log="${test_root}/non-c166-headless.log"
set +e
HOME="${test_home}" XDG_CONFIG_HOME="${config_dir}" "${headless}" \
	"${test_root}" NonC166AutoStructureControlTest \
	-import "${project_dir}/extension.properties" \
	-processor x86:LE:64:default \
	-cspec gcc \
	-noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript NonC166AutoStructureControlTest.java \
	-deleteProject 2>&1 | tee "${non_c166_log}"
non_c166_status=${PIPESTATUS[0]}
set -e

if (( non_c166_status != 0 )) ||
	grep -Eq 'REPORT SCRIPT ERROR|Abort due to Headless analyzer error' "${non_c166_log}"; then
	printf 'x86 shared-core control failed.\n' >&2
	exit 1
fi

arm_log="${test_root}/arm-headless.log"
set +e
HOME="${test_home}" XDG_CONFIG_HOME="${config_dir}" "${headless}" \
	"${test_root}" NonC166ArmAutoStructureControlTest \
	-import "${project_dir}/extension.properties" \
	-processor ARM:LE:32:v8 \
	-cspec default \
	-noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript NonC166AutoStructureControlTest.java \
	-deleteProject 2>&1 | tee "${arm_log}"
arm_status=${PIPESTATUS[0]}
set -e

if (( arm_status != 0 )) ||
	grep -Eq 'REPORT SCRIPT ERROR|Abort due to Headless analyzer error' "${arm_log}"; then
	printf 'ARM shared-core control failed.\n' >&2
	exit 1
fi
