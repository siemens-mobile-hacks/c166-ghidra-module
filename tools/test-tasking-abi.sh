#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ghidra_dir="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
properties_file="${ghidra_dir}/Ghidra/application.properties"
headless="${ghidra_dir}/support/analyzeHeadless"

if [[ ! -f "${properties_file}" || ! -x "${headless}" ]]; then
	printf 'Ghidra installation not found: %s\n' "${ghidra_dir}" >&2
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
	rm -rf -- "${test_root}"
}
trap cleanup EXIT

test_home="${test_root}/home"
config_dir="${test_home}/.config"
# Ghidra prefixes the settings directory with the account name when the
# configured base lies outside java.io.tmpdir's owning home directory.
settings_root="${config_dir}/$(id -un)-ghidra"
extension_dir="${settings_root}/ghidra_${ghidra_version}_${ghidra_release}/Extensions"
project_store="${test_root}/projects"
mkdir -p "${extension_dir}" "${project_store}"
unzip -q "${archive}" -d "${extension_dir}"

run_headless() {
	local name="$1"
	local expected="$2"
	shift 2
	local output="${test_root}/${name}.log"
	local status

	set +e
	HOME="${test_home}" XDG_CONFIG_HOME="${config_dir}" "${headless}" "$@" \
		2>&1 | tee "${output}"
	status=${PIPESTATUS[0]}
	set -e

	if (( status != 0 )) ||
		grep -Eq 'REPORT SCRIPT ERROR|Abort due to Headless analyzer error' "${output}" ||
		! grep -Fq -- "${expected}" "${output}"; then
		printf '%s regression test failed.\n' "${name}" >&2
		return 1
	fi
}

run_headless C166TaskingClassicAbiTest \
	'TASKING far-pointer inference matrix passed' \
	"${project_store}" C166TaskingClassicAbiTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:LE:16:tasking-classic-large \
	-cspec tasking-classic-large -noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166TaskingClassicAbiTest.java \
	-postScript C166IncrementalAnalysisTest.java \
	-postScript C166CodePointerInferenceTest.java \
	-postScript C166FarPointerInferenceTest.java -deleteProject

run_headless C166LegacyAbiTest \
	'Legacy TASKING/Keil compiler spec compatibility tests passed' \
	"${project_store}" C166LegacyAbiTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:LE:16:default -cspec tasking -noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166TaskingClassicAbiTest.java -deleteProject

run_headless C167CsTaskingClassicAbiTest \
	'TASKING far-pointer inference matrix passed' \
	"${project_store}" C167CsTaskingClassicAbiTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:CS:LE:16:tasking-classic-large \
	-cspec tasking-classic-large -noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166TaskingClassicAbiTest.java \
	-postScript C166IncrementalAnalysisTest.java \
	-postScript C166CodePointerInferenceTest.java \
	-postScript C166FarPointerInferenceTest.java -deleteProject
