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

# Ghidra compiles a script directory as one OSGi bundle, but a source error can
# surface only as a misleading "class could not be found" at execution time.
# Compile every headless fixture explicitly first so CI reports the actual file
# and line responsible for a broken test bundle.
mapfile -d '' script_sources < <(
	find "${project_dir}/src/test/ghidra_scripts" -maxdepth 1 -type f -name '*.java' \
		-print0 | sort -z
)
mkdir -p "${test_root}/script-classes"
script_classpath="${project_dir}/build/classes/java/main:$({
	find "${ghidra_dir}/Ghidra" -type f -name '*.jar' -printf '%p:'
})"
javac -proc:none -cp "${script_classpath}" -d "${test_root}/script-classes" \
	"${script_sources[@]}"

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
	-postScript C166ScalarSignatureInferenceTest.java \
	-postScript C166IncrementalAnalysisTest.java \
	-postScript C166CodePointerInferenceTest.java \
	-postScript C166ReturnedLayoutAliasTest.java \
	-postScript C166FarPointerInferenceTest.java -deleteProject

run_headless C166DppAddressingTest \
	'C166 direct and switch DPP dataflow regressions passed.' \
	"${project_store}" C166DppAddressingTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:LE:16:tasking-classic-large \
	-cspec tasking-classic-large -noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166DppAddressingTest.java \
	-postScript C166SwitchRecoveryHeadlessTest.java -deleteProject

run_headless C166TypeInferencePerformanceTest \
	'TASKING type-inference performance work counts passed' \
	"${project_store}" C166TypeInferencePerformanceTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:LE:16:tasking-classic-large \
	-cspec tasking-classic-large -noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166TypeInferencePerformanceTest.java -deleteProject

run_headless C167CsTaskingClassicAbiTest \
	'TASKING far-pointer inference matrix passed' \
	"${project_store}" C167CsTaskingClassicAbiTest \
	-import "${project_dir}/extension.properties" \
	-processor C166:CS:LE:16:tasking-classic-large \
	-cspec tasking-classic-large -noanalysis \
	-scriptPath "${project_dir}/src/test/ghidra_scripts" \
	-postScript C166TaskingClassicAbiTest.java \
	-postScript C166ScalarSignatureInferenceTest.java \
	-postScript C166IncrementalAnalysisTest.java \
	-postScript C166CodePointerInferenceTest.java \
	-postScript C166ReturnedLayoutAliasTest.java \
	-postScript C166FarPointerInferenceTest.java -deleteProject
