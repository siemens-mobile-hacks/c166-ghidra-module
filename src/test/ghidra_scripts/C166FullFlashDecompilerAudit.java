// Headless-only audit helper. Writes a compact Markdown inventory of decompiler anomalies.
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

public class C166FullFlashDecompilerAudit extends GhidraScript {

	private static final int MAX_EXAMPLES = 80;
	private static final Pattern WARNING = Pattern.compile("/\\* WARNING: ([^\\r\\n]*?) \\*/");
	private static final Pattern POINTER_CONCAT = Pattern.compile(
		"\\((?:char|void|byte|ushort|uint|undefined\\d*|[A-Za-z_]\\w*)\\s*\\*\\)\\s*(?:CONCAT|ZEXT)\\w*\\(");
	private static final Pattern POINTER_SPLIT = Pattern.compile(
		"(?:PTR|DAT|UNK)_[0-9A-Fa-f]+\\._(?:0|2)_2_");
	private static final Pattern POINTER_EXTRAOUT = Pattern.compile(
		"\\([^\\r\\n;()]*\\*\\)\\s*(?:extraout_|unaff_|in_)[A-Za-z0-9_]*");
	private static final Pattern BAD_FLOW = Pattern.compile(
		"(?:halt_baddata|code_r0x|BADSPACEBASE|UNRECOVERED_JUMPTABLE)");

	private final Map<String, Integer> counts = new LinkedHashMap<>();
	private final Map<String, List<String>> examples = new LinkedHashMap<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1 || args.length > 3) {
			throw new IllegalArgumentException(
				"expected output Markdown path, optional limit, and optional start address");
		}
		int limit = args.length >= 2 ? Integer.parseInt(args[1]) : Integer.MAX_VALUE;
		long startAddress = args.length == 3 ? Long.decode(args[2]) : 0x200000L;
		boolean targeted = args.length == 3;
		long started = System.nanoTime();
		useRequestedDecompiler();
		int total = 0;
		int flashFunctions = 0;
		int completed = 0;
		int defaultNamed = 0;
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		if (!decompiler.openProgram(currentProgram)) {
			throw new IllegalStateException(decompiler.getLastMessage());
		}
		try {
			FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				monitor.checkCancelled();
				Function function = functions.next();
				if (function.isExternal()) {
					continue;
				}
				total++;
				long address = function.getEntryPoint().getOffset();
				if (address < startAddress || address > 0xffffff) {
					continue;
				}
				flashFunctions++;
				if (flashFunctions > limit) {
					break;
				}
				if (function.getName().startsWith("FUN_")) {
					defaultNamed++;
				}
				forceScalarPointersIfRequested(function);
				auditSignature(function, targeted);
				DecompileResults result = decompiler.decompileFunction(function, 15, monitor);
				if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
					record("decompile-failure", function,
						clean(result.getErrorMessage()));
					continue;
				}
				completed++;
				auditCode(function, result.getDecompiledFunction().getC());
				if ((flashFunctions % 1000) == 0) {
					println("AUDIT progress " + flashFunctions + " functions");
				}
			}
		}
		finally {
			decompiler.dispose();
		}

		StringBuilder report = new StringBuilder();
		report.append("# Raw M55 fullflash decompiler audit inventory\n\n");
		report.append("Generated from a clean Ghidra project; this is evidence for manual triage, not the final report.\n\n");
		report.append("- Program: `").append(currentProgram.getName()).append("`\n");
		report.append("- Language: `").append(currentProgram.getLanguageID()).append("`\n");
		report.append("- Compiler: `").append(currentProgram.getCompilerSpec().getCompilerSpecID()).append("`\n");
		report.append("- Non-external functions: ").append(total).append("\n");
		report.append("- Fullflash functions: ").append(flashFunctions).append("\n");
		report.append("- Successfully decompiled: ").append(completed).append("\n");
		report.append("- Default `FUN_` names: ").append(defaultNamed).append("\n");
		report.append("- Audit time: ").append((System.nanoTime() - started) / 1_000_000_000L).append(" s\n\n");
		report.append("## Categories\n\n");
		for (Map.Entry<String, Integer> entry : counts.entrySet()) {
			report.append("### ").append(entry.getKey()).append(" (").append(entry.getValue()).append(")\n\n");
			for (String example : examples.get(entry.getKey())) {
				report.append("- ").append(example).append("\n");
			}
			report.append("\n");
		}
		Files.writeString(Path.of(args[0]), report.toString(), StandardCharsets.UTF_8);
		println("AUDIT wrote " + args[0]);
	}

	private void forceScalarPointersIfRequested(Function function) throws Exception {
		if (System.getenv("C166_AUDIT_POINTERS_AS_U32") == null) {
			return;
		}
		List<Variable> replacements = new ArrayList<>();
		boolean changed = false;
		for (Parameter parameter : function.getParameters()) {
			DataType type = parameter.getFormalDataType();
			if (type instanceof Pointer && type.getLength() == 4) {
				type = new Undefined4DataType(currentProgram.getDataTypeManager());
				changed = true;
			}
			replacements.add(new ParameterImpl(parameter.getName(), type, currentProgram));
		}
		if (changed) {
			function.updateFunction(function.getCallingConventionName(), null, replacements,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		}
	}

	private void useRequestedDecompiler() throws Exception {
		String path = System.getenv("C166_TEST_DECOMPILER");
		if (path == null || path.isBlank()) {
			return;
		}
		Field executablePath = DecompileProcessFactory.class.getDeclaredField("exepath");
		executablePath.setAccessible(true);
		executablePath.set(null, path);
		println("AUDIT decompiler " + executablePath.get(null));
	}

	private void auditSignature(Function function, boolean targeted) {
		if (targeted) {
			StringBuilder detail = new StringBuilder(function.getPrototypeString(true, true));
			detail.append("; return=").append(function.getReturn().getVariableStorage());
			for (Parameter parameter : function.getParameters()) {
				detail.append("; ").append(parameter.getName()).append("=")
					.append(parameter.getVariableStorage());
			}
			detail.append("; convention=").append(function.getCallingConventionName())
				.append("; source=").append(function.getSignatureSource());
			record("target-signature", function, detail.toString());
		}
		DataType returnType = function.getReturnType();
		if (returnType instanceof Pointer && returnType.getLength() != 4) {
			record("non-4-byte-return-pointer", function, returnType.getDisplayName());
		}
		for (Parameter parameter : function.getParameters()) {
			DataType type = parameter.getFormalDataType();
			if (type instanceof Pointer && type.getLength() != 4) {
				record("non-4-byte-parameter-pointer", function,
					parameter.getName() + ": " + type.getDisplayName());
			}
			if (parameter.getName().contains("return_storage") ||
				parameter.getName().contains("__return")) {
				record("hidden-return-parameter", function,
					parameter.getName() + ": " + type.getDisplayName());
			}
		}
	}

	private void auditCode(Function function, String code) {
		Matcher warning = WARNING.matcher(code);
		while (warning.find()) {
			String text = clean(warning.group(1));
			String category;
			if (text.startsWith("Variable defined which should be unmapped")) {
				category = "warning-unmapped-variable";
			}
			else if (text.contains("bad instruction data") || text.contains("Could not recover jumptable")) {
				category = "warning-bad-control-flow";
			}
			else if (text.startsWith("Function:") && text.contains("replaced with injection")) {
				category = "warning-callfixup-injection";
			}
			else if (text.contains("overlap smaller symbols")) {
				category = "warning-overlapping-globals";
			}
			else {
				category = "warning-other";
			}
			record(category, function, text);
		}
		if (code.contains("__return_storage_ptr__")) {
			record("hidden-return-storage-in-code", function, firstLine(code));
		}
		if (POINTER_CONCAT.matcher(code).find()) {
			record("pointer-cast-from-concat-or-zext", function, matchingLine(code, POINTER_CONCAT));
		}
		if (POINTER_SPLIT.matcher(code).find()) {
			record("split-global-pointer", function, matchingLine(code, POINTER_SPLIT));
		}
		if (POINTER_EXTRAOUT.matcher(code).find()) {
			record("pointer-from-unaff-or-extraout", function, matchingLine(code, POINTER_EXTRAOUT));
		}
		if (BAD_FLOW.matcher(code).find()) {
			record("bad-flow-artifact", function, matchingLine(code, BAD_FLOW));
		}
		if (code.contains("PTR_") && code.contains(">> 0x10")) {
			record("global-pointer-manual-high-word", function, matchingLine(code,
				Pattern.compile("PTR_.*>> 0x10")));
		}
		if (code.contains("extraout_RH4") || code.contains("extraout_RL4")) {
			record("rh4-or-rl4-extraout-occurrence", function,
				code.contains("extraout_RH4") ? "extraout_RH4" : "extraout_RL4");
		}
	}

	private void record(String category, Function function, String detail) {
		counts.merge(category, 1, Integer::sum);
		List<String> list = examples.computeIfAbsent(category, ignored -> new ArrayList<>());
		if (list.size() < MAX_EXAMPLES) {
			list.add("`0x" + function.getEntryPoint() + "` `" + function.getName() + "`: " +
				(detail == null || detail.isBlank() ? "(no detail)" : detail));
		}
	}

	private String matchingLine(String code, Pattern pattern) {
		Matcher matcher = pattern.matcher(code);
		if (!matcher.find()) {
			return "";
		}
		int start = code.lastIndexOf('\n', matcher.start());
		int end = code.indexOf('\n', matcher.end());
		return clean(code.substring(start < 0 ? 0 : start + 1, end < 0 ? code.length() : end));
	}

	private String firstLine(String code) {
		int end = code.indexOf('\n');
		return clean(end < 0 ? code : code.substring(0, end));
	}

	private String clean(String value) {
		if (value == null) {
			return "";
		}
		return value.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
	}
}
