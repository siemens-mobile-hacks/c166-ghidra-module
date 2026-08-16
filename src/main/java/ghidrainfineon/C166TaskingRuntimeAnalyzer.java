package ghidrainfineon;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Identifies TASKING Classic floating-point runtime helpers whose user-stack,
 * arithmetic, or register-preservation effects are not expressible by the
 * ordinary C calling convention.
 *
 * Recognition deliberately uses exact implementation byte sequences at an
 * existing executable function entry.  It is independent of firmware
 * addresses and symbol names, while remaining too strict to annotate a
 * look-alike instruction sequence in the middle of a function.
 */
public class C166TaskingRuntimeAnalyzer extends AbstractAnalyzer {

	private static final String COMPILER_ID = "tasking-classic-large";
	private static final String DOUBLE_RUNTIME_CONVENTION =
		"__tasking_c166_double_runtime";
	private static final Map<String, byte[]> RUNTIME_HELPERS = runtimeHelpers();
	private static final byte[][] PRESERVING_RUNTIME_HELPERS = preservingRuntimeHelpers();

	public C166TaskingRuntimeAnalyzer() {
		super("C166 TASKING Runtime Helpers",
			"Models TASKING Classic double runtime data flow and register preservation.",
			AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguageID().getIdAsString().startsWith("C166:") &&
			COMPILER_ID.equals(
				program.getCompilerSpec().getCompilerSpecID().getIdAsString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Memory memory = program.getMemory();
		FunctionManager functionManager = program.getFunctionManager();
		boolean fullScan = set == null || set.isEmpty() || set.contains(memory);
		Iterator<Function> functions = fullScan
				? functionManager.getFunctions(true)
				: functionManager.getFunctionsOverlapping(set);

		int matched = 0;
		int conventions = 0;
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function function = functions.next();
			if (function.isExternal() || function.isThunk()) {
				continue;
			}
			MemoryBlock block = memory.getBlock(function.getEntryPoint());
			if (block == null || !block.isExecute()) {
				continue;
			}

			String fixup = matchingFixup(memory, function);
			if (fixup != null && function.getCallFixup() == null) {
				function.setCallFixup(fixup);
				matched++;
			}
			if (matchesAny(memory, function, PRESERVING_RUNTIME_HELPERS) &&
				mayAssignRuntimeConvention(function)) {
				try {
					function.setCallingConvention(DOUBLE_RUNTIME_CONVENTION);
					conventions++;
				}
				catch (InvalidInputException e) {
					log.appendException(e);
				}
			}
		}

		if (matched != 0 || conventions != 0) {
			report(program, "Applied " + matched + " precise runtime p-code model(s) and " +
				conventions + " ABI register-preservation model(s) to TASKING double " +
				"runtime helpers.");
		}
		return true;
	}

	private static String matchingFixup(Memory memory, Function function) {
		for (Map.Entry<String, byte[]> helper : RUNTIME_HELPERS.entrySet()) {
			byte[] expected = helper.getValue();
			byte[] actual = new byte[expected.length];
			try {
				if (memory.getBytes(function.getEntryPoint(), actual) != actual.length) {
					continue;
				}
			}
			catch (MemoryAccessException e) {
				continue;
			}
			if (Arrays.equals(expected, actual)) {
				return helper.getKey();
			}
		}
		return null;
	}

	private static boolean matchesAny(Memory memory, Function function, byte[][] signatures) {
		for (byte[] signature : signatures) {
			byte[] actual = new byte[signature.length];
			try {
				if (memory.getBytes(function.getEntryPoint(), actual) == actual.length &&
					Arrays.equals(signature, actual)) {
					return true;
				}
			}
			catch (MemoryAccessException e) {
				// Try the next known implementation signature.
			}
		}
		return false;
	}

	private static boolean mayAssignRuntimeConvention(Function function) {
		String convention = function.getCallingConventionName();
		return Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention);
	}

	private static Map<String, byte[]> runtimeHelpers() {
		Map<String, byte[]> helpers = new LinkedHashMap<>();
		helpers.put("c166_tasking_load8n", new byte[] {
			0x26, (byte) 0xf0, 0x08, 0x00, (byte) 0xf0, (byte) 0xa0,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xc8, (byte) 0xa4, 0x28, (byte) 0xa6,
			(byte) 0xdb, 0x00
		});
		helpers.put("c166_tasking_load8f", new byte[] {
			0x26, (byte) 0xf0, 0x08, 0x00, (byte) 0xf0, (byte) 0xa0,
			(byte) 0xf6, (byte) 0xf5, 0x00, (byte) 0xfe, (byte) 0xcc, 0x00,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xc8, (byte) 0xa4, 0x28, (byte) 0xa6,
			(byte) 0xdb, 0x00
		});
		helpers.put("c166_tasking_store8f", new byte[] {
			(byte) 0xf6, (byte) 0xf5, 0x00, (byte) 0xfe, (byte) 0xcc, 0x00,
			(byte) 0xd8, 0x4a, 0x08, (byte) 0xa2,
			(byte) 0xd8, 0x4a, 0x08, (byte) 0xa2,
			(byte) 0xd8, 0x4a, 0x08, (byte) 0xa2,
			(byte) 0xc8, 0x4a, (byte) 0xdb, 0x00
		});
		helpers.put("c166_tasking_store8n", new byte[] {
			(byte) 0xe8, 0x4a, 0x08, 0x42,
			(byte) 0xe8, 0x4a, 0x08, 0x42,
			(byte) 0xe8, 0x4a, 0x08, 0x42,
			(byte) 0xc8, 0x4a, (byte) 0xdb, 0x00
		});
		helpers.put("c166_tasking_cif28r", new byte[] {
			0x26, (byte) 0xf0, 0x08, 0x00, (byte) 0xf0, (byte) 0xa0,
			(byte) 0x88, 0x70, (byte) 0x88, (byte) 0x80, (byte) 0x88, (byte) 0x90,
			(byte) 0xf0, 0x74, 0x7c, (byte) 0xf7,
			(byte) 0xc4, 0x7a, 0x06, 0x00
		});
		helpers.put("c166_tasking_cfi82r",
			bytes("887088808890dac48c8346f1ff072de246f1ff038df35cb7"));
		helpers.put("c166_tasking_sbf8r",
			bytes("a82b3af2f2ffb82bdac4488346f2ff072dd646f1ff072de1"));
		helpers.put("c166_tasking_adf8r",
			bytes("dac4488346f2ff072dd646f1ff072de148202de948102de1"));
		helpers.put("c166_tasking_mlf8r",
			bytes("dac448837af4f41048202ddf46f2ff072dcc48102ddd46f1"));
		helpers.put("c166_tasking_dvf8r",
			bytes("dac448837af4f41048202dcd46f2ff072dc148102dd946f1"));
		helpers.put("c166_tasking_ngf8r", bytes("a82a3af2f2ffb82adb00"));
		helpers.put("c166_tasking_swap8r",
			bytes("a82bd8bab82a08a2a82bd8bab82a08a2a82bd8bab82a08a2"));
		return Map.copyOf(helpers);
	}

	private static byte[][] preservingRuntimeHelpers() {
		return new byte[][] {
			// __cmf8r: double comparison, result in R4.
			bytes("f01af02b98319852f043703566f3f07f2d1846f3f07f2d19"),
			// __sbf8r entry followed by its shared __adf8r implementation.
			bytes("a82b3af2f2ffb82bdac4488346f2ff072dd646f1ff072de1"),
			// __adf8r.
			bytes("dac4488346f2ff072dd646f1ff072de148202de948102de1"),
			// __mlf8r.
			bytes("dac448837af4f41048202ddf46f2ff072dcc48102ddd46f1"),
			// __dvf8r.
			bytes("dac448837af4f41048202dcd46f2ff072dc148102dd946f1"),
			// __ngf8r.
			bytes("a82a3af2f2ffb82adb00"),
			// Double operand exchange used by the expression runtime.
			bytes("a82bd8bab82a08a2a82bd8bab82a08a2a82bd8bab82a08a2"),
			// __cfi82r: double to signed int.
			bytes("887088808890dac48c8346f1ff072de246f1ff038df35cb7")
		};
	}

	private static byte[] bytes(String hex) {
		byte[] result = new byte[hex.length() / 2];
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return result;
	}

	private void report(Program program, String message) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		PluginTool tool = manager.getAnalysisTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				console.addMessage(getName(), message);
				return;
			}
		}
		Msg.info(this, getName() + "> " + message);
	}
}
