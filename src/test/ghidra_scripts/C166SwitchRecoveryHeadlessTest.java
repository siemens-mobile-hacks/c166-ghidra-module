// Synthetic regression for TASKING Classic bounded local jump tables.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidrainfineon.C166CallTargetAnalyzer;

public class C166SwitchRecoveryHeadlessTest extends GhidraScript {

	private static final long ENTRY = 0x7600;
	private static final long JMPI = 0x7612;
	private static final long TABLE = 0xb000;
	private static final long[] TARGETS = {
		0x7620, 0x7626, 0x762c, 0x7632, 0x7638
	};
	private static final long LOADED_ENTRY = 0x2e7700;
	private static final long LOADED_JMPI = 0x2e7718;
	private static final long LOADED_TABLE = 0x584fc0;
	private static final long[] LOADED_TARGETS = {
		0x2e7722, 0x2e7730, 0x2e7730, 0x2e7728, 0x2e7730
	};

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"wrong C166 ABI profile");

		MemoryBlock table = createMemoryBlock("bounded_switch_table", toAddr(TABLE),
			tableBytes(TARGETS), false);
		table.setRead(true);
		table.setWrite(false);
		byte[] loadedPageBytes = new byte[0xfca];
		put(loadedPageBytes, 0, 0x78, 0x20, 0x2e, 0x00);
		put(loadedPageBytes, 0xfc0, tableBytes(LOADED_TARGETS));
		MemoryBlock loadedTable = createMemoryBlock("loaded_switch_page",
			toAddr(0x584000), loadedPageBytes, false);
		loadedTable.setRead(true);
		loadedTable.setWrite(false);
		createData(toAddr(0x584000), new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager()));
		createLabel(toAddr(0x584000), "PTR_FUN_584000", true);

		byte[] code = new byte[0x44];
		put(code, 0x00,
			0x48, 0xc4,                         // cmp r12,#4
			0xea, 0xe0, 0x3e, 0x76,             // jmpa cc_UGT,0x763e
			0x5c, 0x1c,                         // shl r12,#1
			0x06, 0xfc, 0x00, 0x30,             // add r12,#0x3000
			0xd7, 0x40, 0x02, 0x00,             // extp #2,#1
			0xa8, 0xcc,                         // mov r12,[r12]
			0x9c, 0x0c);                        // jmpi cc_UC,[r12]
		for (int index = 0; index < TARGETS.length; index++) {
			int offset = (int) (TARGETS[index] - ENTRY);
			put(code, offset,
				0xe6, 0xf4, index, 0x00,           // mov r4,#index
				0xdb, 0x00);                       // rets
		}
		put(code, 0x3e,
			0xe6, 0xf4, 0xff, 0x00,             // default: mov r4,#0xff
			0xdb, 0x00);

		Address entry = toAddr(ENTRY);
		MemoryBlock text = createMemoryBlock("bounded_switch_code", entry, code, false);
		text.setExecute(true);
		check(disassemble(entry), "failed to disassemble switch entry");
		Function function = createFunction(entry, "bounded_local_switch");
		check(function != null, "failed to create switch function");
		function.setBody(new AddressSet(entry, entry.add(code.length - 1)));

		byte[] loadedCode = new byte[0x3c];
		put(loadedCode, 0x00,
			0xda, 0x2e, 0x80, 0x77,             // calls 0x2e7780
			0xa8, 0xc0,                         // mov r12,[r0]
			0x48, 0xc4,                         // cmp r12,#4
			0xea, 0xe0, 0x36, 0x77,             // jmpa cc_UGT,0x7736
			0x5c, 0x1c,                         // shl r12,#1
			0x06, 0xfc, 0xc0, 0x0f,             // add r12,#0xfc0
			0xd7, 0x40, 0x61, 0x01,             // extp #0x161,#1
			0xa8, 0xcc,                         // mov r12,[r12]
			0x9c, 0x0c);                        // jmpi cc_UC,[r12]
		put(loadedCode, 0x22,
			0xe6, 0xf4, 0x00, 0x00, 0xdb, 0x00); // case 0
		put(loadedCode, 0x28,
			0xe6, 0xf4, 0x03, 0x00, 0xdb, 0x00); // case 3
		put(loadedCode, 0x30,
			0xe6, 0xf4, 0x01, 0x00, 0xdb, 0x00); // cases 1,2,4
		put(loadedCode, 0x36,
			0xe6, 0xf4, 0xff, 0x00, 0xdb, 0x00); // default
		Address loadedEntry = toAddr(LOADED_ENTRY);
		MemoryBlock loadedText = createMemoryBlock("loaded_switch_code", loadedEntry,
			loadedCode, false);
		loadedText.setExecute(true);
		check(disassemble(loadedEntry), "failed to disassemble loaded-index switch entry");
		Function loadedFunction = createFunction(loadedEntry, "loaded_local_switch");
		check(loadedFunction != null, "failed to create loaded-index switch function");
		loadedFunction.setBody(new AddressSet(loadedEntry,
			loadedEntry.add(loadedCode.length - 1)));

		MemoryBlock helperText = createMemoryBlock("switch_helper", toAddr(0x2e7780),
			new byte[] { (byte) 0xdb, 0x00 }, false);
		helperText.setExecute(true);
		for (long target : TARGETS) {
			check(getInstructionAt(toAddr(target)) == null,
				"case target was unexpectedly disassembled before recovery");
		}
		for (long target : LOADED_TARGETS) {
			check(getInstructionAt(toAddr(target)) == null,
				"loaded-index case target was unexpectedly disassembled before recovery");
		}
		C166CallTargetAnalyzer analyzer = new C166CallTargetAnalyzer();
		MessageLog log = new MessageLog();
		AddressSet scope = new AddressSet(function.getBody());
		scope.add(loadedFunction.getBody());
		check(analyzer.added(currentProgram, scope, monitor, log),
			"switch recovery failed: " + log);

		for (int index = 0; index < TARGETS.length; index++) {
			Address target = toAddr(TARGETS[index]);
			check(getInstructionAt(target) != null,
				"case target was not disassembled: " + target);
			check(hasReference(toAddr(JMPI), target, RefType.COMPUTED_JUMP),
				"missing computed-jump reference to " + target);
			check(getFunctionAt(target) == null,
				"local switch target was incorrectly created as a function: " + target);
			check(getDataAt(toAddr(TABLE + index * 2L)) != null &&
				getDataAt(toAddr(TABLE + index * 2L)).getDataType()
					.isEquivalent(UnsignedShortDataType.dataType),
				"table entry was not defined as a 16-bit offset");
		}
		for (int index = 0; index < LOADED_TARGETS.length; index++) {
			Address target = toAddr(LOADED_TARGETS[index]);
			check(getInstructionAt(target) != null,
				"loaded-index case target was not disassembled: " + target);
			check(hasReference(toAddr(LOADED_JMPI), target, RefType.COMPUTED_JUMP),
				"missing loaded-index computed-jump reference to " + target);
			check(getFunctionAt(target) == null,
				"loaded-index switch target became a function: " + target);
			check(getDataAt(toAddr(LOADED_TABLE + index * 2L)) != null &&
				getDataAt(toAddr(LOADED_TABLE + index * 2L)).getDataType()
					.isEquivalent(UnsignedShortDataType.dataType),
				"loaded-index table entry was not defined as a 16-bit offset");
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			checkNumericSwitch(decompiler, function, TARGETS, true);
			checkNumericSwitch(decompiler, loadedFunction, LOADED_TARGETS, false);
		}
		finally {
			decompiler.dispose();
		}

		println("TASKING bounded local switch recovery passed.");
	}

	private void checkNumericSwitch(DecompInterface decompiler, Function function,
			long[] branchTargets, boolean requireEveryLabel) throws Exception {
		DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
		check(result.decompileCompleted(), result.getErrorMessage());
		String decompiled = result.getDecompiledFunction().getC();
		println(decompiled);
		String compact = decompiled.replaceAll("\\s+", "");
		check(decompiled.contains("switch") &&
			!decompiled.contains("Could not recover jumptable") &&
			!decompiled.contains("(*(code *)") &&
			!compact.contains("switch((uint3)") &&
			!compact.contains("PTR_FUN_"),
			"bounded JMPI still decompiled as an indirect call:\n" + decompiled);
		check(compact.contains("case0:") && compact.contains("case3:") &&
			(!requireEveryLabel || compact.contains("case1:") &&
				compact.contains("case2:") && compact.contains("case4:")) &&
			(requireEveryLabel || compact.contains("default:")),
			"switch is missing its expected numeric/default labels:\n" + decompiled);
		for (long target : branchTargets) {
			check(!compact.contains("case0x" + Long.toHexString(target) + ":"),
				"switch label is a branch destination instead of an index:\n" + decompiled);
		}
	}

	private boolean hasReference(Address from, Address to, RefType type) {
		for (Reference reference : getReferencesFrom(from)) {
			if (reference.getToAddress().equals(to) &&
				reference.getReferenceType().equals(type)) {
				return true;
			}
		}
		return false;
	}

	private byte[] tableBytes(long[] targets) {
		byte[] result = new byte[targets.length * 2];
		for (int index = 0; index < targets.length; index++) {
			result[index * 2] = (byte) targets[index];
			result[index * 2 + 1] = (byte) (targets[index] >> 8);
		}
		return result;
	}

	private void put(byte[] target, int offset, int... values) {
		for (int index = 0; index < values.length; index++) {
			target[offset + index] = (byte) values[index];
		}
	}

	private void put(byte[] target, int offset, byte[] values) {
		System.arraycopy(values, 0, target, offset, values.length);
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
