// Synthetic regression for direct long-memory operands with a live DPP write.
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.GetPagedOffset;
import ghidrainfineon.RegOffsetAddr;
import ghidrainfineon.SwitchLoad;

public class C166DppAddressingTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")), "wrong C166 ABI profile");

		MemoryBlock low = createMemoryBlock("misleading_low", toAddr(0x2cc),
			bytes(0x20, 0x54, 0x2c, 0x20), false);
		low.setWrite(true);
		MemoryBlock physical = createMemoryBlock("physical_globals", toAddr(0x2c2cc),
			bytes(0x00, 0x10, 0x02, 0x00), false);
		physical.setWrite(true);
		createData(toAddr(0x2c2cc), new PointerDataType(CharDataType.dataType,
			currentProgram.getDataTypeManager()));
		createLabel(toAddr(0x2c2cc), "g_path", true);
		MemoryBlock text = createMemoryBlock("text", toAddr(0x9000),
			bytes('a', 'l', 'p', 'h', 'a', 0), false);
		text.setWrite(false);
		createAsciiString(toAddr(0x9000));

		Function sink = function(0x5000, "sink", bytes(0xdb, 0x00));
		sink.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
		List<Variable> parameters = List.of(new ParameterImpl("path",
			new PointerDataType(CharDataType.dataType, currentProgram.getDataTypeManager()),
			currentProgram));
		sink.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

		Function caller = function(0x4000, "direct_dpp_global_pointer", bytes(
			0xe6, 0x00, 0x0b, 0x00, // mov DPP0,#0xb
			0xf2, 0xfc, 0xcc, 0x02, // mov R12,0x2cc -> [0x2c2cc]
			0xf2, 0xfd, 0xce, 0x02, // mov R13,0x2ce -> [0x2c2ce]
			0xda, 0x00, 0x00, 0x50, // calls sink
			0xdb, 0x00));

		// This is the stale state written by old C166AddressAnalyzer versions.
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("DPP0"),
			toAddr(0x4004), toAddr(0x400b), BigInteger.ZERO);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(caller, 30, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			println(code);
			check((code.contains("g_path") || code.contains("\"alpha\"")) &&
				!code.contains("0xb1420") && !code.contains("DAT_0002cc"),
				"live DPP0 did not select physical 0x2c2cc:\n" + code);
		}
		finally {
			decompiler.dispose();
		}

		checkSwitchLoadUsesLiveDpp();
		checkExtsOverridePrecedence();
		checkRegisterExtpKeepsFarPointerSemantics();
		checkImmediateExtpKeepsFullPage();

		println("C166 direct and switch DPP dataflow regressions passed.");
	}

	private void checkImmediateExtpKeepsFullPage() throws Exception {
		MemoryBlock lowPageTarget = createMemoryBlock("immediate_extp_low_target",
			toAddr(0x2a2f0), bytes(0x34, 0x12), false);
		lowPageTarget.setWrite(false);
		createData(toAddr(0x2a2f0), UnsignedShortDataType.dataType);
		createLabel(toAddr(0x2a2f0), "g_immediate_extp_low", true);
		MemoryBlock lowPageWrong = createMemoryBlock("immediate_extp_low_wrong",
			toAddr(0x0a2f0), bytes(0x78, 0x56), false);
		lowPageWrong.setWrite(false);
		createData(toAddr(0x0a2f0), UnsignedShortDataType.dataType);
		createLabel(toAddr(0x0a2f0), "wrong_immediate_extp_low", true);

		MemoryBlock highPageTarget = createMemoryBlock("immediate_extp_high_target",
			toAddr(0x581c58), bytes(0xbc, 0x9a), false);
		highPageTarget.setWrite(false);
		createData(toAddr(0x581c58), UnsignedShortDataType.dataType);
		createLabel(toAddr(0x581c58), "g_immediate_extp_high", true);
		MemoryBlock highPageWrong = createMemoryBlock("immediate_extp_high_wrong",
			toAddr(0x161c58), bytes(0xf0, 0xde), false);
		highPageWrong.setWrite(false);
		createData(toAddr(0x161c58), UnsignedShortDataType.dataType);
		createLabel(toAddr(0x161c58), "wrong_immediate_extp_high", true);

		checkImmediateExtpFunction(0x7200, 0x00a, 0x22f0,
			"g_immediate_extp_low", "wrong_immediate_extp_low");
		checkImmediateExtpFunction(0x7300, 0x160, 0x1c58,
			"g_immediate_extp_high", "wrong_immediate_extp_high");
	}

	private void checkImmediateExtpFunction(long entryOffset, int page, int offset,
			String expectedLabel, String wrongLabel) throws Exception {
		Function function = function(entryOffset, "immediate_extp_" +
			Integer.toHexString(page), bytes(
				0xe6, 0xf7, 0x00, 0x00,             // mov r7,#0
				0xd7, 0x40, page, page >> 8,       // extp #page,#1
				0xd4, 0x47, offset, offset >> 8,   // mov r4,[r7+#offset]
				0xdb, 0x00));                       // rets
		function.setReturnType(UnsignedShortDataType.dataType, SourceType.USER_DEFINED);

		Address load = toAddr(entryOffset + 8);
		BigInteger contextPage = currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("Extp"), load, false);
		check(contextPage != null && contextPage.longValue() == page,
			"fresh immediate EXTP #0x" + Integer.toHexString(page) +
				" decoded as context page " +
				(contextPage == null ? "null" : "0x" + contextPage.toString(16)));
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			println(code);
			check(code.contains(expectedLabel) && !code.contains(wrongLabel),
				"immediate EXTP #0x" + Integer.toHexString(page) +
					" did not resolve its full physical page:\n" + code);
		}
		finally {
			decompiler.dispose();
		}
	}

	private void checkRegisterExtpKeepsFarPointerSemantics() throws Exception {
		Address extpAddress = toAddr(0x7100);
		Address extsAddress = toAddr(0x7110);
		createMemoryBlock("register_ext_overrides", extpAddress, new byte[0x20], false);
		setContext(extpAddress, "ExtpEn", 1);
		setContext(extpAddress, "ExtpRegMode", 1);
		setContext(extpAddress, "ExtpReg", 7);
		setContext(extsAddress, "ExtsEn", 1);
		setContext(extsAddress, "ExtsRegMode", 1);
		setContext(extsAddress, "ExtsReg", 7);

		PcodeOp[] extp = registerOffsetPcode(extpAddress, 6, 0x2cc, 0x400);
		check(extp.length == 3 && extp[0].getOpcode() == PcodeOp.INT_ADD &&
			extp[1].getOpcode() == PcodeOp.INT_AND &&
			extp[1].getInput(1).isConstant() &&
			extp[1].getInput(1).getOffset() == 0x3fff &&
			extp[2].getOpcode() == PcodeOp.CALLOTHER &&
			extp[2].getInput(1).getAddress().equals(
				currentProgram.getRegister("r7").getAddress()),
			"register EXTP was lowered to raw page arithmetic instead of segment(page,offset)");
		for (PcodeOp operation : extp) {
			check(operation.getOpcode() != PcodeOp.INT_LEFT &&
				operation.getOpcode() != PcodeOp.INT_MULT,
				"register EXTP retained a raw page<<14 operation");
		}

		PcodeOp[] exts = registerOffsetPcode(extsAddress, 6, 0x2cc, 0x500);
		boolean shiftsBy16 = false;
		for (PcodeOp operation : exts) {
			check(operation.getOpcode() != PcodeOp.CALLOTHER,
				"register EXTS was incorrectly represented by the paged segmentop");
			if (operation.getOpcode() == PcodeOp.INT_LEFT &&
				operation.getInput(1).isConstant() &&
				operation.getInput(1).getOffset() == 16) {
				shiftsBy16 = true;
			}
		}
		check(shiftsBy16, "register EXTS lost its 16-bit segment arithmetic");
	}

	private PcodeOp[] registerOffsetPcode(Address address, int baseRegister,
			long offset, long uniqueOffset) throws Exception {
		SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();
		InjectContext context = new InjectContext();
		context.language = language;
		context.baseAddr = address;
		context.nextAddr = address.add(2);
		context.inputlist = new ArrayList<>();
		context.output = new ArrayList<>();
		Register base = currentProgram.getRegister("r" + baseRegister);
		context.inputlist.add(new Varnode(base.getAddress(), base.getMinimumByteSize()));
		context.inputlist.add(new Varnode(
			language.getAddressFactory().getConstantSpace().getAddress(offset), 2));
		context.output.add(new Varnode(
			language.getAddressFactory().getUniqueSpace().getAddress(uniqueOffset), 3));
		return new RegOffsetAddr("c166_reg_offset_addr", language, 0x12000)
			.getPcode(currentProgram, context);
	}

	private void setContext(Address address, String registerName, long value)
			throws Exception {
		currentProgram.getProgramContext().setValue(currentProgram.getRegister(registerName),
			address, address, BigInteger.valueOf(value));
	}

	private void checkExtsOverridePrecedence() throws Exception {
		Address address = toAddr(0x7000);
		createMemoryBlock("ext_override_precedence", address, bytes(0, 0), false);
		for (String name : List.of("ExtpEn", "ExtsEn")) {
			currentProgram.getProgramContext().setValue(currentProgram.getRegister(name),
				address, address, BigInteger.ONE);
		}
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("Extp"),
			address, address, BigInteger.valueOf(0x34));
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("Exts"),
			address, address, BigInteger.valueOf(0x12));
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("ExtpRegMode"),
			address, address, BigInteger.ZERO);
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("ExtsRegMode"),
			address, address, BigInteger.ZERO);

		SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();
		InjectContext context = new InjectContext();
		context.language = language;
		context.baseAddr = address;
		context.nextAddr = address.add(2);
		context.inputlist = new ArrayList<>();
		context.output = new ArrayList<>();
		context.inputlist.add(new Varnode(
			language.getAddressFactory().getConstantSpace().getAddress(0x9234), 2));
		context.output.add(new Varnode(
			language.getAddressFactory().getUniqueSpace().getAddress(0x300), 3));
		PcodeOp[] pcode = new GetPagedOffset("GetPagedOffset", language, 0x11000)
			.getPcode(currentProgram, context);
		check(pcode.length == 1 && pcode[0].getOpcode() == PcodeOp.COPY &&
			pcode[0].getInput(0).isConstant() &&
			pcode[0].getInput(0).getOffset() == 0x129234,
			"EXTS did not take precedence over stale simultaneous EXTP context");
	}

	private void checkSwitchLoadUsesLiveDpp() throws Exception {
		Function function = function(0x6000, "switch_live_dpp", bytes(
			0xe6, 0x01, 0x0b, 0x00, // mov DPP1,#0xb
			0xe6, 0xf4, 0x00, 0x00, // mov r4,#0
			0x06, 0xf4, 0x00, 0x40, // add r4,#0x4000 -> selects DPP1
			0xa8, 0x44,             // mov r4,[r4]
			0x9c, 0x04));            // jmpi cc_UC,[r4]
		Address loadAddress = toAddr(0x600c);
		check("mov".equalsIgnoreCase(
			currentProgram.getListing().getInstructionAt(loadAddress).getMnemonicString()),
			"switch-load fixture did not disassemble as mov");
		check("jmpi".equalsIgnoreCase(
			currentProgram.getListing().getInstructionAt(loadAddress.add(2)).getMnemonicString()),
			"switch-load fixture did not disassemble as jmpi");

		SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();
		Register r4 = currentProgram.getRegister("r4");
		Register dpp1 = currentProgram.getRegister("DPP1");
		InjectContext context = new InjectContext();
		context.language = language;
		context.baseAddr = loadAddress;
		context.nextAddr = loadAddress.add(2);
		context.inputlist = new ArrayList<>();
		context.output = new ArrayList<>();
		context.inputlist.add(new Varnode(r4.getAddress(), r4.getMinimumByteSize()));
		context.output.add(new Varnode(
			language.getAddressFactory().getUniqueSpace().getAddress(0x200), 2));
		PcodeOp[] pcode = new SwitchLoad("c166_switch_load", language, 0x10000)
			.getPcode(currentProgram, context);
		boolean usesLiveDpp1 = false;
		for (PcodeOp operation : pcode) {
			if (operation.getOpcode() != PcodeOp.CALLOTHER) {
				continue;
			}
			for (int i = 1; i < operation.getNumInputs(); i++) {
				if (operation.getInput(i).getAddress().equals(dpp1.getAddress())) {
					usesLiveDpp1 = true;
				}
			}
		}
		check(usesLiveDpp1,
			"switch-load p-code folded DPP1 instead of preserving its live register value");
		check(function.getBody().contains(loadAddress), "invalid switch-load fixture body");
	}

	private Function function(long offset, String name, byte[] code) throws Exception {
		Address entry = toAddr(offset);
		MemoryBlock block = createMemoryBlock(name, entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		function.setBody(new AddressSet(entry, entry.add(code.length - 1)));
		return function;
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
