// Run against the patched Ghidra via tools/test-patched-decompiler.sh.
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.plugin.core.analysis.OperandReferenceAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166TaskingDataTypePhase;
import ghidrainfineon.C166VariadicCallPhase;

public class C166FarPointerDecompilerTest extends GhidraScript {

	private static final long STRCMP_ADDRESS = 0xbfa966;
	private static final long SNPRINTF_ADDRESS = 0xbfb34a;
	private static final long SPRINTF_ADDRESS = 0xbfb37e;

	private final List<Function> callers = new ArrayList<>();

	private DataType charPointer;
	private DataType word;

	@Override
	protected void run() throws Exception {
		useDevelopmentDecompilerIfRequested();
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"wrong compiler spec");

		charPointer = new PointerDataType(CharDataType.dataType,
			currentProgram.getDataTypeManager());
		word = new UnsignedShortDataType(currentProgram.getDataTypeManager());
		TypedefDataType canonicalSizeType = new TypedefDataType(
			new CategoryPath("/stddef.h"), "size_t",
			new UnsignedIntegerDataType(currentProgram.getDataTypeManager()),
			currentProgram.getDataTypeManager());
		currentProgram.getDataTypeManager().addDataType(canonicalSizeType,
			DataTypeConflictHandler.REPLACE_HANDLER);
		TypedefDataType importedSizeTypeDefinition = new TypedefDataType(
			new CategoryPath("/stddef.h"), "size_t.conflict",
			new UnsignedLongDataType(currentProgram.getDataTypeManager()),
			currentProgram.getDataTypeManager());
		DataType importedSizeType = currentProgram.getDataTypeManager().addDataType(
			importedSizeTypeDefinition, DataTypeConflictHandler.REPLACE_HANDLER);

		string(0x5000, "blabla");       // page 1, offset 0x1000
		string(0x9000, "alpha");        // page 2, offset 0x1000
		string(0xd000, "beta");         // page 3, offset 0x1000
		string(0x579208, "done");       // firmware-style page 0x15e, offset 0x1208
		string(0x57851d, "A:\\Internet\\pm_%d_%d.dat");
		string(0x5785b4, "A:\\Internet\\~pm_%d_%d.dat");
		string(0x5d4bfe, "class");
		string(0x5c5972,
			"%s\\%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x" +
			"%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x");
		data(0x12000, 0x100, true);      // writable sprintf destination
		createLabel(toAddr(0x12000), "sprintf_buffer", true);
		// FUN_747f44 loads logical offsets 0x196e/0x1970 after setting
		// DPP0=0x171, so the physical pointer object is at 0x5c596e.
		data(0x5c596e, 4, true);
		createData(toAddr(0x5c596e), charPointer);
		createLabel(toAddr(0x5c596e), "PTR_5c596e", true);
		data(0x37da6, 0x100, true);
		createLabel(toAddr(0x37da6), "snprintf_buffer", true);
		data(0x654e3b, 1, true);
		createLabel(toAddr(0x654e3b), "extp_register_target", true);
		string(0x56735e, "fixed-stack-fixture");
		string(0x5679ac, "third-stack-argument");
		data(0x56978d, 0x10, false);       // page 0x15a, offset 0x178d
		data(0x2cc, 4, true);
		currentProgram.getMemory().setBytes(toAddr(0x2cc),
			bytes(0x20, 0x54, 0x2c, 0x20)); // stale low-memory value -> false 0xb1420
		data(0x2c2cc, 4, true);
		currentProgram.getMemory().setBytes(toAddr(0x2c2cc),
			bytes(0x00, 0x10, 0x02, 0x00)); // far pointer to "alpha"
		createData(toAddr(0x2c2cc), charPointer);
		createLabel(toAddr(0x2c2cc), "g_path", true);
		data(0x5d4c04, 0x1000, true);
		currentProgram.getMemory().getBlock(toAddr(0x5d4c04)).setExecute(true);
		currentProgram.getMemory().setBytes(toAddr(0x5d4c04),
			bytes('h', 't', 't', 'p', ':', 0));
		currentProgram.getMemory().setBytes(toAddr(0x5d4c30), bytes('-', 'r', 0));
		currentProgram.getMemory().setBytes(toAddr(0x5d4c0a),
			bytes('f', 'i', 'l', 'e', ':', '/', '/', '%', 's', 0));
		createAsciiString(toAddr(0x5d4c0a));
		currentProgram.getMemory().setBytes(toAddr(0x5d4c1c),
			bytes('f', 'i', 'l', 'e', ':', '/', '/', '%', 's', 0));
		createAsciiString(toAddr(0x5d4c1c));

		Function takes0 = callee(0x2100, "takes_pair_0", VoidDataType.dataType,
			charPointer);
		Function directDppGlobalCaller = caller(0x2d00,
			"direct_dpp_global_pointer", bytes(
				0xe6, 0x00, 0x0b, 0x00, // mov DPP0,#0xb
				0xf2, 0xfc, 0xcc, 0x02, // mov R12,0x2cc -> [0x2c2cc]
				0xf2, 0xfd, 0xce, 0x02, // mov R13,0x2ce -> [0x2c2ce]
				0xda, 0x00, 0x00, 0x21, // calls takes_pair_0
				0xdb, 0x00));
		// Simulate an old analyzer run which persisted an incorrect DPP value at
		// the load sites.  P-code must follow the architectural MOV above instead
		// of folding this database cache into the instruction semantics.
		currentProgram.getProgramContext().setValue(currentProgram.getRegister("DPP0"),
			toAddr(0x2d04), toAddr(0x2d0b), java.math.BigInteger.ZERO);
		Function takes1 = callee(0x2110, "takes_pair_1", VoidDataType.dataType,
			word, charPointer);
		Function takes2 = callee(0x2120, "takes_pair_2", VoidDataType.dataType,
			word, word, charPointer);
		Function takesDword = callee(0x2130, "takes_dword", VoidDataType.dataType,
			new UnsignedLongDataType(currentProgram.getDataTypeManager()));
		Function returnsString = callee(0x2140, "returns_string", charPointer);
		setCode(returnsString, bytes(
			0xe6, 0xf4, 0x00, 0x10, // R4 = offset
			0xe6, 0xf5, 0x01, 0x00, // R5 = page
			0xdb, 0x00));
		callee(0x2160, "returns_context", charPointer);
		callee(0x2170, "feature_enabled", word, word);
		Function savedFarPointerField = caller(0x2180,
			"saved_far_pointer_field_after_call", bytes(
				0xda, 0x00, 0x60, 0x21,             // returns_context() -> R5:R4
				0xf0, 0x84,                         // R8 = OFFSET
				0xf0, 0x95,                         // R9 = PAGE
				0xe6, 0xfc, 0x14, 0x05,             // R12 = 0x514
				0xda, 0x00, 0x70, 0x21,             // feature_enabled(0x514)
				0xf0, 0xc8,                         // R12 = saved OFFSET
				0xf0, 0xd9,                         // R13 = saved PAGE
				0x06, 0xfc, 0xcc, 0x02,             // R12 += 0x2cc
				0xdc, 0x4d,                         // EXTP R13,#1
				0xa8, 0x4c,                         // R4 = [R12]
				0xdb, 0x00));
		savedFarPointerField.setReturnType(word, SourceType.USER_DEFINED);
		savedFarPointerField.updateFunction("__tasking_c166_classic", null, List.of(),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		FunctionDefinitionDataType callbackDefinition = new FunctionDefinitionDataType(
			"paged_pointer_negative_callback", currentProgram.getDataTypeManager());
		callbackDefinition.setReturnType(VoidDataType.dataType);
		DataType callbackPointer = new PointerDataType(callbackDefinition,
			currentProgram.getDataTypeManager());
		callee(0x21a0, "returns_callback", callbackPointer);
		Function callbackAsData = caller(0x21b0,
			"function_pointer_is_not_paged_data", bytes(
				0xda, 0x00, 0xa0, 0x21,
				0xf0, 0x84,
				0xf0, 0x95,
				0xf0, 0xc8,
				0xf0, 0xd9,
				0x06, 0xfc, 0xcc, 0x02,
				0xdc, 0x4d,
				0xa8, 0x4c,
				0xdb, 0x00));
		callbackAsData.setReturnType(word, SourceType.USER_DEFINED);
		callbackAsData.updateFunction("__tasking_c166_classic", null, List.of(),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		DataType dword = new UnsignedLongDataType(currentProgram.getDataTypeManager());
		callee(0x21d0, "returns_scalar_pair", dword);
		Function scalarAsData = caller(0x21e0,
			"scalar_pair_is_not_paged_pointer", bytes(
				0xda, 0x00, 0xd0, 0x21,
				0xf0, 0x84,
				0xf0, 0x95,
				0xf0, 0xc8,
				0xf0, 0xd9,
				0x06, 0xfc, 0xcc, 0x02,
				0xdc, 0x4d,
				0xa8, 0x4c,
				0xdb, 0x00));
		scalarAsData.setReturnType(word, SourceType.USER_DEFINED);
		scalarAsData.updateFunction("__tasking_c166_classic", null, List.of(),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function mismatchedFarPointerParts = functionWithCode(0x3500,
			"mismatched_far_pointer_parts", bytes(
				0x06, 0xfc, 0xcc, 0x02,             // first OFFSET += 0x2cc
				0xdc, 0x4f,                         // EXTP second PAGE,#1
				0xa8, 0x4c,                         // R4 = [first OFFSET]
				0xdb, 0x00));
		mismatchedFarPointerParts.setReturnType(word, SourceType.USER_DEFINED);
		mismatchedFarPointerParts.updateFunction("__tasking_c166_classic", null,
			List.of(
				new ParameterImpl("first", charPointer, currentProgram),
				new ParameterImpl("second", charPointer, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		DataType dwordPointer = new PointerDataType(
			new UnsignedLongDataType(currentProgram.getDataTypeManager()),
			currentProgram.getDataTypeManager());
		Function stackLength = callee(0xbfa81a, "stack_length", word, charPointer);
		Function consumeStackLength = callee(0x743766, "consume_stack_length",
			new ShortDataType(currentProgram.getDataTypeManager()),
			charPointer, dwordPointer, new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager()));
		Function stackAliasCaller = caller(0x2b80, "call_stack_length_by_address", hexBytes(
			"8890888026f04400f08ff09e88c088d0" +
			"dabf1aa8e00cc4401400c4c0160098d098c0" +
			"f0e066feff3ff2ff02fe88f088e0e6fe140000e0" +
			"66feff3ff2ff02feda74663706f00400" +
			"06f0440098809890db00"));
		List<Variable> stackAliasParameters = new ArrayList<>();
		stackAliasParameters.add(new ParameterImpl("input", charPointer, currentProgram));
		stackAliasCaller.setReturnType(
			new ShortDataType(currentProgram.getDataTypeManager()), SourceType.USER_DEFINED);
		stackAliasCaller.updateFunction("__tasking_c166_classic", null,
			stackAliasParameters, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
			SourceType.USER_DEFINED);

		Function strcmp = callee(STRCMP_ADDRESS, "strcmp",
			new ShortDataType(currentProgram.getDataTypeManager()),
			charPointer, charPointer);
		strcmp.setSignatureSource(SourceType.ANALYSIS);
		Function sprintf = callee(SPRINTF_ADDRESS, "sprintf",
			new ShortDataType(currentProgram.getDataTypeManager()),
			charPointer, charPointer);
		sprintf.setSignatureSource(SourceType.ANALYSIS);
		sprintf.setVarArgs(true);
		Function snprintf = callee(SNPRINTF_ADDRESS, "snprintf",
			new ShortDataType(currentProgram.getDataTypeManager()),
			charPointer, importedSizeType, charPointer);
		snprintf.setSignatureSource(SourceType.ANALYSIS);
		snprintf.setVarArgs(true);
		Function strstr = callee(0xbfa98e, "strstr", charPointer,
			charPointer, charPointer);
		strstr.setSignatureSource(SourceType.ANALYSIS);
		Function variadicWithStackParameter = callee(0x2150, "variadic_with_stack_parameter",
			VoidDataType.dataType, charPointer, charPointer, word);
		variadicWithStackParameter.setVarArgs(true);

		Function exactTarget = functionWithCode(0x258e12, "FUN_258e12", bytes(
			0xdc, 0x4d, 0xa8, 0x4c,             // R4 = *(R13:R12)
			0xdc, 0x4f, 0xa8, 0x5e, 0x00, 0x45, // R5 = *(R15:R14); add R4,R5
			0xd4, 0xc0, 0x00, 0x00,             // R12 = [SP+0]
			0xd4, 0xd0, 0x02, 0x00,             // R13 = [SP+2]
			0xdc, 0x4d, 0xa8, 0x5c, 0x00, 0x45,
			0xdb, 0x00));
		C166FarPointerPhase farPointerAnalyzer = new C166FarPointerPhase();
		check(farPointerAnalyzer.added(currentProgram, exactTarget.getBody(), monitor,
			new MessageLog()), "stack far-pointer analyzer failed");
		checkThreePointerSignature(exactTarget);
		setThreeCharPointers(exactTarget);
		Function extpRegisterConstant = functionWithCode(0x3400,
			"extp_register_constant_page", bytes(
				0xe6, 0xf6, 0x3b, 0x0e, // mov r6,#0x0e3b
				0xe6, 0xf7, 0x95, 0x01, // mov r7,#0x0195
				0xdc, 0x47,             // extp r7,#1
				0xb9, 0x26,             // movb [r6],RL1
				0xdb, 0x00));
		callee(0x9b7372, "auto_structure_tail", VoidDataType.dataType);
		Function autoStructureFarParameter = functionWithCode(0x2c00,
			"firmware_auto_structure_far_parameter", hexBytes(
				"dc5dc4ec4000c4fc4200fa9b7273"));
		List<Variable> autoStructureParameters = new ArrayList<>();
		autoStructureParameters.add(new ParameterImpl("object",
			new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager()), currentProgram));
		autoStructureParameters.add(new ParameterImpl("field_40", word, currentProgram));
		autoStructureParameters.add(new ParameterImpl("field_42", word, currentProgram));
		autoStructureFarParameter.setReturnType(VoidDataType.dataType,
			SourceType.USER_DEFINED);
		autoStructureFarParameter.updateFunction("__tasking_c166_classic", null,
			autoStructureParameters, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
			SourceType.USER_DEFINED);

		callers.add(caller(0x2200, "call_pair_0", bytes(
			0xe6, 0xfc, 0x00, 0x10, // R12 = offset 0x1000
			0xe6, 0xfd, 0x01, 0x00, // R13 = page 1
			0xda, 0x00, 0x00, 0x21, 0xdb, 0x00)));

		callers.add(caller(0x2300, "call_pair_1", bytes(
			0xe6, 0xfc, 0x07, 0x00, // leading word
			0xe6, 0xfd, 0x00, 0x10, // R13 = offset
			0xe6, 0xfe, 0x02, 0x00, // R14 = page
			0xda, 0x00, 0x10, 0x21, 0xdb, 0x00)));

		callers.add(caller(0x2400, "call_pair_2", bytes(
			0xe6, 0xfc, 0x01, 0x00,
			0xe6, 0xfd, 0x02, 0x00,
			0xe6, 0xfe, 0x00, 0x10, // R14 = offset
			0xe6, 0xff, 0x03, 0x00, // R15 = page
			0xda, 0x00, 0x20, 0x21, 0xdb, 0x00)));

		callers.add(caller(0x2500, "call_strcmp", bytes(
			0xe6, 0xfc, 0x00, 0x10, // "alpha"
			0xe6, 0xfd, 0x02, 0x00,
			0xe6, 0xfe, 0x00, 0x10, // "beta"
			0xe6, 0xff, 0x03, 0x00,
			0xda, 0xbf, 0x66, 0xa9, 0xdb, 0x00)));

		// Exact mixed stack/constant strcmp setup from real firmware fixture FUN_25d31c.
		// This used to print the second argument as the raw concatenation
		// 0x015a178d instead of its physical address 0x56978d.
		Function liveStrcmpCaller = caller(0x25d490, "call_strcmp_firmware_exact", bytes(
			0xe0, 0x3c,                         // mov r12, #3
			0x00, 0xc0,                         // add r12, r0
			0x66, 0xfc, 0xff, 0x3f,             // and r12, #0x3fff
			0xf2, 0xfd, 0x02, 0xfe,             // mov r13, DPP1
			0xe6, 0xfe, 0x8d, 0x17,             // mov r14, #0x178d
			0xe6, 0xff, 0x5a, 0x01,             // mov r15, #0x15a
			0xda, 0xbf, 0x66, 0xa9,             // calls strcmp
			0xdb, 0x00));

		Function sprintfCaller = caller(0x2600, "call_sprintf", bytes(
			0xe6, 0xfc, 0x00, 0x20, // writable 0x12000: page 4, offset 0x2000
			0xe6, 0xfd, 0x04, 0x00,
			0xe6, 0xfe, 0x08, 0x12, // "done": page 0x15e, offset 0x1208
			0xe6, 0xff, 0x5e, 0x01,
			0xda, 0xbf, 0x7e, 0xb3, 0xdb, 0x00));
		callers.add(sprintfCaller);

		Function strstrUndefinedTargetCaller = caller(0x2900,
			"call_strstr_undefined_target", bytes(
				0xe6, 0xfc, 0x00, 0x10, // "alpha"
				0xe6, 0xfd, 0x02, 0x00,
				0xe6, 0xfe, 0x04, 0x0c, // undefined writable "http:": page 0x175
				0xe6, 0xff, 0x75, 0x01,
				0xda, 0xbf, 0x8e, 0xa9,
				0xdb, 0x00));
		Function strstrShortTargetCaller = caller(0x2920,
			"call_strstr_short_target", bytes(
				0xe6, 0xfc, 0x00, 0x10, // "alpha"
				0xe6, 0xfd, 0x02, 0x00,
				0xe6, 0xfe, 0x30, 0x0c, // short "-r": page 0x175
				0xe6, 0xff, 0x75, 0x01,
				0xda, 0xbf, 0x8e, 0xa9,
				0xdb, 0x00));
		Function strcmpStringLiteralCaller = caller(0x2940,
			"call_strcmp_string_literal", bytes(
				0xe6, 0xfc, 0x00, 0x10, // "alpha"
				0xe6, 0xfd, 0x02, 0x00,
				0xe6, 0xfe, 0xfe, 0x0b, // "class": page 0x175
				0xe6, 0xff, 0x75, 0x01,
				0xda, 0xbf, 0x66, 0xa9,
				0xdb, 0x00));

		// Firmware-style variadic call: two optional words are pushed first,
		// while the fixed format far pointer remains in R15:R14.  This must not
		// collapse PAGE:OFFSET to the invalid raw address 0x015e051d.
		callers.add(caller(0x2650, "call_sprintf_with_varargs", bytes(
			0xe6, 0xf8, 0x11, 0x00,
			0xe6, 0xf9, 0x22, 0x00,
			0x88, 0x90,             // push R9
			0x88, 0x80,             // push R8
			0xe6, 0xfc, 0x00, 0x20, // writable 0x12000
			0xe6, 0xfd, 0x04, 0x00,
			0xe6, 0xfe, 0x1d, 0x05, // format: page 0x15e, offset 0x051d
			0xe6, 0xff, 0x5e, 0x01,
			0xda, 0xbf, 0x7e, 0xb3,
			0x06, 0xf0, 0x04, 0x00, // add R0, #4
			0xdb, 0x00)));

		// Exact call setup from real firmware fixture FUN_26cee4 at 0x26cf12.  Unlike the
		// compact fixture above, the destination is a stack far pointer formed
		// with the live DPP1 value.
		callers.add(caller(0x2680, "call_sprintf_firmware_exact", bytes(
			0x88, 0x90,                         // mov [-r0], r9
			0x88, 0x60,                         // mov [-r0], r6
			0xe6, 0xfc, 0x3a, 0x00,             // mov r12, #0x3a
			0x00, 0xc0,                         // add r12, r0
			0x66, 0xfc, 0xff, 0x3f,             // and r12, #0x3fff
			0xf2, 0xfd, 0x02, 0xfe,             // mov r13, DPP1
			0xe6, 0xfe, 0x1d, 0x05,
			0xe6, 0xff, 0x5e, 0x01,
			0xda, 0xbf, 0x7e, 0xb3,
			0x06, 0xf0, 0x04, 0x00,             // add r0, #4
			0xdb, 0x00)));

		callers.add(caller(0x26cee4, "firmware_FUN_26cee4_full", hexBytes(
			"889088808870886088e026f09000f09df06ce008e007e00cb8c0c4c002004860" +
			"eae0e0d0f2fdbea12d02da26f2d088908860e6fc3a0000c066fcff3ff2fd02fe" +
			"e6fe1d05e6ff5e01dabf7eb30804d4c0900048c12d0248c23d0ada26b4ced4c0" +
			"9e00d4d0a000204c305dea80e0d0d4c09000ea2008d0f0c6da26a6cc4049ea30" +
			"08d088908860e08c00c066fcff3ff2fd02fee6feb405e6ff5e01dabf7eb30804" +
			"e02c00c066fcff3ff2fd02fe88d088c0e08c00c066fcff3ff2fd02fee6fe6c00" +
			"00e066feff3ff2ff02fedaa4e215080448403d28e02c00c066fcff3ff2fd02fe" +
			"88d088c0e08c00c066fcff3ff2fd02fee6fe3a0000e066feff3ff2ff02fedaa4" +
			"ba14080448403d0ee04c00c066fcff3ff2fd02fee02e00e066feff3ff2ff02fe" +
			"daa45e16d4c090002d0548c12d0f48c22d330d38e6f70080e6fc8000b8c0f0c6" +
			"f0d9da26b4cc48403d2f0d2ce6f70280e6fc0001b8c0f0c6f0d9da26b4cc48" +
			"403d23d4809a00d4c09c00708c3d1bd4709e00d4d0a00088d08870d4e09e00" +
			"d4f0a00088f088e0f0c6f0d9e02eda26e4ce06f00800f0840d34e6f70181e6" +
			"f60001b8600d02e6f8ffff48803d1ee028008066f8ff3ff2f602fe88608880e6" +
			"fc3a0000c066fcff3ff2fd02fef0e7d4f00400daa492160804f6f4c2a146f4" +
			"ffff3d03e6f8ffff0d01e00848803d04f6f9bea1e0040d06f68ebea1f68fc2" +
			"a1e6f4ffff06f092009860987098809890db00")));

		// Same bit pattern as the first string pointer, but explicitly uint32_t.
		// The generic Ghidra patch must be type-driven and leave it numeric.
		callers.add(caller(0x2700, "call_dword", bytes(
			0xe6, 0xfc, 0x00, 0x10,
			0xe6, 0xfd, 0x01, 0x00,
			0xda, 0x00, 0x30, 0x21, 0xdb, 0x00)));

		callers.add(caller(0x2800, "call_pointer_return", bytes(
			0xda, 0x00, 0x40, 0x21, // returns_string()
			0xf0, 0xc4,             // mov R12,R4
			0xf0, 0xd5,             // mov R13,R5
			0xda, 0x00, 0x00, 0x21, // takes_pair_0(...)
			0xdb, 0x00)));

		// Exact instruction sequence supplied from firmware at 0x256c1e.
		callers.add(caller(0x256c1e, "call_three_far_pointers", bytes(
			0xe6, 0xfc, 0xac, 0x39,
			0xe6, 0xfd, 0x59, 0x01,
			0x88, 0xd0,
			0x88, 0xc0,
			0xc4, 0x80, 0x04, 0x00,
			0xc4, 0x90, 0x06, 0x00,
			0xf0, 0xc8,
			0xf0, 0xd9,
			0xe6, 0xfe, 0x5e, 0x33,
			0xe6, 0xff, 0x59, 0x01,
			0xda, 0x25, 0x12, 0x8e,
			0xdb, 0x00)));

		// Exact TASKING layout from real firmware fixture FUN_91f82a at 0x91fa22:
		// destination in R13:R12, 16-bit size in R14, then the fixed format
		// pointer and one far-pointer vararg on the stack.  The failed register
		// join for the format exhausts R15, so it must never appear as an extra
		// argument.
		Function snprintfExactCaller = caller(0x29a0, "call_snprintf_firmware_exact", bytes(
			0xda, 0x00, 0x40, 0x21,             // returns_string() -> R5:R4
			0xf0, 0x64,                         // mov R6, R4 (optional OFFSET)
			0xf0, 0x75,                         // mov R7, R5 (optional PAGE)
			0x88, 0x70,                         // mov [-R0], R7
			0x88, 0x60,                         // mov [-R0], R6
			0xe6, 0xf8, 0x0a, 0x0c,             // R8 = format OFFSET
			0xe6, 0xf9, 0x75, 0x01,             // R9 = format PAGE
			0x88, 0x90,                         // mov [-R0], R9
			0x88, 0x80,                         // mov [-R0], R8
			0xe6, 0xfc, 0xa6, 0x3d,             // R12 = destination OFFSET
			0xe6, 0xfd, 0x0d, 0x00,             // R13 = destination PAGE
			0xe6, 0xfe, 0xff, 0x00,             // R14 = size_t 0xff
			0xda, 0xbf, 0x4a, 0xb3,             // calls snprintf
			0x06, 0xf0, 0x08, 0x00,             // add R0, #8
			0xdb, 0x00));
		callers.add(snprintfExactCaller);

		Function snprintfParameterCaller = caller(0x29e0,
			"call_snprintf_pointer_parameter", bytes(
				0xf0, 0x8c,                         // mov R8, R12 (argument OFFSET)
				0xf0, 0x9d,                         // mov R9, R13 (argument PAGE)
				0x88, 0x90,                         // mov [-R0], R9
				0x88, 0x80,                         // mov [-R0], R8
				0xe6, 0xf6, 0x1c, 0x0c,             // R6 = format OFFSET
				0xe6, 0xf7, 0x75, 0x01,             // R7 = format PAGE
				0x88, 0x70,                         // mov [-R0], R7
				0x88, 0x60,                         // mov [-R0], R6
				0xe6, 0xfc, 0xa6, 0x3d,             // R12 = destination OFFSET
				0xe6, 0xfd, 0x0d, 0x00,             // R13 = destination PAGE
				0xe6, 0xfe, 0xff, 0x00,             // R14 = size_t 0xff
				0xda, 0xbf, 0x4a, 0xb3,             // calls snprintf
				0x06, 0xf0, 0x08, 0x00,             // add R0, #8
				0xdb, 0x00));
		snprintfParameterCaller.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING,
			null, List.of(new ParameterImpl("input", charPointer, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		callers.add(snprintfParameterCaller);

		// Same stack layout, but with no manually assigned caller prototype.  A
		// typed use first proves that R13:R12 is a char pointer, while an old
		// word-wise snprintf override exposes it as separate OFFSET/PAGE inputs.
		// This is the regression observed in real firmware fixture FUN_91f82a.
		Function snprintfInferredParameterCaller = caller(0x2a20,
			"call_snprintf_inferred_pointer_parameter", bytes(
				0xf0, 0x8c,                         // mov R8, R12 (saved OFFSET)
				0xf0, 0x9d,                         // mov R9, R13 (saved PAGE)
				0xda, 0x00, 0x00, 0x21,             // takes_pair_0(R13:R12)
				0x88, 0x90,                         // mov [-R0], R9
				0x88, 0x80,                         // mov [-R0], R8
				0xe6, 0xf6, 0x1c, 0x0c,             // R6 = format OFFSET
				0xe6, 0xf7, 0x75, 0x01,             // R7 = format PAGE
				0x88, 0x70,                         // mov [-R0], R7
				0x88, 0x60,                         // mov [-R0], R6
				0xe6, 0xfc, 0xa6, 0x3d,             // R12 = destination OFFSET
				0xe6, 0xfd, 0x0d, 0x00,             // R13 = destination PAGE
				0xe6, 0xfe, 0xff, 0x00,             // R14 = size_t 0xff
				0xda, 0xbf, 0x4a, 0xb3,             // calls snprintf
				0x06, 0xf0, 0x08, 0x00,             // add R0, #8
				0xdb, 0x00));
		callers.add(snprintfInferredParameterCaller);

		// No pre-existing call-site override: the analyzer must first expose the
		// two optional stack words from the post-call cleanup, then re-decompile
		// and join their char *16 OFFSET evidence with PAGE into one 32-bit char *.
		// This is the minimal standalone regression for real firmware fixture FUN_91f82a.
		Function snprintfFreshPointerCaller = caller(0x2a60,
			"call_snprintf_fresh_pointer", bytes(
				0xda, 0x00, 0x40, 0x21,             // returns_string() -> R5:R4
				0xf0, 0x64,                         // mov R6, R4 (optional OFFSET)
				0xf0, 0x75,                         // mov R7, R5 (optional PAGE)
				0x88, 0x70,                         // mov [-R0], R7
				0x88, 0x60,                         // mov [-R0], R6
				0xe6, 0xf8, 0x1c, 0x0c,             // R8 = format OFFSET
				0xe6, 0xf9, 0x75, 0x01,             // R9 = format PAGE
				0x88, 0x90,                         // mov [-R0], R9
				0x88, 0x80,                         // mov [-R0], R8
				0xe6, 0xfc, 0xa6, 0x3d,             // R12 = destination OFFSET
				0xe6, 0xfd, 0x0d, 0x00,             // R13 = destination PAGE
				0xe6, 0xfe, 0xff, 0x00,             // R14 = size_t 0xff
				0xda, 0xbf, 0x4a, 0xb3,             // calls snprintf
				0x06, 0xf0, 0x08, 0x00,             // add R0, #8
				0xdb, 0x00));
		callers.add(snprintfFreshPointerCaller);

		// Preserve an incoming far pointer in R7:R6 across an intervening call,
		// then push it next to one independent scalar.  A stale decompiler override
		// may coalesce all three optional words into undefined6; listing recovery
		// must rebuild them as pointer4 + scalar2.
		Function sprintfPointerScalarCaller = caller(0x2e00,
			"call_sprintf_saved_pointer_and_scalar", bytes(
				0xf0, 0x6c,                         // R6 = input OFFSET
				0xf0, 0x7d,                         // R7 = input PAGE
				0xf0, 0x8e,                         // R8 = scalar id
				0xda, 0x00, 0x00, 0x21,             // intervening call
				0x88, 0x80,                         // push scalar (rightmost)
				0x88, 0x70,                         // push pointer PAGE
				0x88, 0x60,                         // push pointer OFFSET
				0xe6, 0xfc, 0x00, 0x20,             // destination OFFSET
				0xe6, 0xfd, 0x04, 0x00,             // destination PAGE
				0xe6, 0xfe, 0x1d, 0x05,             // format OFFSET
				0xe6, 0xff, 0x5e, 0x01,             // format PAGE
				0xda, 0xbf, 0x7e, 0xb3,             // calls sprintf
				0x06, 0xf0, 0x06, 0x00,             // pop three optional words
				0xdb, 0x00));
		sprintfPointerScalarCaller.updateFunction("__tasking_c166_classic", null,
			List.of(
				new ParameterImpl("input", charPointer, currentProgram),
				new ParameterImpl("id", word, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
			SourceType.USER_DEFINED);
		callers.add(sprintfPointerScalarCaller);

		// A textually unique save after a conditional branch does not dominate the
		// call.  It must not be treated as the origin of an incoming pointer on the
		// branch path which bypasses both MOV instructions.
		Function conditionalSavedPointerCaller = caller(0x2f00,
			"conditional_saved_pointer_is_ambiguous", bytes(
				0x2d, 0x02,                         // branch directly to pushes
				0xf0, 0x6c,                         // fall-through-only R6 = OFFSET
				0xf0, 0x7d,                         // fall-through-only R7 = PAGE
				0x88, 0x70,
				0x88, 0x60,
				0xe6, 0xfc, 0x00, 0x20,
				0xe6, 0xfd, 0x04, 0x00,
				0xe6, 0xfe, 0x1d, 0x05,
				0xe6, 0xff, 0x5e, 0x01,
				0xda, 0xbf, 0x7e, 0xb3,
				0x06, 0xf0, 0x04, 0x00,
				0xdb, 0x00));
		conditionalSavedPointerCaller.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("input", charPointer, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
			SourceType.USER_DEFINED);
		callers.add(conditionalSavedPointerCaller);

		// Exact real firmware fixture instruction sequence from FUN_747f44 at 0x747f94 through
		// the cleanup after snprintf@0x748042. It pushes sixteen promoted bytes,
		// one typed global far-pointer vararg, and the fixed format far pointer.
		// This caller is deliberately omitted from callerBodies below: changing
		// only snprintf must still invalidate and rebuild every direct call site.
		Function snprintf747f44Caller = caller(0x2aa0,
			"firmware_FUN_747f44_snprintf", hexBytes(
				"f4200f00c02c88c0f4401000c04d88d0f4601100c06e88e0" +
				"f4801200c08f88f0f4a01300c0aa88a0f4201400c02b88b0" +
				"f4201500c02c88c0f4201600c02c88c0f4201700c02c88c0" +
				"f4201800c02c88c0f4201900c02c88c0f4201a00c02c88c0" +
				"f4201b00c02c88c0f4201c00c02c88c0f4201d00c02c88c0" +
				"f4201e00c02ce600710188c0f2fc6e19f2fd701988d088c0" +
				"e6fc7219e6fd710188d088c0e6fc3c0000c066fcff3f" +
				"f2fd02fee6fe2d00dabf4ab306f02800db00"));

		AddressSet callerBodies = new AddressSet();
		for (Function caller : callers) {
			callerBodies.add(caller.getBody());
		}
		callerBodies.add(liveStrcmpCaller.getBody());
		callerBodies.add(strstrUndefinedTargetCaller.getBody());
		callerBodies.add(strstrShortTargetCaller.getBody());
		callerBodies.add(strcmpStringLiteralCaller.getBody());
		C166TaskingDataTypePhase dataTypeAnalyzer = new C166TaskingDataTypePhase();
		check(dataTypeAnalyzer.added(currentProgram, callerBodies, monitor, new MessageLog()),
			"TASKING data-type analyzer failed");
		check(snprintf.getParameter(1).getFormalDataType().getLength() == 2 &&
			"/stddef.h/size_t".equals(
				snprintf.getParameter(1).getFormalDataType().getPathName()),
			"snprintf retained generic-clib size_t.conflict");
		FunctionDefinitionDataType unsafeSnprintfOverride = new FunctionDefinitionDataType(
			"old_unsafe_snprintf_override", currentProgram.getDataTypeManager());
		unsafeSnprintfOverride.setCallingConvention("__tasking_c166_classic_vararg_3");
		unsafeSnprintfOverride.setReturnType(
			new ShortDataType(currentProgram.getDataTypeManager()));
		unsafeSnprintfOverride.setArguments(
			new ParameterDefinitionImpl("s", charPointer, null),
			new ParameterDefinitionImpl("maxlen",
				new UnsignedLongDataType(currentProgram.getDataTypeManager()), null),
			new ParameterDefinitionImpl("format", charPointer, null),
			new ParameterDefinitionImpl("old_word_1", Undefined.getUndefinedDataType(2), null),
			new ParameterDefinitionImpl("old_word_2", Undefined.getUndefinedDataType(2), null),
			new ParameterDefinitionImpl("old_word_3", Undefined.getUndefinedDataType(2), null),
			new ParameterDefinitionImpl("old_word_4", Undefined.getUndefinedDataType(2), null));
		HighFunctionDBUtil.writeOverride(snprintfExactCaller, toAddr(0x29c4),
			unsafeSnprintfOverride);
		FunctionDefinitionDataType splitPointerOverride = new FunctionDefinitionDataType(
			"old_split_pointer_override", currentProgram.getDataTypeManager());
		splitPointerOverride.setCallingConvention("__tasking_c166_classic_vararg_3");
		splitPointerOverride.setReturnType(
			new ShortDataType(currentProgram.getDataTypeManager()));
		splitPointerOverride.setArguments(
			new ParameterDefinitionImpl("s", charPointer, null),
			new ParameterDefinitionImpl("maxlen",
				snprintf.getParameter(1).getFormalDataType(), null),
			new ParameterDefinitionImpl("format", charPointer, null),
			new ParameterDefinitionImpl("offset",
				snprintf.getParameter(1).getFormalDataType(), null),
			new ParameterDefinitionImpl("page", Undefined.getUndefinedDataType(2), null));
		HighFunctionDBUtil.writeOverride(snprintfParameterCaller, toAddr(0x2a00),
			splitPointerOverride);
		HighFunctionDBUtil.writeOverride(snprintfInferredParameterCaller, toAddr(0x2a44),
			splitPointerOverride);
		FunctionDefinitionDataType coalescedSprintfOverride =
			new FunctionDefinitionDataType("old_coalesced_sprintf_override",
				currentProgram.getDataTypeManager());
		coalescedSprintfOverride.setCallingConvention("__tasking_c166_classic_vararg_2");
		coalescedSprintfOverride.setReturnType(
			new ShortDataType(currentProgram.getDataTypeManager()));
		coalescedSprintfOverride.setArguments(
			new ParameterDefinitionImpl("s", charPointer, null),
			new ParameterDefinitionImpl("format", charPointer, null),
			new ParameterDefinitionImpl("coalesced_optional_words",
				Undefined.getUndefinedDataType(6), null));
		HighFunctionDBUtil.writeOverride(sprintfPointerScalarCaller, toAddr(0x2e20),
			coalescedSprintfOverride);
		FunctionDefinitionDataType ambiguousSavedPointerOverride =
			new FunctionDefinitionDataType("ambiguous_saved_pointer_override",
				currentProgram.getDataTypeManager());
		ambiguousSavedPointerOverride.setCallingConvention("__tasking_c166_classic_vararg_2");
		ambiguousSavedPointerOverride.setReturnType(
			new ShortDataType(currentProgram.getDataTypeManager()));
		ambiguousSavedPointerOverride.setArguments(
			new ParameterDefinitionImpl("s", charPointer, null),
			new ParameterDefinitionImpl("format", charPointer, null),
			new ParameterDefinitionImpl("unknown_optional_words",
				Undefined.getUndefinedDataType(4), null));
		HighFunctionDBUtil.writeOverride(conditionalSavedPointerCaller, toAddr(0x2f1a),
			ambiguousSavedPointerOverride);
		C166VariadicCallPhase variadicAnalyzer = new C166VariadicCallPhase();
		AddressSet snprintfOnly = new AddressSet(snprintf.getBody());
		check(variadicAnalyzer.added(currentProgram, snprintfOnly, monitor, new MessageLog()),
			"incremental variadic target analysis failed");
		FunctionDefinition snprintf747f44Override = prototypeOverride(
			snprintf747f44Caller, toAddr(0x2b4e));
		check(snprintf747f44Override != null,
			"changed snprintf target did not invalidate FUN_747f44 call site");
		ParameterDefinition[] snprintf747f44Arguments =
			snprintf747f44Override.getArguments();
		StringBuilder snprintf747f44Types = new StringBuilder();
		for (ParameterDefinition argument : snprintf747f44Arguments) {
			if (!snprintf747f44Types.isEmpty()) {
				snprintf747f44Types.append(", ");
			}
			snprintf747f44Types.append(argument.getDataType().getDisplayName());
		}
		check(snprintf747f44Arguments.length == 20,
			"FUN_747f44 override expected 3 fixed and 17 optional arguments, got " +
				snprintf747f44Arguments.length + ": " + snprintf747f44Types);
		check(snprintf747f44Arguments[0].getDataType() instanceof Pointer &&
			snprintf747f44Arguments[0].getDataType().getLength() == 4 &&
			snprintf747f44Arguments[1].getDataType().getLength() == 2 &&
			snprintf747f44Arguments[2].getDataType() instanceof Pointer &&
			snprintf747f44Arguments[2].getDataType().getLength() == 4 &&
			snprintf747f44Arguments[3].getDataType() instanceof Pointer &&
			snprintf747f44Arguments[3].getDataType().getLength() == 4,
			"FUN_747f44 fixed or pointer-vararg storage was split: " +
				snprintf747f44Types);
		for (int i = 4; i < snprintf747f44Arguments.length; i++) {
			check(snprintf747f44Arguments[i].getDataType().getLength() == 2,
				"FUN_747f44 promoted byte argument " + (i - 4) + " is not one word");
		}
		FunctionDefinitionDataType overjoinedScalarOverride = new FunctionDefinitionDataType(
			"old_overjoined_scalar_override", currentProgram.getDataTypeManager());
		overjoinedScalarOverride.setCallingConvention("__tasking_c166_classic_vararg_3");
		overjoinedScalarOverride.setReturnType(
			new ShortDataType(currentProgram.getDataTypeManager()));
		List<ParameterDefinition> overjoinedArguments = new ArrayList<>();
		overjoinedArguments.add(new ParameterDefinitionImpl("s", charPointer, null));
		overjoinedArguments.add(new ParameterDefinitionImpl("maxlen",
			snprintf.getParameter(1).getFormalDataType(), null));
		overjoinedArguments.add(new ParameterDefinitionImpl("format", charPointer, null));
		overjoinedArguments.add(new ParameterDefinitionImpl("real_pointer", charPointer, null));
		overjoinedArguments.add(new ParameterDefinitionImpl("false_pointer_1", charPointer, null));
		overjoinedArguments.add(new ParameterDefinitionImpl("false_pointer_2", charPointer, null));
		for (int i = 0; i < 12; i++) {
			overjoinedArguments.add(new ParameterDefinitionImpl("word_" + i,
				Undefined.getUndefinedDataType(2), null));
		}
		overjoinedScalarOverride.setArguments(
			overjoinedArguments.toArray(ParameterDefinition[]::new));
		check(deletePrototypeOverride(snprintf747f44Caller, toAddr(0x2b4e)),
			"failed to replace FUN_747f44 override with stale scalar fixture");
		HighFunctionDBUtil.writeOverride(snprintf747f44Caller, toAddr(0x2b4e),
			overjoinedScalarOverride);
		check(variadicAnalyzer.added(currentProgram, snprintf747f44Caller.getBody(), monitor,
			new MessageLog()), "overjoined scalar override repair failed");
		ParameterDefinition[] normalized747f44Arguments = prototypeOverride(
			snprintf747f44Caller, toAddr(0x2b4e)).getArguments();
		check(normalized747f44Arguments.length == 20,
			"overjoined scalar override was not expanded back to 20 arguments");
		check(normalized747f44Arguments[3].getDataType() instanceof Pointer,
			"real pointer was split while normalizing scalar varargs");
		for (int i = 4; i < normalized747f44Arguments.length; i++) {
			check(normalized747f44Arguments[i].getDataType().getLength() == 2,
				"normalized promoted byte argument " + (i - 4) + " is not one word");
		}
		FunctionDefinition freshOverride = prototypeOverride(
			snprintfFreshPointerCaller, toAddr(0x2a84));
		check(freshOverride != null && freshOverride.getArguments().length == 4 &&
			freshOverride.getArguments()[3].getDataType() instanceof Pointer &&
			freshOverride.getArguments()[3].getDataType().getLength() == 4,
			"fresh variadic call did not receive one 32-bit pointer override");
		DecompInterface firstPassDecompiler = new DecompInterface();
		firstPassDecompiler.toggleCCode(true);
		firstPassDecompiler.toggleSyntaxTree(true);
		check(firstPassDecompiler.openProgram(currentProgram),
			"failed to initialize first-pass decompiler: " +
				firstPassDecompiler.getLastMessage());
		try {
			String firstPassCode = decompile(firstPassDecompiler,
				snprintfFreshPointerCaller);
			String compactFirstPass = firstPassCode.replaceAll("\\s+", "");
			check((compactFirstPass.contains(
				"snprintf(&snprintf_buffer,0xff,s_file____s_5d4c1c,vararg_1)") ||
				compactFirstPass.contains(
					"snprintf(&snprintf_buffer,0xff,(char*)s_file____s_5d4c1c,vararg_1)") ||
				compactFirstPass.contains(
					"snprintf((char*)0x37da6,0xff,\"file://%s\",vararg_1)")) &&
				!firstPassCode.contains(">> 0x10"),
				"fresh variadic pointer was not joined in one analyzer run:\n" +
					firstPassCode);
		}
		finally {
			firstPassDecompiler.dispose();
		}
		check(variadicAnalyzer.added(currentProgram, callerBodies, monitor, new MessageLog()),
			"variadic call analyzer failed on its idempotence run");
		check(sprintf.hasVarArgs(), "variadic analyzer removed sprintf varargs");
		FunctionDefinition pointerScalarOverride = prototypeOverride(
			sprintfPointerScalarCaller, toAddr(0x2e20));
		check(pointerScalarOverride != null &&
			pointerScalarOverride.getArguments().length == 4 &&
			pointerScalarOverride.getArguments()[2].getDataType() instanceof Pointer &&
			pointerScalarOverride.getArguments()[2].getDataType().getLength() == 4 &&
			pointerScalarOverride.getArguments()[3].getDataType().getLength() == 2 &&
			!(pointerScalarOverride.getArguments()[3].getDataType() instanceof Pointer),
			"coalesced optional words were not rebuilt as pointer4 + scalar2");
		FunctionDefinition ambiguousSavedOverride = prototypeOverride(
			conditionalSavedPointerCaller, toAddr(0x2f1a));
		check(ambiguousSavedOverride != null,
			"conditional saved-pointer override disappeared");
		for (int i = 2; i < ambiguousSavedOverride.getArguments().length; i++) {
			check(!(ambiguousSavedOverride.getArguments()[i].getDataType() instanceof Pointer),
				"non-dominating saved registers were inferred as a pointer");
		}
		check(!sprintf.getCallingConventionName().startsWith(
			"__tasking_c166_classic_vararg_"),
			"variadic analyzer assigned its call-site convention to sprintf");
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram),
			"failed to initialize decompiler: " + decompiler.getLastMessage());
		try {
			String directDppCode = decompile(decompiler, directDppGlobalCaller);
			check((directDppCode.contains("g_path") || directDppCode.contains("\"alpha\"")) &&
				!directDppCode.contains("0xb1420") && !directDppCode.contains("DAT_0002cc"),
				"direct DPP load used stale ProgramContext instead of live DPP0:\n" +
					directDppCode);
			DecompileResults autoStructureResults = decompiler.decompileFunction(
				autoStructureFarParameter, 30, monitor);
			check(autoStructureResults.decompileCompleted() &&
				autoStructureResults.getHighFunction() != null,
				"failed to decompile C166 far-pointer auto-structure fixture: " +
					autoStructureResults.getErrorMessage());
			HighSymbol autoStructureSymbol = autoStructureResults.getHighFunction()
				.getLocalSymbolMap().getParamSymbol(0);
			HighVariable autoStructureVariable = autoStructureSymbol == null ? null :
				autoStructureSymbol.getHighVariable();
			Structure autoStructure = new FillOutStructureHelper(currentProgram, monitor)
				.processStructure(autoStructureVariable, autoStructureFarParameter,
					true, false, null);
			check(autoStructure != null && autoStructure.getLength() == 0x44 &&
				autoStructure.getComponentAt(0x40) != null &&
				autoStructure.getComponentAt(0x40).getLength() == 2 &&
				autoStructure.getComponentAt(0x42) != null &&
				autoStructure.getComponentAt(0x42).getLength() == 2,
				"C166 far-pointer auto-structure did not recover word fields at " +
					"offsets 0x40 and 0x42");

			String extpCode = decompile(decompiler, extpRegisterConstant);
			check(extpCode.contains("extp_register_target") &&
				!extpCode.contains("0x1950e3b"),
				"register EXTP was not normalized to page<<14 address 0x654e3b:\n" +
					extpCode);
			String savedFieldCode = decompile(decompiler, savedFarPointerField);
			String compactSavedField = savedFieldCode.replaceAll("\\s+", "");
			check(compactSavedField.contains("returns_context()") &&
				compactSavedField.contains("feature_enabled(0x514)") &&
				compactSavedField.contains("+0x2cc") &&
				!savedFieldCode.contains("0x4000") &&
				!savedFieldCode.contains("0x3fff") &&
				!savedFieldCode.contains(">> 0x10") &&
				!savedFieldCode.contains("CONCAT") &&
				!savedFieldCode.contains("segment(") &&
				!savedFieldCode.contains("Type propagation algorithm not settling"),
				"saved far-pointer field access was not reconstructed:\n" +
					savedFieldCode);
			String savedFieldSecondPass = decompile(decompiler, savedFarPointerField)
				.replaceAll("\\s+", "");
			check(compactSavedField.equals(savedFieldSecondPass),
				"saved far-pointer reconstruction was not idempotent");
			for (Function negative : List.of(callbackAsData, scalarAsData,
				mismatchedFarPointerParts)) {
				String negativeCode = decompile(decompiler, negative);
				check(negativeCode.contains("0x3fff"),
					negative.getName() +
						": unrelated halves were incorrectly folded into one data pointer:\n" +
						negativeCode);
			}
			String pair0 = decompile(decompiler, callers.get(0));
			checkCleanPointerCall(pair0, "\"blabla\"");

			String stackAliasCode = decompile(decompiler, stackAliasCaller);
			check(stackAliasCode.contains(" = stack_length(") &&
				!stackAliasCode.matches("(?s).*\\n\\s*stack_length\\([^;]+;.*") &&
				stackAliasCode.contains("consume_stack_length"),
				"stack local passed by address lost its initializing call result:\n" +
					stackAliasCode);

			String pair1 = decompile(decompiler, callers.get(1));
			checkCleanPointerCall(pair1, "\"alpha\"");

			String pair2 = decompile(decompiler, callers.get(2));
			checkCleanPointerCall(pair2, "\"beta\"");

			String strcmpCode = decompile(decompiler, callers.get(3));
			check(strcmpCode.contains("strcmp(\"alpha\",\"beta\")") ||
				strcmpCode.contains("strcmp(\"alpha\", \"beta\")"),
				"strcmp did not receive two string literals:\n" + strcmpCode);
			checkNoRepresentationArtifacts(strcmpCode);

			String liveStrcmpCode = decompile(decompiler, liveStrcmpCaller);
			check(liveStrcmpCode.contains("0x56978d") ||
				liveStrcmpCode.contains("UNK_56978d"),
				"firmware strcmp far constant was not converted to physical address:\n" +
					liveStrcmpCode);
			check(!liveStrcmpCode.contains("0x15a178d"),
				"firmware strcmp retained raw PAGE:OFFSET concatenation:\n" + liveStrcmpCode);

			String strstrUndefinedCode = decompile(decompiler, strstrUndefinedTargetCaller);
			check(strstrUndefinedCode.contains("(char *)0x5d4c04"),
				"undefined strstr target was not printed as a physical address:\n" +
					strstrUndefinedCode);
			check(!strstrUndefinedCode.contains("0x1750c04"),
				"undefined strstr target retained raw PAGE:OFFSET encoding:\n" +
					strstrUndefinedCode);
			checkPhysicalPointerToken(decompiler, strstrUndefinedTargetCaller, 0x5d4c04);
			String strstrShortCode = decompile(decompiler, strstrShortTargetCaller);
			check(strstrShortCode.contains("(char *)0x5d4c30"),
				"short strstr target was not printed as a physical address:\n" +
					strstrShortCode);
			checkPhysicalPointerToken(decompiler, strstrShortTargetCaller, 0x5d4c30);
			String strcmpLiteralCode = decompile(decompiler, strcmpStringLiteralCaller);
			check(strcmpLiteralCode.contains("strcmp(\"alpha\",\"class\")") ||
				strcmpLiteralCode.contains("strcmp(\"alpha\", \"class\")"),
				"strcmp string literal was not rendered:\n" + strcmpLiteralCode);
			checkStringPointerToken(decompiler, strcmpStringLiteralCaller, "\"class\"",
				0x5d4bfe);
			currentProgram.getReferenceManager().addMemoryReference(toAddr(0x2910),
				toAddr(0x5d4c04), RefType.DATA,
				SourceType.ANALYSIS, Reference.MNEMONIC);
			check(farPointerAnalyzer.added(currentProgram, callerBodies, monitor,
				new MessageLog()), "far-pointer reference analysis failed");
			Reference physicalReference = currentProgram.getReferenceManager().getReference(
				toAddr(0x290c), toAddr(0x5d4c04), Reference.MNEMONIC);
			check(physicalReference != null &&
				physicalReference.getReferenceType() == RefType.PARAM,
				"strstr far pointer did not create a physical PARAM xref on its setup");
			check(currentProgram.getReferenceManager().getReference(toAddr(0x2910),
				toAddr(0x5d4c04), Reference.MNEMONIC) == null,
				"strstr retained the legacy physical xref on the call");
			Reference shortReference = currentProgram.getReferenceManager().getReference(
				toAddr(0x292c), toAddr(0x5d4c30), Reference.MNEMONIC);
			check(shortReference != null &&
				shortReference.getReferenceType() == RefType.PARAM,
				"short strstr far pointer did not create a physical PARAM xref on its setup");
			Reference stringReference = currentProgram.getReferenceManager().getReference(
				toAddr(0x294c), toAddr(0x5d4bfe), Reference.MNEMONIC);
			check(stringReference != null && stringReference.getReferenceType() == RefType.PARAM,
				"strcmp string literal did not create a physical PARAM xref on its setup");
			OperandReferenceAnalyzer referenceAnalyzer = new OperandReferenceAnalyzer();
			check(referenceAnalyzer.added(currentProgram,
				new AddressSet(toAddr(0x290c), toAddr(0x292c)), monitor,
				new MessageLog()), "Reference analyzer failed");
			Data stringData = currentProgram.getListing().getDefinedDataAt(toAddr(0x5d4c04));
			check(stringData != null && "http:".equals(stringData.getValue()),
				"Reference analyzer did not create the referenced string at 0x5d4c04");
			Data shortData = currentProgram.getListing().getDataAt(toAddr(0x5d4c30));
			check(shortData == null || !shortData.isDefined(),
				"Reference analyzer ignored its minimum length for short string");
			decompiler.flushCache();
			String strstrStringCode = decompile(decompiler, strstrUndefinedTargetCaller);
			check(strstrStringCode.contains("s_http__5d4c04"),
				"strstr physical target was not rendered as a string:\n" +
					strstrStringCode);
			String strstrSymbolCode = decompile(decompiler, strstrShortTargetCaller);
			check(strstrSymbolCode.contains("&DAT_5d4c30"),
				"short strstr target was not rendered as a symbol:\n" +
					strstrSymbolCode);
			checkSymbolPointerToken(decompiler, strstrShortTargetCaller,
				"DAT_5d4c30", 0x5d4c30);

			String sprintfCode = decompile(decompiler, callers.get(4));
			check(sprintfCode.contains("sprintf("), "sprintf call is missing:\n" + sprintfCode);
			check(sprintfCode.contains("\"done\""),
				"sprintf format was not resolved as a string:\n" + sprintfCode);
			check(sprintfCode.contains("sprintf_buffer"),
				"sprintf destination did not resolve to its physical symbol:\n" + sprintfCode);
			checkNoRepresentationArtifacts(sprintfCode);

			String sprintfVarargsCode = decompile(decompiler, callers.get(5));
			check(sprintfVarargsCode.contains("\"A:\\\\Internet\\\\pm_%d_%d.dat\""),
				"variadic sprintf format was not resolved as a string:\n" +
					sprintfVarargsCode);
			checkNoRepresentationArtifacts(sprintfVarargsCode);

			String sprintfExactCode = decompile(decompiler, callers.get(6));
			check(sprintfExactCode.contains("\"A:\\\\Internet\\\\pm_%d_%d.dat\""),
				"exact firmware sprintf format was not resolved as a string:\n" +
					sprintfExactCode);
			checkNoRepresentationArtifacts(sprintfExactCode);

			String sprintfFullCode = decompile(decompiler, callers.get(7));
			check(sprintfFullCode.contains("\"A:\\\\Internet\\\\pm_%d_%d.dat\""),
				"full firmware FUN_26cee4 format was not resolved as a string:\n" +
					sprintfFullCode);
			check(sprintfFullCode.contains("\"A:\\\\Internet\\\\~pm_%d_%d.dat\""),
				"full firmware FUN_26cee4 second format was not resolved as a string:\n" +
					sprintfFullCode);
			checkNoRepresentationArtifacts(sprintfFullCode);

			String dwordCode = decompile(decompiler, callers.get(8));
			check(dwordCode.contains("takes_dword("), "uint32_t call is missing:\n" + dwordCode);
			check(!dwordCode.contains("\"blabla\""),
				"non-pointer uint32_t was incorrectly rendered as a string:\n" + dwordCode);

			String returnCode = decompile(decompiler, callers.get(9));
			check(returnCode.contains("returns_string()") &&
				returnCode.contains("takes_pair_0("),
				"far-pointer return value was not propagated as one value:\n" + returnCode);
			checkNoRepresentationArtifacts(returnCode);

			String exactCode = decompile(decompiler, callers.get(10));
			check(exactCode.contains("FUN_258e12("),
				"exact 0x256c1e call is missing:\n" + exactCode);
			check(exactCode.contains("\"fixed-stack-fixture\"") &&
				exactCode.contains("\"third-stack-argument\""),
				"constant register/stack far pointers were not resolved:\n" + exactCode);
			check(exactCode.replaceAll("\\s+", "")
				.contains("\"third-stack-argument\");"),
				"0x256c1e incorrectly gained a fourth argument:\n" + exactCode);
			checkNoRepresentationArtifacts(exactCode);

			String snprintfExactCode = decompile(decompiler, snprintfExactCaller);
			String compactSnprintf = snprintfExactCode.replaceAll("\\s+", "");
			check((compactSnprintf.contains("snprintf(snprintf_buffer,0xff,") ||
				compactSnprintf.contains("snprintf(&snprintf_buffer,0xff,")) &&
				(compactSnprintf.contains("\"file://%s\"") ||
				compactSnprintf.contains("s_file____s_5d4c0a")),
				"exact firmware snprintf fixed arguments were not reconstructed:\n" +
					snprintfExactCode);
			check(!snprintfExactCode.contains("extraout_r15") &&
				!compactSnprintf.contains("snprintf_buffer,0xd,") &&
				!compactSnprintf.contains("0x3da6,0xd") &&
				!snprintfExactCode.contains(">> 0x10"),
				"exact firmware snprintf retained split register trials:\n" +
					snprintfExactCode);
			checkNoRepresentationArtifacts(snprintfExactCode);

			String snprintfParameterCode = decompile(decompiler, snprintfParameterCaller);
			String compactSnprintfParameter = snprintfParameterCode.replaceAll("\\s+", "");
			check(compactSnprintfParameter.contains(
				"snprintf(&snprintf_buffer,0xff,s_file____s_5d4c1c,input)") ||
				compactSnprintfParameter.contains(
					"snprintf(&snprintf_buffer,0xff,(char*)s_file____s_5d4c1c,input)") ||
				compactSnprintfParameter.contains(
					"snprintf((char*)0x37da6,0xff,\"file://%s\",input)"),
				"far-pointer function parameter was split at snprintf call:\n" +
					snprintfParameterCode);
			check(!snprintfParameterCode.contains(">> 0x10") &&
				!snprintfParameterCode.contains(",param_2") &&
				!snprintfParameterCode.contains("(size_t)input"),
				"far-pointer function parameter retained separate OFFSET/PAGE words:\n" +
					snprintfParameterCode);

			String snprintfInferredParameterCode = decompile(decompiler,
				snprintfInferredParameterCaller);
			String compactSnprintfInferred = snprintfInferredParameterCode.replaceAll(
				"\\s+", "");
			check((compactSnprintfInferred.contains(
				"snprintf(&snprintf_buffer,0xff,s_file____s_5d4c1c,param_1)") ||
				compactSnprintfInferred.contains(
					"snprintf(&snprintf_buffer,0xff,(char*)s_file____s_5d4c1c,param_1)") ||
				compactSnprintfInferred.contains(
					"snprintf((char*)0x37da6,0xff,\"file://%s\",param_1)")) &&
				!snprintfInferredParameterCode.contains(">> 0x10") &&
				!compactSnprintfInferred.contains("(size_t)param_1,param_2"),
				"inferred far-pointer parameter retained separate OFFSET/PAGE words:\n" +
					snprintfInferredParameterCode);

			String pointerScalarCode = decompile(decompiler, sprintfPointerScalarCaller);
			String compactPointerScalar = pointerScalarCode.replaceAll("\\s+", "");
			check(compactPointerScalar.contains("sprintf(") &&
				compactPointerScalar.contains(",input,id)") &&
				!pointerScalarCode.contains(">> 0x10") &&
				!pointerScalarCode.contains("CONCAT"),
				"saved far pointer and scalar were not reconstructed independently:\n" +
					pointerScalarCode);

			String snprintf747f44Code = decompile(decompiler, snprintf747f44Caller);
			String compactSnprintf747f44 = snprintf747f44Code.replaceAll("\\s+", "");
			check(compactSnprintf747f44.contains("snprintf(") &&
				compactSnprintf747f44.contains(",0x2d,") &&
				(compactSnprintf747f44.contains("\"%s\\\\%0.2x") ||
					compactSnprintf747f44.contains("(char*)0x5c5972")),
				"FUN_747f44 fixed snprintf arguments were not reconstructed:\n" +
					snprintf747f44Code);
			check(snprintf747f44Code.indexOf("PTR_5c596e") >= 0 &&
				!snprintf747f44Code.contains("PTR_5c596e._2_2_") &&
				!snprintf747f44Code.contains("pcRam5c596e") &&
				!snprintf747f44Code.contains("0x1711972"),
				"FUN_747f44 retained split far-pointer representation:\n" +
					snprintf747f44Code);
		}
		finally {
			decompiler.dispose();
		}

		println("Patched far-pointer decompiler matrix passed: register and stack pairs, " +
			"exact three-argument 0x256c1e fixture, strcmp@BFA966, sprintf@BFB37E, " +
			"snprintf fixed-stack spill, unsafe-override recovery, mixed pointer/scalar " +
			"override recovery, and split pointer " +
			"parameter recovery, C166 far-pointer auto-structure, clickable undefined " +
			"target, return value, and a " +
			"non-pointer control.");
	}

	private void useDevelopmentDecompilerIfRequested() throws Exception {
		String path = System.getenv("C166_TEST_DECOMPILER");
		if (path == null || path.isBlank()) {
			return;
		}
		Field executablePath = DecompileProcessFactory.class.getDeclaredField("exepath");
		executablePath.setAccessible(true);
		executablePath.set(null, path);
		println("Using development decompiler: " + executablePath.get(null));
	}

	private FunctionDefinition prototypeOverride(Function caller, Address callSite) {
		if (HighFunction.findOverrideSpace(caller) == null) {
			return null;
		}
		for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(callSite)) {
			if (symbol.getSymbolType() != SymbolType.LABEL ||
				!HighFunction.isOverrideNamespace(symbol.getParentNamespace())) {
				continue;
			}
			DataTypeSymbol override = HighFunctionDBUtil.readOverride(symbol);
			if (override != null && override.getDataType() instanceof FunctionDefinition definition) {
				return definition;
			}
		}
		return null;
	}

	private boolean deletePrototypeOverride(Function caller, Address callSite) {
		if (HighFunction.findOverrideSpace(caller) == null) {
			return false;
		}
		for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(callSite)) {
			if (symbol.getSymbolType() == SymbolType.LABEL &&
				HighFunction.isOverrideNamespace(symbol.getParentNamespace()) &&
				HighFunctionDBUtil.readOverride(symbol) != null) {
				return symbol.delete();
			}
		}
		return false;
	}

	private Function callee(long address, String name, DataType returnType,
			DataType... parameterTypes) throws Exception {
		Address entry = toAddr(address);
		byte[] code = new byte[0x10];
		code[0] = (byte) 0xdb;
		MemoryBlock block = createMemoryBlock(name + "_code", entry,
			code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		function.setReturnType(returnType, SourceType.USER_DEFINED);
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < parameterTypes.length; i++) {
			parameters.add(new ParameterImpl("arg" + i, parameterTypes[i], currentProgram));
		}
		function.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING, null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		return function;
	}

	private Function caller(long address, String name, byte[] code) throws Exception {
		return functionWithCode(address, name, code);
	}

	private Function functionWithCode(long address, String name, byte[] code) throws Exception {
		Address entry = toAddr(address);
		MemoryBlock block = createMemoryBlock(name + "_code", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private void checkThreePointerSignature(Function function) {
		check(function.getParameterCount() == 3,
			"expected three inferred far pointers, got " + function.getParameterCount());
		String[] storage = { "r13+r12", "r15+r14", "Stack[0x0]:4" };
		for (int i = 0; i < storage.length; i++) {
			check(function.getParameter(i).getFormalDataType() instanceof Pointer,
				"parameter " + i + " was not inferred as a pointer");
			check(storage[i].equals(describe(function.getParameter(i).getVariableStorage())),
				"parameter " + i + " has wrong storage: " +
					describe(function.getParameter(i).getVariableStorage()));
		}
	}

	private void setThreeCharPointers(Function function) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			parameters.add(new ParameterImpl("arg" + i, charPointer, currentProgram));
		}
		function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private String describe(ghidra.program.model.listing.VariableStorage storage) {
		if (storage.isStackStorage()) {
			return "Stack[0x" + Integer.toHexString(storage.getStackOffset()) + "]:" +
				storage.size();
		}
		return storage.getRegisters().stream()
			.map(register -> register.getName().toLowerCase())
			.reduce((left, right) -> left + "+" + right)
			.orElse(storage.toString());
	}

	private void setCode(Function function, byte[] code) throws Exception {
		Address entry = function.getEntryPoint();
		clearListing(entry, entry.add(code.length - 1));
		currentProgram.getMemory().setBytes(entry, code);
		check(disassemble(entry), "failed to replace code for " + function.getName());
		function.setBody(new AddressSet(entry, entry.add(code.length - 1)));
	}

	private void string(long address, String value) throws Exception {
		byte[] encoded = new byte[value.length() + 1];
		for (int i = 0; i < value.length(); i++) {
			encoded[i] = (byte) value.charAt(i);
		}
		MemoryBlock block = createMemoryBlock("string_" + Long.toHexString(address),
			toAddr(address), encoded, false);
		block.setWrite(false);
		createAsciiString(toAddr(address));
	}

	private void data(long address, long size, boolean writable) throws Exception {
		MemoryBlock block = createMemoryBlock("data_" + Long.toHexString(address),
			toAddr(address), new byte[(int) size], false);
		block.setWrite(writable);
	}

	private void checkPhysicalPointerToken(DecompInterface decompiler, Function function,
			long expectedAddress) {
		DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
		check(result.decompileCompleted(), function.getName() + ": token decompilation failed: " +
			result.getErrorMessage());
		List<ClangNode> nodes = new ArrayList<>();
		result.getCCodeMarkup().flatten(nodes);
		for (ClangNode node : nodes) {
			if (!(node instanceof ClangVariableToken token) || token.getVarnode() == null ||
				!token.getVarnode().isConstant()) {
				continue;
			}
			if (token.getText().equals("0x" + Long.toHexString(expectedAddress))) {
				check(toAddr(expectedAddress).equals(token.getResolvedAddress()),
					"pointer token has wrong resolved address: " + token.getResolvedAddress());
				return;
			}
		}
		throw new AssertionError("physical pointer token is missing for 0x" +
			Long.toHexString(expectedAddress));
	}

	private void checkSymbolPointerToken(DecompInterface decompiler, Function function,
			String symbolName, long expectedAddress) {
		DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
		check(result.decompileCompleted(), function.getName() +
			": symbol token decompilation failed: " + result.getErrorMessage());
		List<ClangNode> nodes = new ArrayList<>();
		result.getCCodeMarkup().flatten(nodes);
		for (ClangNode node : nodes) {
			if (node instanceof ClangVariableToken token &&
				token.getText().equals(symbolName)) {
				check(toAddr(expectedAddress).equals(token.getResolvedAddress()),
					"symbol token has wrong resolved address: " +
						token.getResolvedAddress() + ", op=" + token.getPcodeOp() +
						", varnode=" + token.getVarnode());
				return;
			}
		}
		throw new AssertionError("symbol pointer token is missing for " + symbolName);
	}

	private void checkStringPointerToken(DecompInterface decompiler, Function function,
			String text, long expectedAddress) {
		DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
		check(result.decompileCompleted(), function.getName() +
			": string-token decompilation failed: " + result.getErrorMessage());
		List<ClangNode> nodes = new ArrayList<>();
		result.getCCodeMarkup().flatten(nodes);
		for (ClangNode node : nodes) {
			if (node instanceof ClangVariableToken token && token.getText().equals(text)) {
				check(toAddr(expectedAddress).equals(token.getResolvedAddress()),
					"string token has wrong resolved address: " +
						token.getResolvedAddress());
				return;
			}
		}
		throw new AssertionError("string pointer token is missing for " + text);
	}

	private String decompile(DecompInterface decompiler, Function function) {
		DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
		check(result.decompileCompleted(), function.getName() + ": decompilation failed: " +
			result.getErrorMessage());
		String code = result.getDecompiledFunction().getC();
		println(code);
		return code;
	}

	private void checkCleanPointerCall(String code, String expectedLiteral) {
		check(code.contains(expectedLiteral), "far string was not resolved:\n" + code);
		checkNoRepresentationArtifacts(code);
	}

	private void checkNoRepresentationArtifacts(String code) {
		for (String artifact : List.of("CONCAT", "ZEXT", "SEXT", "segment(")) {
			check(!code.contains(artifact), artifact + " remains in decompiled call:\n" + code);
		}
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private byte[] hexBytes(String value) {
		check((value.length() & 1) == 0, "odd hex fixture length");
		byte[] result = new byte[value.length() / 2];
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
