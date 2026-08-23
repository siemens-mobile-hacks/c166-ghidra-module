// Run against the patched Ghidra via tools/test-patched-decompiler.sh.
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166AddressAnalyzer;
import ghidrainfineon.C166CallTargetAnalyzer;
import ghidrainfineon.C166CodePointerPhase;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166PointerReturnPhase;
import ghidrainfineon.C166ScalarSignaturePhase;
import ghidrainfineon.C166TaskingDataTypePhase;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;
import ghidrainfineon.C166VariadicCallPhase;

public class NonC166AutoStructureControlTest extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String language = currentProgram.getLanguageID().getIdAsString();
		check(!language.startsWith("C166:"),
			"non-C166 control accidentally uses C166");
		check(currentProgram.getLanguage().getProperty("c166.abi") == null,
			"C166 TASKING decompiler markers leaked into " + language);
		for (AbstractAnalyzer analyzer : List.of(
			new C166AddressAnalyzer(),
			new C166CallTargetAnalyzer(),
			new C166TaskingRuntimeAnalyzer(),
			new C166TaskingTypeInferenceAnalyzer())) {
			check(!analyzer.canAnalyze(currentProgram),
				analyzer.getName() + " accepted " + language);
		}
		check(!new C166CodePointerPhase().canAnalyze(currentProgram),
			"code-pointer phase accepted " + language);
		check(!new C166FarPointerPhase().canAnalyze(currentProgram),
			"far-pointer phase accepted " + language);
		check(!new C166PointerReturnPhase().canAnalyze(currentProgram),
			"pointer-return phase accepted " + language);
		check(!new C166ScalarSignaturePhase().canAnalyze(currentProgram),
			"scalar-signature phase accepted " + language);
		check(!new C166TaskingDataTypePhase().canAnalyze(currentProgram),
			"data-type phase accepted " + language);
		check(!new C166VariadicCallPhase().canAnalyze(currentProgram),
			"variadic phase accepted " + language);

		Address entry = toAddr(0x1000);
		byte[] code;
		if (language.startsWith("x86:")) {
			code = bytes(
				0x89, 0x77, 0x40, // mov dword ptr [rdi+0x40],esi
				0x89, 0x57, 0x44, // mov dword ptr [rdi+0x44],edx
				0xc3);            // ret
		}
		else if (language.startsWith("ARM:LE:32:")) {
			code = bytes(
				0x40, 0x10, 0x80, 0xe5, // str r1,[r0,#0x40]
				0x44, 0x20, 0x80, 0xe5, // str r2,[r0,#0x44]
				0x1e, 0xff, 0x2f, 0xe1); // bx lr
		}
		else {
			throw new AssertionError("unsupported non-C166 control language: " + language);
		}
		MemoryBlock block = createMemoryBlock("auto_structure_control_code", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble non-C166 auto-structure control");
		Function function = createFunction(entry, "auto_structure_control");
		check(function != null, "failed to create non-C166 auto-structure control");
		function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
		List<Variable> parameters = new ArrayList<>();
		parameters.add(new ParameterImpl("object",
			new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager()), currentProgram));
		parameters.add(new ParameterImpl("field_40",
			new Undefined4DataType(currentProgram.getDataTypeManager()), currentProgram));
		parameters.add(new ParameterImpl("field_44",
			new Undefined4DataType(currentProgram.getDataTypeManager()), currentProgram));
		function.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING, null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram),
			"failed to initialize x86 decompiler: " + decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
			check(results.decompileCompleted() && results.getHighFunction() != null,
				"failed to decompile non-C166 auto-structure control: " +
					results.getErrorMessage());
			HighSymbol symbol = results.getHighFunction().getLocalSymbolMap().getParamSymbol(0);
			HighVariable variable = symbol == null ? null : symbol.getHighVariable();
			Structure structure = new FillOutStructureHelper(currentProgram, monitor)
				.processStructure(variable, function, true, false, null);
			check(structure != null && structure.getLength() == 0x48 &&
				structure.getComponentAt(0x40) != null &&
				structure.getComponentAt(0x44) != null,
				"upstream-style non-C166 auto-structure behavior regressed");
		}
		finally {
			decompiler.dispose();
		}
		checkNativeWidthPointerConstant(language);

		println("Non-C166 auto-structure control passed for " + language + ".");
	}

	private void checkNativeWidthPointerConstant(String language) throws Exception {
		Address target = toAddr(0x12345678L);
		MemoryBlock data = createMemoryBlock("native_pointer_target", target,
			bytes(0x78, 0x56, 0x34, 0x12), false);
		data.setWrite(false);
		createData(target, Undefined4DataType.dataType);
		createLabel(target, "g_native_width_pointer", true);

		Address entry = toAddr(0x2000);
		byte[] code;
		if (language.startsWith("x86:")) {
			code = bytes(
				0xa1, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, // mov eax,[0x12345678]
				0xc3);                                      // ret
		}
		else {
			code = bytes(
				0x78, 0x06, 0x05, 0xe3, // movw r0,#0x5678
				0x34, 0x02, 0x41, 0xe3, // movt r0,#0x1234
				0x00, 0x00, 0x90, 0xe5, // ldr r0,[r0]
				0x1e, 0xff, 0x2f, 0xe1);// bx lr
		}
		MemoryBlock block = createMemoryBlock("native_pointer_code", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble native-pointer control");
		Function function = createFunction(entry, "native_pointer_control");
		check(function != null, "failed to create native-pointer control");
		function.setReturnType(Undefined4DataType.dataType, SourceType.USER_DEFINED);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String codeText = results.getDecompiledFunction().getC();
			check(codeText.contains("g_native_width_pointer"),
				"native-width pointer constant changed on " + language + ":\n" + codeText);
		}
		finally {
			decompiler.dispose();
		}
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
