// Headless regression test; run via tools/test-tasking-abi.sh.
import java.util.ArrayList;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.ParameterPieces;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.classfinder.ClassSearcher;
import ghidrainfineon.C166ArchitectureProfile;
import ghidrainfineon.C166CodePointerPhase;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166TaskingDataTypePhase;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;
import ghidrainfineon.C166VariadicCallPhase;

public class C166TaskingClassicAbiTest extends GhidraScript {

	private PrototypeModel model;

	@Override
	protected void run() throws Exception {
		String compilerId = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
		check("tasking-classic-large".equals(compilerId),
			"wrong compiler spec: " + compilerId);
		check(new C166CodePointerPhase().canAnalyze(currentProgram),
			"code-pointer phase does not accept TASKING Classic large");
		check(new C166FarPointerPhase().canAnalyze(currentProgram),
			"far-pointer phase does not accept TASKING Classic large");
		check(new C166VariadicCallPhase().canAnalyze(currentProgram),
			"variadic phase does not accept TASKING Classic large");
		check(new C166TaskingDataTypePhase().canAnalyze(currentProgram),
			"data-type phase does not accept TASKING Classic large");
		check(new C166TaskingRuntimeAnalyzer().canAnalyze(currentProgram),
			"runtime analyzer does not accept TASKING Classic large");
		C166TaskingTypeInferenceAnalyzer unified =
			new C166TaskingTypeInferenceAnalyzer();
		check(unified.canAnalyze(currentProgram) &&
			unified.getDefaultEnablement(currentProgram),
			"unified TASKING type inference is not the enabled analyzer");
		Set<String> discoveredAnalyzers = ClassSearcher.getClasses(Analyzer.class).stream()
			.filter(type -> type.getName().startsWith("ghidrainfineon.C166"))
			.map(Class::getSimpleName)
			.collect(Collectors.toSet());
		check(discoveredAnalyzers.contains("C166TaskingTypeInferenceAnalyzer"),
			"unified TASKING type inference is absent from ClassSearcher");
		for (String phase : Set.of("C166CodePointerPhase", "C166FarPointerPhase",
			"C166PointerReturnPhase", "C166TaskingDataTypePhase",
			"C166VariadicCallPhase")) {
			check(!discoveredAnalyzers.contains(phase),
				"internal phase leaked into Ghidra Analyzer list: " + phase);
		}
		check(currentProgram.getCompilerSpec().getCallingConvention(
			"__tasking_c166_double_runtime") != null,
			"TASKING double-runtime calling convention is missing");
		String languageId = currentProgram.getLanguageID().getIdAsString();
		check("C166:LE:16:tasking-classic-large".equals(languageId) ||
			"C166:CS:LE:16:tasking-classic-large".equals(languageId),
			"wrong language: " + languageId);
		check(C166ArchitectureProfile.TASKING_CLASSIC_LARGE.equals(
			currentProgram.getLanguage().getProperty(C166ArchitectureProfile.PROPERTY)),
			"TASKING Classic Large ABI profile is missing");

		model = currentProgram.getCompilerSpec().getDefaultCallingConvention();
		check("__tasking_c166_classic".equals(model.getName()),
			"wrong default convention: " + model.getName());
		check(currentProgram.getDefaultPointerSize() == 4,
			"default pointer size is " + currentProgram.getDefaultPointerSize());
		check(currentProgram.getRegister("ARGFP12") == null,
			"synthetic TASKING call-view register ARGFP12 is still present");
		check(!hasUserop("farsegment_arg"),
			"synthetic TASKING call-view userop farsegment_arg is still present");
		check(!hasUserop("farsegment"), "obsolete farsegment userop is still present");
		checkDataOrganization();
		checkSizeTypeNormalization();

		DataType voidType = VoidDataType.dataType;
		DataType word = new UnsignedShortDataType(currentProgram.getDataTypeManager());
		DataType dword = new UnsignedLongDataType(currentProgram.getDataTypeManager());
		DataType qword = new UnsignedLongLongDataType(currentProgram.getDataTypeManager());
		DataType byteType = new UnsignedCharDataType(currentProgram.getDataTypeManager());
		DataType floatType = new FloatDataType(currentProgram.getDataTypeManager());
		DataType doubleType = new DoubleDataType(currentProgram.getDataTypeManager());
		DataType structure = new StructureDataType("AbiStruct", 2,
			currentProgram.getDataTypeManager());
		DataType largeStructure = new StructureDataType("AbiLargeStruct", 8,
			currentProgram.getDataTypeManager());
		DataType pointer = new PointerDataType(CharDataType.dataType,
			currentProgram.getDataTypeManager());

		check(pointer.getLength() == 4, "C pointer length is " + pointer.getLength());

		checkStorage("noargs", locations(voidType), "void");
		checkStorage("byte-return", locations(byteType), "rl4");
		checkStorage("word-return", locations(word), "r4");
		checkStorage("dword-return", locations(dword), "r5+r4");
		checkStorage("pointer-return", locations(pointer), "r5+r4");
		checkStorage("byte-parameters", locations(voidType,
			byteType, byteType, byteType, byteType),
			"void", "r12", "r13", "r14", "r15");
		checkStorage("f1", locations(voidType, word, word, word, word),
			"void", "r12", "r13", "r14", "r15");
		checkStorage("f2", locations(dword, dword, dword),
			"r5+r4", "r13+r12", "r15+r14");
		checkStorage("f3", locations(voidType, word, dword, word),
			"void", "r12", "r14+r13", "r15");
		checkStorage("f4", locations(voidType, dword, word, dword, word),
			"void", "r13+r12", "r14", "stack[0x0]:4", "stack[0x4]:2");
		checkStorage("f6", locations(pointer, pointer, pointer),
			"r5+r4", "r13+r12", "r15+r14");
		checkStorage("unaligned-pointer", locations(voidType, word, pointer, word),
			"void", "r12", "r14+r13", "r15");
		checkStorage("late-pointer", locations(voidType, word, word, pointer),
			"void", "r12", "r13", "r15+r14");
		checkStorage("pointer-spill", locations(voidType, word, word, word, pointer, word),
			"void", "r12", "r13", "r14", "stack[0x0]:4", "stack[0x4]:2");
		checkStorage("qword-spill", locations(voidType, qword, word),
			"void", "stack[0x0]:8", "stack[0x8]:2");
		checkStorage("double-spill", locations(voidType, doubleType, word),
			"void", "stack[0x0]:8", "stack[0x8]:2");

		VariableStorage[] variadic = variadicLocations(voidType, 1, word, word, dword);
		checkStorage("f5", variadic,
			"void", "r12", "stack[0x0]:2", "stack[0x2]:4");
		checkStorage("variadic-fixed-pointer",
			variadicLocations(voidType, 1, pointer, word, dword),
			"void", "r13+r12", "stack[0x0]:2", "stack[0x2]:4");
		checkStorage("float", locations(floatType, word, floatType, word),
			"r5+r4", "r12", "stack[0x0]:4", "stack[0x4]:2");
		checkStorage("aggregate", locations(voidType, word, structure, word),
			"void", "r12", "stack[0x0]:2", "stack[0x2]:2");
		VariableStorage[] aggregateIndirectReturn =
			locationsWithAuto(largeStructure, word, word);
		checkStorage("aggregate-indirect-return", aggregateIndirectReturn,
			"r4", "r12", "r13");
		check(aggregateIndirectReturn[0].isForcedIndirect(),
			"aggregate result is not returned indirectly through R4");
		checkNoAutoStorage("aggregate-indirect-return", aggregateIndirectReturn);
		VariableStorage[] doubleIndirectReturn = locationsWithAuto(doubleType, word, word);
		checkStorage("double-indirect-return", doubleIndirectReturn,
			"r4", "r12", "r13");
		check(doubleIndirectReturn[0].isForcedIndirect(),
			"double result is not returned indirectly through R4");
		checkNoAutoStorage("double-indirect-return", doubleIndirectReturn);
		VariableStorage[] variadicIndirectReturn =
			variadicLocationsWithAuto(largeStructure, 0, word, word);
		checkStorage("variadic-indirect-return", variadicIndirectReturn,
			"r4", "stack[0x0]:2", "stack[0x2]:2");
		check(variadicIndirectReturn[0].isForcedIndirect(),
			"variadic aggregate result is not returned indirectly through R4");
		checkNoAutoStorage("variadic-indirect-return", variadicIndirectReturn);
		checkCallSiteConvention("vararg1", "__tasking_c166_classic_vararg_1",
			new DataType[] { voidType, pointer, word },
			"void", "r13+r12", "stack[0x0]:2");
		checkCallSiteConvention("vararg2", "__tasking_c166_classic_vararg_2",
			new DataType[] { voidType, pointer, pointer, word },
			"void", "r13+r12", "r15+r14", "stack[0x0]:2");
		checkCallSiteConvention("vararg3", "__tasking_c166_classic_vararg_3",
			new DataType[] { voidType, word, word, word, word },
			"void", "r12", "r13", "r14", "stack[0x0]:2");
		checkCallSiteConvention("snprintf-vararg3", "__tasking_c166_classic_vararg_3",
			new DataType[] { voidType, pointer, word, pointer, pointer },
			"void", "r13+r12", "r14", "stack[0x0]:4", "stack[0x4]:4");
		check(currentProgram.getCompilerSpec().getCallingConvention(
			"__tasking_c166_classic_farptr2") == null,
			"synthetic farptr2 calling convention is still present");

		Set<String> killedRegisters = Set.of(model.getKilledByCallList()).stream()
			.map(currentProgram::getRegister)
			.filter(register -> register != null)
			.map(register -> register.getName().toLowerCase())
			.collect(Collectors.toSet());
		for (String register : Set.of("r12", "r13", "r14", "r15")) {
			check(killedRegisters.contains(register), register + " is not killed by call");
		}

		println("TASKING C166 Classic ABI storage tests passed.");
	}

	private void checkDataOrganization() {
		DataOrganization organization = currentProgram.getCompilerSpec().getDataOrganization();
		check(organization.getCharSize() == 1, "char size is not 1");
		check(organization.getShortSize() == 2, "short size is not 2");
		check(organization.getIntegerSize() == 2, "int size is not 2");
		check(organization.getLongSize() == 4, "long size is not 4");
		check(organization.getFloatSize() == 4, "float size is not 4");
		check(organization.getDoubleSize() == 8, "double size is not 8");
		check(organization.getPointerSize() == 4, "pointer size is not 4");
	}

	private void checkSizeTypeNormalization() throws Exception {
		ghidra.program.model.data.DataTypeManager manager =
			currentProgram.getDataTypeManager();
		TypedefDataType wrongSizeType = new TypedefDataType(new CategoryPath("/stddef.h"),
			"size_t", new UnsignedLongDataType(manager), manager);
		manager.addDataType(wrongSizeType,
			DataTypeConflictHandler.REPLACE_HANDLER);
		check(manager.getDataType("/stddef.h/size_t").getLength() == 4,
			"failed to construct the wrong imported size_t fixture");
		C166TaskingDataTypePhase analyzer = new C166TaskingDataTypePhase();
		check(analyzer.added(currentProgram, new AddressSet(), monitor, new MessageLog()),
			"TASKING data-type analyzer failed");
		DataType normalized = manager.getDataType("/stddef.h/size_t");
		check(normalized != null && normalized.getLength() == 2,
			"size_t was not normalized to 16-bit unsigned int");

		TypedefDataType conflictDefinition = new TypedefDataType(new CategoryPath("/stddef.h"),
			"size_t.conflict", new UnsignedLongDataType(manager), manager);
		DataType conflict = manager.addDataType(conflictDefinition,
			DataTypeConflictHandler.REPLACE_HANDLER);
		FunctionDefinitionDataType importedSnprintf = new FunctionDefinitionDataType(
			new CategoryPath("/test"), "snprintf_fixture", manager);
		importedSnprintf.setArguments(
			new ParameterDefinitionImpl("maxlen", conflict, null));
		manager.addDataType(importedSnprintf, DataTypeConflictHandler.REPLACE_HANDLER);

		check(analyzer.added(currentProgram, new AddressSet(), monitor, new MessageLog()),
			"TASKING data-type conflict cleanup failed");
		check(manager.getDataType("/stddef.h/size_t.conflict") == null,
			"incompatible generic-clib size_t.conflict survived normalization");
		FunctionDefinition normalizedSnprintf =
			(FunctionDefinition) manager.getDataType("/test/snprintf_fixture");
		DataType normalizedArgument = normalizedSnprintf.getArguments()[0].getDataType();
		check(normalizedArgument.getLength() == 2 &&
			"/stddef.h/size_t".equals(normalizedArgument.getPathName()),
			"dependent snprintf prototype still uses " + normalizedArgument.getPathName() +
				" (" + normalizedArgument.getLength() + " bytes)");
	}

	private VariableStorage[] locations(DataType returnType, DataType... parameters) {
		DataType[] signature = new DataType[parameters.length + 1];
		signature[0] = returnType;
		System.arraycopy(parameters, 0, signature, 1, parameters.length);
		return model.getStorageLocations(currentProgram, signature, false);
	}

	private VariableStorage[] locationsWithAuto(DataType returnType, DataType... parameters) {
		DataType[] signature = new DataType[parameters.length + 1];
		signature[0] = returnType;
		System.arraycopy(parameters, 0, signature, 1, parameters.length);
		return model.getStorageLocations(currentProgram, signature, true);
	}

	private VariableStorage[] variadicLocations(DataType returnType, int firstVarArgSlot,
			DataType... parameters) {
		return variadicLocations(returnType, firstVarArgSlot, false, parameters);
	}

	private VariableStorage[] variadicLocationsWithAuto(DataType returnType,
			int firstVarArgSlot, DataType... parameters) {
		return variadicLocations(returnType, firstVarArgSlot, true, parameters);
	}

	private VariableStorage[] variadicLocations(DataType returnType, int firstVarArgSlot,
			boolean addAutoParams, DataType... parameters) {
		PrototypePieces pieces = new PrototypePieces(model, returnType);
		for (DataType parameter : parameters) {
			pieces.intypes.add(parameter);
		}
		pieces.firstVarArgSlot = firstVarArgSlot;

		ArrayList<ParameterPieces> assigned = new ArrayList<>();
		model.assignParameterStorage(pieces, currentProgram.getDataTypeManager(), assigned,
			addAutoParams);
		VariableStorage[] result = new VariableStorage[assigned.size()];
		for (int i = 0; i < assigned.size(); i++) {
			result[i] = assigned.get(i).getVariableStorage(currentProgram);
		}
		return result;
	}

	private void checkCallSiteConvention(String fixture, String conventionName,
			DataType[] signature, String... expected) {
		PrototypeModel convention =
			currentProgram.getCompilerSpec().getCallingConvention(conventionName);
		check(convention != null, conventionName + " convention is missing");
		checkStorage(fixture,
			convention.getStorageLocations(currentProgram, signature, false), expected);
	}

	private void checkStorage(String fixture, VariableStorage[] actual, String... expected) {
		check(actual.length == expected.length,
			fixture + ": expected " + expected.length + " storage entries, got " + actual.length);
		for (int i = 0; i < expected.length; i++) {
			String described = describe(actual[i]);
			check(expected[i].equals(described), fixture + "[" + i + "]: expected " +
				expected[i] + ", got " + described + " (" +
				actual[i].getSerializationString() + ")");
		}
	}

	private void checkNoAutoStorage(String fixture, VariableStorage[] storage) {
		for (int i = 0; i < storage.length; i++) {
			check(!storage[i].isAutoStorage(), fixture + "[" + i +
				"] unexpectedly contains an automatic hidden parameter");
		}
	}

	private String describe(VariableStorage storage) {
		if (storage.isVoidStorage()) {
			return "void";
		}
		if (storage.isStackStorage()) {
			return "stack[0x" + Integer.toHexString(storage.getStackOffset()) + "]:" +
				storage.size();
		}
		if (!storage.getRegisters().isEmpty() && !storage.hasStackStorage()) {
			return storage.getRegisters().stream()
				.map(register -> register.getName().toLowerCase())
				.collect(Collectors.joining("+"));
		}
		return storage.toString();
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}

	private boolean hasUserop(String expectedName) {
		for (int i = 0; i < currentProgram.getLanguage().getNumberOfUserDefinedOpNames(); i++) {
			if (expectedName.equals(currentProgram.getLanguage().getUserDefinedOpName(i))) {
				return true;
			}
		}
		return false;
	}
}
