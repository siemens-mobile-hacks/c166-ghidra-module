// Focused headless regression for exact returned-layout aliases.
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166AggregateLayoutPhase;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166ReturnedLayoutAliasTest extends GhidraScript {

	private long nextAddress = 0x700000;

	@Override
	protected void run() throws Exception {
		DataType word = new UnsignedShortDataType(currentProgram.getDataTypeManager());
		DataType element = new UnsignedIntegerDataType(currentProgram.getDataTypeManager());
		DataType wordPointer = new PointerDataType(element,
			currentProgram.getDataTypeManager());
		StructureDataType definition = new StructureDataType(
			new CategoryPath("/auto_structs"), "astruct_returned_layout", 6,
			currentProgram.getDataTypeManager());
		definition.replaceAtOffset(0, wordPointer, 4, "body", null);
		definition.replaceAtOffset(4, word, 2, "capacity", null);
		DataType layout = currentProgram.getDataTypeManager().addDataType(definition,
			DataTypeConflictHandler.REPLACE_HANDLER);
		DataType layoutPointer = new PointerDataType(layout,
			currentProgram.getDataTypeManager());
		DataType genericPointer = new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager());

		Function direct = fixture("returned_layout_parameter", bytes(
			0xf0, 0x4c, // R4 = incoming OFFSET R12
			0xf0, 0x5d, // R5 = incoming PAGE R13
			0xdb, 0x00));
		setAnalysisPointer(direct, genericPointer, layoutPointer);

		Function callee = fixture("forwarded_layout_callee", bytes(
			0xf0, 0x4c, 0xf0, 0x5d, 0xdb, 0x00));
		setAnalysisPointer(callee, genericPointer, genericPointer);
		Function wrapper = fixture("returned_layout_call_wrapper",
			concat(callInstruction(callee), bytes(0xdb, 0x00)));
		setAnalysisPointer(wrapper, genericPointer, layoutPointer);
		Function fieldStore = fixture("aggregate_pointer_field_store", bytes(
			0xdc, 0x5d,             // EXTP R13, #2
			0xc4, 0xfc, 0x02, 0x00, // [R12 + 2] = R15 (PAGE)
			0xb8, 0xec,             // [R12] = R14 (OFFSET)
			0xf0, 0x4c, 0xf0, 0x5d, 0xdb, 0x00));
		setAnalysisSignature(fieldStore, List.of(genericPointer, word, word),
			genericPointer);
		Function fieldWrapper = fixture("aggregate_pointer_field_wrapper",
			concat(bytes(
				0xa8, 0x10,                         // R1 = [R0] (third argument)
				0xdc, 0x4d,                         // EXTP R13, #1
				0xc4, 0x1c, 0x04, 0x00,             // [R12 + 4] = R1
				0x88, 0xc0, 0x88, 0xd0),            // save R12:R13
				callInstruction(fieldStore),
				bytes(0x98, 0xd0, 0x98, 0xc0,       // restore R13:R12
					0xf0, 0x4c, 0xf0, 0x5d, 0xdb, 0x00)));
		setAnalysisSignature(fieldWrapper,
			List.of(layoutPointer, genericPointer, word),
			layoutPointer);
		Function localCallee = fixture("typed_local_object_consumer", bytes(0xdb, 0x00));
		setAnalysisSignature(localCallee,
			List.of(layoutPointer, wordPointer, word), VoidDataType.dataType);
		Function localCaller = fixture("typed_local_object_caller", concat(bytes(
			0x26, 0xf0, 0x50, 0x00,             // reserve 0x50 local bytes
			0xe6, 0xfc, 0x26, 0x00,             // third argument = 0x26
			0x88, 0xc0,                         // push third argument
			0xe0, 0x8c, 0x00, 0xc0,             // R12 = R0 + 8
			0x66, 0xfc, 0xff, 0x3f,
			0xf2, 0xfd, 0x02, 0xfe,             // R13 = DPP1
			0xe0, 0xee, 0x00, 0xe0,             // R14 = R0 + 14
			0x66, 0xfe, 0xff, 0x3f,
			0xf2, 0xff, 0x02, 0xfe),            // R15 = DPP1
			callInstruction(localCallee),
			bytes(0x06, 0xf0, 0x52, 0x00, 0xdb, 0x00)));
		setAnalysisSignature(localCaller, List.of(), VoidDataType.dataType);
		DataType sizedWord = new Undefined2DataType(currentProgram.getDataTypeManager());
		DataType sizedWordPointer = new PointerDataType(sizedWord,
			currentProgram.getDataTypeManager());
		Function sizedLocalCallee = fixture("sized_local_object_consumer",
			bytes(0xdb, 0x00));
		setAnalysisSignature(sizedLocalCallee, List.of(sizedWordPointer),
			VoidDataType.dataType);
		Function sizedLocalCaller = fixture("sized_local_object_caller", concat(bytes(
			0x26, 0xf0, 0x0a, 0x00,             // reserve local plus saved return word
			0xe0, 0x8c, 0x00, 0xc0,             // R12 = R0 + 8
			0x66, 0xfc, 0xff, 0x3f,
			0xf2, 0xfd, 0x02, 0xfe),            // R13 = DPP1
			callInstruction(sizedLocalCallee),
			bytes(0x06, 0xf0, 0x0a, 0x00, 0xdb, 0x00)));
		setAnalysisSignature(sizedLocalCaller, List.of(), VoidDataType.dataType);

		AddressSet aliasScope = new AddressSet(direct.getBody());
		aliasScope.add(callee.getBody());
		aliasScope.add(wrapper.getBody());
		check(new C166AggregateLayoutPhase().added(currentProgram, aliasScope, monitor,
			new MessageLog()), "returned-layout alias phase failed");
		check(hasTarget(direct.getParameter(0).getFormalDataType(), layout),
			"direct returned parameter did not receive the concrete layout");
		check(hasTarget(callee.getReturnType(), layout),
			"forwarded call did not refine the callee return");
		check(hasTarget(callee.getParameter(0).getFormalDataType(), layout),
			"forwarded callee parameter did not receive the concrete layout");
		check(hasTarget(wrapper.getParameter(0).getFormalDataType(), layout),
			"returned call parameter alias did not propagate back into the wrapper");

		AddressSet pipelineScope = new AddressSet(fieldWrapper.getBody());
		pipelineScope.add(localCaller.getBody());
		pipelineScope.add(sizedLocalCaller.getBody());
		check(new C166TaskingTypeInferenceAnalyzer().added(currentProgram, pipelineScope,
			monitor, new MessageLog()), "shared-scope type inference pipeline failed");
		check(hasTarget(((ghidra.program.model.data.Structure) layout)
			.getComponentAt(0).getDataType(), element),
			"aggregate extension weakened an existing concrete pointer field");
		check(hasTarget(fieldWrapper.getParameter(1).getFormalDataType(), element),
			"pointer field initializer did not recover the wrapper pointee type: " +
				fieldWrapper.getParameter(1).getFormalDataType().getDisplayName() +
				", field=" + ((ghidra.program.model.data.Structure) layout)
					.getComponentAt(0).getDataType().getDisplayName());
		boolean structureLocal = false;
		boolean elementArrayLocal = false;
		for (Variable local : localCaller.getLocalVariables()) {
			structureLocal |= local.getDataType().isEquivalent(layout);
			if (local.getDataType() instanceof ghidra.program.model.data.Array array) {
				elementArrayLocal |= array.getDataType().isEquivalent(element);
			}
		}
		check(structureLocal && elementArrayLocal,
			"concrete pointer parameters did not retype exact local stack objects");
		boolean sizedWordLocal = false;
		for (Variable local : sizedLocalCaller.getLocalVariables()) {
			sizedWordLocal |=
				local.getDataType() instanceof ghidra.program.model.data.AbstractIntegerDataType integer &&
					!integer.isSigned() && integer.getLength() == 2;
		}
		check(sizedWordLocal,
			"width-specific undefined pointee did not create a stable two-byte word");

		println("TASKING exact returned-layout aliases passed.");
	}

	private Function fixture(String name, byte[] code) throws Exception {
		Address entry = toAddr(nextAddress);
		nextAddress += 0x100;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		return createFunction(entry, name);
	}

	private void setAnalysisPointer(Function function, DataType parameter,
			DataType returned) throws Exception {
		setAnalysisSignature(function, List.of(parameter), returned);
	}

	private void setAnalysisSignature(Function function, List<DataType> parameterTypes,
			DataType returned) throws Exception {
		List<ParameterImpl> parameters = new java.util.ArrayList<>();
		for (DataType type : parameterTypes) {
			parameters.add(new ParameterImpl(null, type, currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null,
			parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		function.setReturnType(returned, SourceType.ANALYSIS);
	}

	private boolean hasTarget(DataType type, DataType target) {
		return type instanceof Pointer pointer &&
			pointer.getDataType().isEquivalent(target);
	}

	private byte[] callInstruction(Function target) {
		long address = target.getEntryPoint().getOffset();
		return bytes(0xda, (int) (address >> 16), (int) address, (int) (address >> 8));
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int index = 0; index < values.length; index++) {
			result[index] = (byte) values[index];
		}
		return result;
	}

	private byte[] concat(byte[]... parts) {
		int length = 0;
		for (byte[] part : parts) {
			length += part.length;
		}
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
