// Headless regression test; run via tools/test-tasking-abi.sh.
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166CodePointerPhase;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166PointerReturnPhase;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166CodePointerInferenceTest extends GhidraScript {

	private long nextFixture = 0x180000;

	@Override
	protected void run() throws Exception {
		useDevelopmentDecompilerIfRequested();
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"wrong compiler spec");

		Function mallocTarget = functionAt(0x253d0e, "code_pointer_malloc_target");
		Function freeTarget = functionAt(0x253d7c, "code_pointer_free_target");
		Function overlapFirstTarget = functionAt(0x263d0e, "overlap_first_target");
		Function overlapSecondTarget = functionAt(0x270026, "overlap_second_target");
		check(mallocTarget != null && freeTarget != null,
			"failed to create code-pointer targets");

		Function twoCallbacks = fixture("two_code_pointer_parameters", bytes(0xdb, 0x00));
		Function twoCallbacksCaller = fixture("two_code_pointer_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			codePointerSetup(14, 15, freeTarget.getEntryPoint()),
			calls(twoCallbacks), bytes(0xdb, 0x00)));
		Function twoCallbacksCaller2 = fixture("two_code_pointer_caller_2", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			codePointerSetup(14, 15, freeTarget.getEntryPoint()),
			calls(twoCallbacks), bytes(0xdb, 0x00)));

		// A real function-pointer typedef must retain SEGMENT:OFFSET semantics.
		// PAGE:OFFSET would turn 0x25:0x3d0e into the wrong address 0x097d0e.
		Address wrongPagedAddress = toAddr(0x097d0e);
		createMemoryBlock("wrong_paged_code_pointer_bytes", wrongPagedAddress,
			bytes(0x00), false);
		createLabel(wrongPagedAddress, "wrong_paged_code_pointer_target", true);
		Function typedCallback = fixture("typed_code_pointer_parameter", bytes(0xdb, 0x00));
		setUserFunctionPointer(typedCallback, "malloc_cb", "malloc_cb_t");
		Function typedCallbackCaller = fixture("typed_code_pointer_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			calls(typedCallback), bytes(0xdb, 0x00)));

		// A neighbouring PAGE:OFFSET pair must remain a data pointer even when
		// another parameter at the same call site is a proven code pointer.
		Function mixed = fixture("mixed_code_and_data_parameters", pagedRead(15, 14));
		setAnalysisWords(mixed, "malloc_offset", "malloc_segment", "data_offset", "data_page");
		Function mixedCaller = fixture("mixed_code_and_data_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			bytes(
				0xe6, 0xfe, 0x00, 0x10, // R14 = data OFFSET
				0xe6, 0xff, 0x02, 0x00), // R15 = data PAGE; 0x021000 is not a function
			calls(mixed), bytes(0xdb, 0x00)));

		// Once all register argument slots are occupied, a pushed low/high pair is
		// the next four-byte stack parameter.
		Function stackCallback = fixture("stack_code_pointer_parameter", bytes(0xdb, 0x00));
		Function stackCaller = fixture("stack_code_pointer_caller", concat(
			bytes(
				0xf0, 0xc8, // R12 = unknown R8
				0xf0, 0xd9, // R13 = unknown R9
				0xf0, 0xea, // R14 = unknown R10
				0xf0, 0xfb), // R15 = unknown R11
			codePointerSetup(6, 7, freeTarget.getEntryPoint()),
			bytes(0x88, 0x70, 0x88, 0x60), // push SEGMENT high, then OFFSET low
			calls(stackCallback),
			bytes(0x06, 0xf0, 0x04, 0x00, 0xdb, 0x00)));

		Function copiedCallback = fixture("copied_code_pointer_parameter", bytes(0xdb, 0x00));
		Function copiedCallbackCaller = fixture("copied_code_pointer_caller", concat(
			codePointerSetup(6, 7, mallocTarget.getEntryPoint()),
			bytes(0xf0, 0xc6, 0xf0, 0xd7), // R13:R12 = R7:R6
			calls(copiedCallback), bytes(0xdb, 0x00)));

		// Mirrors FUN_242066's two callback pairs on the stack: arguments are
		// pushed right-to-left, with each pair itself pushed high then low.
		Function twoStackCallbacks = fixture("two_stack_code_pointer_parameters",
			bytes(0xdb, 0x00));
		Function twoStackCallbacksCaller = fixture("two_stack_code_pointer_caller", concat(
			codePointerSetup(8, 9, freeTarget.getEntryPoint()),
			bytes(0x88, 0x90, 0x88, 0x80),
			codePointerSetup(6, 7, mallocTarget.getEntryPoint()),
			bytes(0x88, 0x70, 0x88, 0x60),
			bytes(0xf0, 0xc1, 0xf0, 0xd2, 0xf0, 0xe3, 0xf0, 0xf4),
			calls(twoStackCallbacks),
			bytes(0x06, 0xf0, 0x08, 0x00, 0xdb, 0x00)));

		// R13:R12 and R14:R13 can both name valid functions.  Equal overlapping
		// evidence has no unique ABI layout and must therefore remain untouched.
		Function ambiguousOverlap = fixture("ambiguous_code_pointer_overlap",
			bytes(0xdb, 0x00));
		Function ambiguousOverlapCaller = fixture("ambiguous_code_pointer_overlap_caller",
			concat(
				bytes(
					0xe6, 0xfc, 0x0e, 0x3d,
					0xe6, 0xfd, 0x26, 0x00,
					0xe6, 0xfe, 0x27, 0x00),
				calls(ambiguousOverlap), bytes(0xdb, 0x00)));

		// Executable bytes which are not a function entry are not code-pointer
		// evidence.
		Function nonEntry = fixture("non_entry_code_constant", bytes(0xdb, 0x00));
		Function nonEntryCaller = fixture("non_entry_code_constant_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint().add(1)),
			calls(nonEntry), bytes(0xdb, 0x00)));

		// Four SEGMENT:OFFSET constants may each name an exact function entry and
		// still be two scalar parameters.  A complete 2x2 combination proves that
		// OFFSET and SEGMENT vary independently.  Reject fresh inference and repair
		// stale generic ANALYSIS pointers from an older pass.  Carry that scalar
		// proof through a first-instruction forwarding call so a stale target type
		// cannot feed circular fpointer evidence back into the wrapper.
		Function grid00 = functionAt(0x281000, "scalar_grid_00");
		Function grid01 = functionAt(0x291000, "scalar_grid_01");
		Function grid10 = functionAt(0x281100, "scalar_grid_10");
		Function grid11 = functionAt(0x291100, "scalar_grid_11");
		Function rectangleForwardingTarget = fixture(
			"exact_entry_rectangle_forwarding_target", bytes(0xdb, 0x00));
		setLegacyGenericFunctionPointers(rectangleForwardingTarget, "misclassified");
		Function rectangleScalar = fixture("exact_entry_rectangle_is_two_scalars",
			concat(calls(rectangleForwardingTarget), bytes(0xdb, 0x00)));
		setAnalysisPointer(rectangleScalar, "misclassified");
		Function staleRectangleFunctionPointer = fixture(
			"repair_stale_rectangle_function_pointer", bytes(0xdb, 0x00));
		setLegacyGenericFunctionPointers(staleRectangleFunctionPointer, "misclassified");
		Function orphanStaleFunctionPointer = fixture(
			"repair_orphan_stale_function_pointer", bytes(0xdb, 0x00));
		setLegacyGenericFunctionPointers(orphanStaleFunctionPointer, "misclassified");
		List<Function> rectangleCallers = new ArrayList<>();
		for (Function gridTarget : List.of(grid00, grid01, grid10, grid11)) {
			rectangleCallers.add(fixture("exact_entry_rectangle_caller_" +
				gridTarget.getName(), concat(
				codePointerSetup(12, 13, gridTarget.getEntryPoint()),
				calls(rectangleScalar),
				codePointerSetup(12, 13, gridTarget.getEntryPoint()),
				calls(staleRectangleFunctionPointer), bytes(0xdb, 0x00))));
		}

		Function userDefined = fixture("user_defined_code_words", bytes(0xdb, 0x00));
		setUserWords(userDefined, "offset", "segment");
		Function userDefinedCaller = fixture("user_defined_code_words_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			calls(userDefined), bytes(0xdb, 0x00)));

		// Proven or pre-existing data-pointer semantics take precedence even if a
		// particular constant also names executable code under SEGMENT:OFFSET.
		Function existingDataPointer = fixture("existing_data_pointer", bytes(0xdb, 0x00));
		setAnalysisPointer(existingDataPointer, "data_pointer");
		Function existingDataPointerCaller = fixture("existing_data_pointer_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			calls(existingDataPointer), bytes(0xdb, 0x00)));

		// One exact function-entry constant supports the callee's local fpointer,
		// but is not a strong enough root for backwards propagation.  The same
		// slot may receive ordinary data from a wrapper; propagating the one-off
		// collision would incorrectly turn the wrapper's data pointer into code.
		Function singleExactTarget = fixture("single_exact_entry_target",
			bytes(0xdb, 0x00));
		Function singleExactTargetCaller = fixture("single_exact_entry_target_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			calls(singleExactTarget), bytes(0xdb, 0x00)));
		Function singleExactDataWrapper = fixture("single_exact_data_wrapper",
			concat(calls(singleExactTarget), bytes(0xdb, 0x00)));
		setAnalysisPointer(singleExactDataWrapper, "object");

		// Direct paged dereference is stronger semantic evidence than a constant
		// which merely happens to name a function entry.  It must repair a stale
		// generic fpointer and later code-pointer passes must not restore it.
		Function dataWins = fixture("paged_use_overrides_code_constant", pagedRead(13, 12));
		Function dataWinsCaller = fixture("paged_use_overrides_code_constant_caller", concat(
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			calls(dataWins), bytes(0xdb, 0x00)));

		// A carry-coupled R13:R12 value is one 32-bit scalar.  Propagate that
		// evidence backwards through a wrapper and replace a stale generic
		// function pointer without splitting the ABI storage into two words.
		Function packedArithmetic = fixture("packed_scalar_carry_arithmetic", bytes(
			0x26, 0xfc, 0x34, 0x12,       // sub R12,#0x1234
			0x36, 0xfd, 0x00, 0x00,       // subc R13,#0
			0xdb, 0x00));
		Function packedForwardingWrapper = fixture("packed_scalar_forwarding_wrapper",
			concat(
				bytes(0x2d, 0x00), // validation branch to the forwarding call
				calls(packedArithmetic), bytes(0xdb, 0x00)));
		setLegacyGenericFunctionPointers(packedForwardingWrapper, "size");
		Function packedForwardingCaller = fixture("packed_scalar_forwarding_caller", concat(
			bytes(0xe6, 0xfc, 0x40, 0x00, 0xe6, 0xfd, 0x00, 0x00),
			calls(packedForwardingWrapper), bytes(0xdb, 0x00)));
		Function packedNarrowingTarget = fixture("packed_scalar_narrowing_target",
			bytes(0xdb, 0x00));
		setUserWords(packedNarrowingTarget, "length");
		Function packedNarrowingWrapper = fixture("packed_scalar_narrowing_wrapper",
			concat(calls(packedNarrowingTarget), bytes(0xdb, 0x00)));
		setLegacyGenericFunctionPointers(packedNarrowingWrapper, "wide_length");
		Function packedNarrowingCaller = fixture("packed_scalar_narrowing_caller", concat(
			bytes(0xe6, 0xfc, 0x10, 0x00, 0xe6, 0xfd, 0x00, 0x00),
			calls(packedNarrowingWrapper), bytes(0xdb, 0x00)));

		// TASKING 3.6: after three word parameters, a four-byte value cannot fit
		// in R15 and spills whole.  Reproduce the stale signature previously seen
		// on FUN_26cee4: a synthetic R15 word followed by two stack fpointers.
		// Each stack slot receives both an exact function entry and a non-code
		// scalar.  The repaired signature must be three words plus two undefined4
		// stack values, with no invented R15 parameter.
		Function packedStackSpill = fixture("packed_scalar_stack_spill", bytes(
			0xd4, 0x40, 0x04, 0x00,       // R4 = Stack[4] low
			0xd4, 0x50, 0x06, 0x00,       // R5 = Stack[6] high
			0x26, 0xf4, 0x01, 0x00,       // sub R4,#1
			0x36, 0xf5, 0x00, 0x00,       // subc R5,#0
			0xdb, 0x00));
		setAnalysisWordsAndLegacyFunctionPointers(packedStackSpill,
			new String[] { "word0", "word1", "word2", "spill_hole" },
			new String[] { "value0", "value1" });
		Function packedStackExactCaller = fixture("packed_scalar_stack_exact_caller", concat(
			codePointerSetup(8, 9, freeTarget.getEntryPoint()),
			bytes(0x88, 0x90, 0x88, 0x80),
			codePointerSetup(6, 7, mallocTarget.getEntryPoint()),
			bytes(0x88, 0x70, 0x88, 0x60, 0xf0, 0xf7),
			bytes(0xe6, 0xfc, 0x01, 0x00, 0xe6, 0xfd, 0x02, 0x00,
				0xe6, 0xfe, 0x03, 0x00),
			calls(packedStackSpill),
			bytes(0x06, 0xf0, 0x08, 0x00, 0xdb, 0x00)));
		Function packedStackScalarCaller = fixture("packed_scalar_stack_value_caller", concat(
			bytes(
				0xe6, 0xf8, 0x10, 0x00, 0xe6, 0xf9, 0x00, 0x00,
				0x88, 0x90, 0x88, 0x80,
				0xe6, 0xf6, 0x04, 0x00, 0xe6, 0xf7, 0x00, 0x00,
				0x88, 0x70, 0x88, 0x60, 0xf0, 0xf7,
				0xe6, 0xfc, 0x01, 0x00, 0xe6, 0xfd, 0x02, 0x00,
				0xe6, 0xfe, 0x03, 0x00),
			calls(packedStackSpill),
			bytes(0x06, 0xf0, 0x08, 0x00, 0xdb, 0x00)));

		// A far indirect dispatcher consumes only R5:R4 as the target.  Values in
		// R12-R15 are ordinary arguments of the runtime target and cannot type the
		// dispatcher's own prototype, even if they happen to name code.
		Function dispatcher = fixture("far_indirect_dispatcher_shape",
			bytes(0xec, 0xf5, 0xec, 0xf4, 0xdb, 0x00));
		setAnalysisWords(dispatcher, "stale0", "stale1", "stale2");
		Function dispatcherCaller = fixture("far_indirect_dispatcher_caller", concat(
			codePointerSetup(4, 5, freeTarget.getEntryPoint()),
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			calls(dispatcher), bytes(0xdb, 0x00)));
		Function indirectTarget = fixture("parameter_used_as_far_indirect_target", concat(
			bytes(0xf0, 0x4c, 0xf0, 0x5d), // R5:R4 = R13:R12
			calls(dispatcher), bytes(0xdb, 0x00)));
		Function middleIndirectTarget = fixture("middle_parameter_used_as_far_indirect_target",
			concat(
				bytes(0xf0, 0x4d, 0xf0, 0x5e), // R5:R4 = R14:R13
				calls(dispatcher), bytes(0xdb, 0x00)));
		Function lateIndirectTarget = fixture("late_parameter_used_as_far_indirect_target",
			concat(
				bytes(0xf0, 0x4e, 0xf0, 0x5f), // R5:R4 = R15:R14
				calls(dispatcher), bytes(0xdb, 0x00)));
		Function reversedIndirectTarget = fixture("reversed_words_are_not_indirect_target",
			concat(
				bytes(0xf0, 0x4d, 0xf0, 0x5c), // reversed R12:R13
				calls(dispatcher), bytes(0xdb, 0x00)));
		Function savedIndirectTarget = fixture("saved_parameter_used_as_far_indirect_target",
			concat(
				bytes(
					0x88, 0xc0,                         // push R12
					0x88, 0xd0,                         // push R13
					0xd4, 0x50, 0x00, 0x00,             // R5 = [SP]
					0xd4, 0x40, 0x02, 0x00),            // R4 = [SP+2]
				calls(dispatcher),
				bytes(0x06, 0xf0, 0x04, 0x00, 0xdb, 0x00)));
		// Real TASKING code often validates first, then saves the incoming callback
		// in a new basic block before loading R5:R4.  The semantic tracer must cross
		// that predecessor boundary without allowing ordinary constant inference to
		// do the same.
		Function branchSavedIndirectTarget = fixture(
			"branch_saved_parameter_used_as_far_indirect_target", concat(
				bytes(
					0x2d, 0x00,                         // conditional branch to the push
					0x88, 0xc0,                         // push R12
					0x88, 0xd0,                         // push R13
					0xd4, 0x50, 0x00, 0x00,             // R5 = [SP]
					0xd4, 0x40, 0x02, 0x00),            // R4 = [SP+2]
				calls(dispatcher),
				bytes(0x06, 0xf0, 0x04, 0x00, 0xdb, 0x00)));
		Function semanticInterveningCall = fixture(
			"callee_saved_callback_intervening_call", bytes(0xdb, 0x00));
		Function calleeSavedIndirectTarget = fixture(
			"callee_saved_parameter_used_as_far_indirect_target", concat(
				bytes(
					0xf0, 0x8e,                         // R8 = R14
					0xf0, 0x9f,                         // R9 = R15
					0x2d, 0x00),                        // validation branch
				calls(semanticInterveningCall),
				bytes(
					0xf0, 0x48,                         // R4 = R8
					0xf0, 0x59),                        // R5 = R9
				calls(dispatcher), bytes(0xdb, 0x00)));
		// Semantic use as R5:R4 is stronger than a generic ANALYSIS void *.  This
		// reproduces FUN_2590ce after the earlier far-data pass typed its callback
		// parameter as data.
		Function analysisPointerIndirectTarget = fixture(
			"analysis_pointer_used_as_far_indirect_target", concat(
				pagedAccess(13, 12),
				bytes(0xf0, 0x4c, 0xf0, 0x5d),
				calls(dispatcher), bytes(0xdb, 0x00)));
		setAnalysisPointer(analysisPointerIndirectTarget, "callback");
		// FunctionDB delegates updateFunction() on a thunk to its target.  A full
		// cleanup pass must therefore skip the thunk: it has no local evidence map,
		// but splitting its inherited fpointer would silently split the proven
		// callback on the target (the real shape is FUN_92c0c6 -> FUN_9057dc).
		Function analysisPointerIndirectThunk = fixture(
			"analysis_pointer_indirect_target_thunk", bytes(0xdb, 0x00));
		analysisPointerIndirectThunk.setThunkedFunction(analysisPointerIndirectTarget);

		// Function-pointer types must propagate backwards through wrappers to a
		// fixed point.  The second wrapper needs a later pass after the first one is
		// repaired, matching FUN_9bb936 -> FUN_25901a -> FUN_2590ce.
		Function forwardingTarget = fixture("typed_function_pointer_target",
			bytes(0xdb, 0x00));
		setUserFunctionPointer(forwardingTarget, "callback", "forwarded_cb_t");
		Function forwardingWrapper = fixture("analysis_pointer_forwarding_wrapper",
			concat(calls(forwardingTarget), bytes(0xdb, 0x00)));
		setAnalysisPointer(forwardingWrapper, "callback");
		Function secondLevelForwardingWrapper = fixture(
			"second_level_analysis_pointer_forwarding_wrapper",
			concat(calls(forwardingWrapper), bytes(0xdb, 0x00)));
		setAnalysisPointer(secondLevelForwardingWrapper, "callback");
		Function stackForwardingTarget = fixture("typed_stack_forwarding_target",
			bytes(0xdb, 0x00));
		setUserWordsAndFunctionPointer(stackForwardingTarget);
		Function stackForwardingInterveningCall = fixture(
			"stack_forwarding_intervening_call", bytes(0xdb, 0x00));
		Function stackForwardingWrapper = fixture("stack_parameter_forwarding_wrapper",
			concat(
				bytes(
					0x88, 0x90, 0x88, 0x80, 0x88, 0x70, 0x88, 0x60,
					0x88, 0xe0, 0x88, 0xf0),
				calls(stackForwardingInterveningCall),
				bytes(
					0xd4, 0xe0, 0x0c, 0x00,
					0xd4, 0xf0, 0x0e, 0x00),
				calls(stackForwardingTarget),
				bytes(0x06, 0xf0, 0x0c, 0x00, 0xdb, 0x00)));
		setAnalysisWordsAndPointer(stackForwardingWrapper);

		// An incoming branch makes the call a new basic block.  Constants from the
		// fall-through predecessor are not valid on every path and must not count.
		Function branchMerge = fixture("branch_merge_is_not_constant", bytes(0xdb, 0x00));
		Function branchMergeCaller = fixture("branch_merge_is_not_constant_caller", concat(
			bytes(0x2d, 0x05), // jmpr cc_EQ to the call, bypassing the setup
			codePointerSetup(12, 13, mallocTarget.getEntryPoint()),
			bytes(0xcc, 0x00),
			calls(branchMerge), bytes(0xdb, 0x00)));

		// Old pushes separated from the call by an explicit stack reset are not
		// current stack arguments.
		Function stalePush = fixture("stale_push_is_not_argument", bytes(0xdb, 0x00));
		setAnalysisWords(stalePush, "word0", "word1", "word2", "word3");
		Function stalePushCaller = fixture("stale_push_is_not_argument_caller", concat(
			codePointerSetup(6, 7, mallocTarget.getEntryPoint()),
			bytes(0x88, 0x70, 0x88, 0x60, 0x06, 0xf0, 0x04, 0x00),
			bytes(0xf0, 0xc8, 0xf0, 0xd9, 0xf0, 0xea, 0xf0, 0xfb),
			calls(stalePush), bytes(0xdb, 0x00)));

		// An outer stack argument may be pushed before a complete nested call
		// frame.  The nested cleanup must cancel only the nested push; the outer
		// target's immediate cleanup then proves exactly one missing fixed word.
		Function nestedSetupCall = fixture("nested_stack_setup_call", bytes(0xdb, 0x00));
		Function nestedFixedStack = fixture("nested_call_fixed_stack_parameter",
			bytes(0xdb, 0x00));
		setAnalysisWords(nestedFixedStack, "word0", "word1", "word2", "word3");
		Function nestedFixedStackCaller = fixture(
			"nested_call_fixed_stack_parameter_caller", concat(
				bytes(
					0xe6, 0xf6, 0x2c, 0x05, // outer line word
					0x88, 0x60,             // push outer word
					0xe6, 0xf7, 0x99, 0x00, // nested word
					0x88, 0x70),            // push nested word
				calls(nestedSetupCall),
				bytes(
					0x06, 0xf0, 0x02, 0x00, // pop nested frame only
					0xe6, 0xfc, 0x01, 0x00,
					0xe6, 0xfd, 0x02, 0x00,
					0xe6, 0xfe, 0x03, 0x00,
					0xe6, 0xff, 0x04, 0x00),
				calls(nestedFixedStack),
				bytes(0x06, 0xf0, 0x02, 0x00, 0xdb, 0x00)));

		// Exact cleanup alone is insufficient after an unknown R0 mutation.  The
		// analyzer must leave the target at its original four register words.
		Function unknownStackMutation = fixture("unknown_stack_mutation_target",
			bytes(0xdb, 0x00));
		setAnalysisWords(unknownStackMutation, "word0", "word1", "word2", "word3");
		Function unknownStackMutationCaller = fixture(
			"unknown_stack_mutation_target_caller", concat(
				bytes(
					0xe6, 0xf6, 0x2c, 0x05,
					0x88, 0x60,
					0xf0, 0x01,             // mov R0,R1: unknown stack reset
					0xe6, 0xfc, 0x01, 0x00,
					0xe6, 0xfd, 0x02, 0x00,
					0xe6, 0xfe, 0x03, 0x00,
					0xe6, 0xff, 0x04, 0x00),
				calls(unknownStackMutation),
				bytes(0x06, 0xf0, 0x02, 0x00, 0xdb, 0x00)));

		// Table 3-15 returns a far pointer in R5:R4.  Two downstream data-pointer
		// uses are sufficient evidence; an integer consumer is not, and an actual
		// far-indirect use conflicts with data-pointer inference.
		Function returnDataConsumer = fixture("return_data_pointer_consumer",
			bytes(0xdb, 0x00));
		setUserDataPointer(returnDataConsumer, "object");
		Function dataReturn = fixture("two_uses_prove_data_pointer_return",
			bytes(0xdb, 0x00));
		Function dataReturnCaller = fixture("two_uses_prove_data_pointer_return_caller",
			concat(calls(dataReturn), bytes(
				0xf0, 0x84, 0xf0, 0x95, // R8:R9 = returned R4:R5
				0xf0, 0xc8, 0xf0, 0xd9),
				calls(returnDataConsumer), bytes(0xf0, 0xc8, 0xf0, 0xd9),
				calls(returnDataConsumer), bytes(0xdb, 0x00)));
		Function directPagedReturn = fixture("paged_use_proves_data_pointer_return",
			bytes(0xdb, 0x00));
		Function directPagedReturnCaller = fixture(
			"paged_use_proves_data_pointer_return_caller",
			concat(calls(directPagedReturn),
				bytes(0xf0, 0x64, 0xf0, 0x75), // R6:R7 = returned R4:R5
				pagedRead(7, 6)));
		Function scalarReturnConsumer = fixture("scalar_return_consumer", bytes(0xdb, 0x00));
		setUserWords(scalarReturnConsumer, "low", "high");
		Function scalarReturn = fixture("scalar_r5_r4_return", bytes(0xdb, 0x00));
		Function scalarReturnCaller = fixture("scalar_r5_r4_return_caller", concat(
			calls(scalarReturn), calls(scalarReturnConsumer), bytes(0xdb, 0x00)));
		Function scalar32ReturnConsumer = fixture("scalar32_return_consumer",
			bytes(0xdb, 0x00));
		setUserDword(scalar32ReturnConsumer, "value");
		Function explicitScalar32Return = fixture("explicit_scalar32_r5_r4_return",
			bytes(
				0xe6, 0xf4, 0x01, 0x00, // R4 = low word
				0xe6, 0xf5, 0x00, 0x00, // R5 = high word
				0xdb, 0x00));
		setAnalysisDataPointerReturn(explicitScalar32Return);
		Function explicitScalar32ReturnCaller = fixture(
			"explicit_scalar32_r5_r4_return_caller", concat(
				calls(explicitScalar32Return), bytes(
					0xf0, 0xc4,             // R12 = returned R4
					0xf0, 0xd5),            // R13 = returned R5
				calls(scalar32ReturnConsumer), bytes(0xdb, 0x00)));
		Function analysisGenericDataConsumer = fixture(
			"analysis_generic_data_pointer_consumer", bytes(0xdb, 0x00));
		setAnalysisPointer(analysisGenericDataConsumer, "value");
		Function unsignedLongRuntime = fixture("tasking_unsigned_long_multiply",
			bytes(0xdb, 0x00));
		unsignedLongRuntime.setCallFixup("c166_tasking_mulu4");
		Function runtimeScalarReturn = fixture("runtime_scalar_r5_r4_return", bytes(
			0xe6, 0xf4, 0x01, 0x00,
			0xe6, 0xf5, 0x00, 0x00,
			0xdb, 0x00));
		setAnalysisDataPointerReturn(runtimeScalarReturn);
		Function runtimeScalarReturnCaller = fixture(
			"runtime_scalar_r5_r4_return_caller", concat(
				calls(runtimeScalarReturn), bytes(
					0xf0, 0x84,             // preserve returned low word in R8
					0xf0, 0x95,             // preserve returned high word in R9
					0xf0, 0xc8,             // R12 = returned low word
					0xf0, 0xd9),            // R13 = returned high word
				calls(analysisGenericDataConsumer), bytes(
					0xf0, 0x48,             // unsigned helper left low word
					0xf0, 0x59,             // unsigned helper left high word
					0xe6, 0xfa, 0x0c, 0x00, // right operand = 12
					0xe6, 0xfb, 0x00, 0x00),
				calls(unsignedLongRuntime), bytes(0xdb, 0x00)));
		Function explicitSingleUseDataReturn = fixture(
			"explicit_single_use_data_pointer_return", bytes(
				0xe6, 0xf4, 0x00, 0x10,
				0xe6, 0xf5, 0x02, 0x00,
				0xdb, 0x00));
		explicitSingleUseDataReturn.setReturnType(Undefined.getUndefinedDataType(4),
			SourceType.ANALYSIS);
		Function explicitSingleUseDataReturnCaller = fixture(
			"explicit_single_use_data_pointer_return_caller", concat(
				calls(explicitSingleUseDataReturn), bytes(
					0xf0, 0xc4, 0xf0, 0xd5),
				calls(returnDataConsumer), bytes(0xdb, 0x00)));
		Function explicitCodeReturn = fixture("explicit_function_pointer_return", bytes(
			0xe6, 0xf4, 0x0e, 0x3d,
			0xe6, 0xf5, 0x25, 0x00,
			0xdb, 0x00));
		setAnalysisDataPointerReturn(explicitCodeReturn);
		Function explicitCodeReturnCaller = fixture(
			"explicit_function_pointer_return_caller", concat(
				calls(explicitCodeReturn), calls(dispatcher), bytes(0xdb, 0x00)));
		Function conflictingReturn = fixture("conflicting_pointer_return", bytes(0xdb, 0x00));
		Function conflictingReturnCaller = fixture("conflicting_pointer_return_caller",
			concat(calls(conflictingReturn), bytes(
				0xf0, 0x84, 0xf0, 0x95,
				0xf0, 0xc8, 0xf0, 0xd9),
				calls(returnDataConsumer), bytes(
				0xf0, 0xc8, 0xf0, 0xd9),
				calls(returnDataConsumer), bytes(
				0xf0, 0x48, 0xf0, 0x59),
				calls(dispatcher), bytes(0xdb, 0x00)));

		// Explicitly defining only R4 is negative producer evidence.  Even two
		// typed four-byte consumers must not turn an unrelated caller extraout R5
		// into a real long/far-pointer return.
		Function partialScalarReturn = fixture("partial_r4_only_return", bytes(
			0xe6, 0xf4, 0x34, 0x12,
			0xdb, 0x00));
		Function partialScalarReturnCaller = fixture("partial_r4_only_return_caller", concat(
			calls(partialScalarReturn), bytes(
				0xf0, 0x84, 0xf0, 0x95,
				0xf0, 0xc8, 0xf0, 0xd9),
			calls(scalar32ReturnConsumer), bytes(0xf0, 0xc8, 0xf0, 0xd9),
			calls(scalar32ReturnConsumer), bytes(0xdb, 0x00)));

		// Strong downstream evidence never owns USER_DEFINED or IMPORTED return
		// declarations.  Preserve both signatures byte-for-byte under conflict.
		Function userDefinedReturn = fixture("user_defined_return_is_preserved", bytes(
			0xe6, 0xf4, 0x00, 0x10, 0xe6, 0xf5, 0x02, 0x00, 0xdb, 0x00));
		userDefinedReturn.setCallingConvention("__tasking_c166_classic");
		userDefinedReturn.setReturnType(new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager()), SourceType.USER_DEFINED);
		Function userDefinedReturnCaller = fixture("user_defined_return_is_preserved_caller",
			concat(calls(userDefinedReturn), bytes(0xf0, 0xc4, 0xf0, 0xd5),
				calls(scalar32ReturnConsumer), bytes(0xdb, 0x00)));
		Function importedReturn = fixture("imported_return_is_preserved", bytes(
			0xe6, 0xf4, 0x00, 0x10, 0xe6, 0xf5, 0x02, 0x00, 0xdb, 0x00));
		importedReturn.setCallingConvention("__tasking_c166_classic");
		importedReturn.setReturnType(new UnsignedLongDataType(
			currentProgram.getDataTypeManager()), SourceType.IMPORTED);
		Function importedReturnCaller = fixture("imported_return_is_preserved_caller",
			concat(calls(importedReturn), bytes(0xf0, 0xc4, 0xf0, 0xd5),
				calls(returnDataConsumer), bytes(0xdb, 0x00)));
		String protectedReturnSnapshot = snapshot(userDefinedReturn, importedReturn);

		C166TaskingRuntimeAnalyzer runtimeAnalyzer = new C166TaskingRuntimeAnalyzer();
		check(runtimeAnalyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "runtime analysis before code-pointer inference failed");
		check("call_far_indirect".equals(dispatcher.getCallFixup()),
			"far indirect dispatcher did not receive its call-fixup");
		check(dispatcher.getParameterCount() == 0,
			"far indirect dispatcher retained a stale analysis signature");
		C166CodePointerPhase analyzer = new C166CodePointerPhase();
		check(analyzer.added(currentProgram, twoCallbacksCaller.getBody(), monitor,
			new MessageLog()), "incremental code-pointer analysis failed");
		checkCodeSignature(twoCallbacks, "r13+r12", "r15+r14");
		check(mixed.getParameterCount() == 4,
			"incremental scan touched an unrelated target");
		check(analyzer.added(currentProgram, dataWinsCaller.getBody(), monitor,
			new MessageLog()), "code-first conflict setup failed");
		checkCodeSignature(dataWins, "r13+r12");

		AddressSet pagedBodies = new AddressSet(mixed.getBody());
		pagedBodies.add(dataWins.getBody());
		check(new C166FarPointerPhase().added(currentProgram, pagedBodies, monitor,
			new MessageLog()), "semantic far-data analysis failed");
		checkDataPointer(dataWins, "r13+r12");

		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "full code-pointer One Shot failed");
		checkWordSignature(rectangleScalar, SourceType.ANALYSIS, "r12", "r13");
		checkWordSignature(rectangleForwardingTarget, SourceType.ANALYSIS, "r12", "r13");
		checkWordSignature(staleRectangleFunctionPointer, SourceType.ANALYSIS,
			"r12", "r13");
		checkWordSignature(orphanStaleFunctionPointer, SourceType.ANALYSIS,
			"r12", "r13");
		checkSemanticCodeEvidence(analysisPointerIndirectTarget, 0);
		checkSemanticCodeEvidence(branchSavedIndirectTarget, 0);
		checkSemanticCodeEvidence(calleeSavedIndirectTarget, 2);
		checkCodeSignature(analysisPointerIndirectTarget, "r13+r12");
		check(analysisPointerIndirectThunk.isThunk() &&
			analysisPointerIndirectThunk.getThunkedFunction(true).getEntryPoint().equals(
				analysisPointerIndirectTarget.getEntryPoint()),
			"callback thunk no longer targets the semantic callback function");
		// A later full far-data One Shot must not use the recovered callback type
		// itself as data evidence.  This is the real GUI ordering which previously
		// changed FUN_9b0678(fpointer, ...) back to void *.
		check(new C166FarPointerPhase().added(currentProgram,
			currentProgram.getMemory(), monitor, new MessageLog()),
			"far-data analysis after code-pointer inference failed");
		checkWordSignature(rectangleScalar, SourceType.ANALYSIS, "r12", "r13");
		checkWordSignature(rectangleForwardingTarget, SourceType.ANALYSIS, "r12", "r13");
		checkWordSignature(staleRectangleFunctionPointer, SourceType.ANALYSIS,
			"r12", "r13");
		checkCodeSignature(twoCallbacks, "r13+r12", "r15+r14");
		checkMixedSignature(mixed);
		checkDataPointer(dataWins, "r13+r12");
		checkPackedScalar(packedForwardingWrapper, "r13+r12");
		checkPackedScalar(packedNarrowingWrapper, "r13+r12");
		checkPackedStackScalars(packedStackSpill);
		checkCodeSignature(stackCallback, "r12", "r13", "r14", "r15", "Stack[0x0]:4");
		checkCodeSignature(copiedCallback, "r13+r12");
		checkCodeSignature(twoStackCallbacks, "r12", "r13", "r14", "r15",
			"Stack[0x0]:4", "Stack[0x4]:4");
		check(ambiguousOverlap.getParameterCount() == 0,
			"equal overlapping code-pointer evidence was accepted");
		check(nonEntry.getParameterCount() == 0,
			"non-entry executable address was inferred as a code pointer");
		checkWordSignature(userDefined, SourceType.USER_DEFINED, "r12", "r13");
		check(existingDataPointer.getParameterCount() == 1 &&
			existingDataPointer.getParameter(0).getFormalDataType() instanceof Pointer &&
			!isFunctionPointer(existingDataPointer.getParameter(0).getFormalDataType()),
			"existing data pointer was replaced by a function pointer");
		checkCodeSignature(singleExactTarget, "r13+r12");
		checkDataPointer(singleExactDataWrapper, "r13+r12");
		check(dispatcher.getParameterCount() == 0,
			"far indirect dispatcher's ordinary arguments were typed as callbacks");
		checkCodeSignature(indirectTarget, "r13+r12");
		checkCodeSignature(middleIndirectTarget, "r12", "r14+r13");
		checkCodeSignature(lateIndirectTarget, "r12", "r13", "r15+r14");
		checkCodeSignature(savedIndirectTarget, "r13+r12");
		checkCodeSignature(branchSavedIndirectTarget, "r13+r12");
		checkCodeSignature(calleeSavedIndirectTarget, "r12", "r13", "r15+r14");
		checkCodeSignature(analysisPointerIndirectTarget, "r13+r12");
		checkCodeSignature(forwardingWrapper, "r13+r12");
		checkCodeSignature(secondLevelForwardingWrapper, "r13+r12");
		checkCodeSignature(stackForwardingWrapper, "r12", "r13", "r14", "r15",
			"Stack[0x0]:4");
		check(reversedIndirectTarget.getParameterCount() == 0,
			"reversed far-indirect target words were accepted");
		check(branchMerge.getParameterCount() == 0,
			"path-dependent constants crossed a basic-block boundary");
		checkWordSignature(stalePush, SourceType.ANALYSIS, "r12", "r13", "r14", "r15");
		checkWordSignature(nestedFixedStack, SourceType.ANALYSIS,
			"r12", "r13", "r14", "r15", "Stack[0x0]:2");
		checkWordSignature(unknownStackMutation, SourceType.ANALYSIS,
			"r12", "r13", "r14", "r15");
		checkParamReference(twoCallbacksCaller.getEntryPoint().add(4),
			mallocTarget.getEntryPoint(), true);
		checkParamReference(twoCallbacksCaller.getEntryPoint().add(12),
			freeTarget.getEntryPoint(), true);
		checkParamReference(dataWinsCaller.getEntryPoint().add(4),
			mallocTarget.getEntryPoint(), false);
		checkParamReference(dispatcherCaller.getEntryPoint().add(12),
			mallocTarget.getEntryPoint(), false);
		checkParamReference(branchMergeCaller.getEntryPoint().add(6),
			mallocTarget.getEntryPoint(), false);
		checkTypedSignature(typedCallback, "malloc_cb_t");
		checkTypedCodePointer(typedCallbackCaller, mallocTarget, wrongPagedAddress);
		checkDecompilerConstants(twoCallbacksCaller, mallocTarget, freeTarget);

		// Migrate the raw generic Function Definition pointer emitted by the first
		// analyzer revision to the public pointer typedef without changing concrete
		// user callback typedefs.
		setLegacyGenericFunctionPointers(twoCallbacks, "callback0", "callback1");
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "legacy generic function-pointer migration failed");
		checkCodeSignature(twoCallbacks, "r13+r12", "r15+r14");

		// Migration from the old Far Pointer Inference bug.  Simulate the observed
		// database where both the callback type and old PARAM references are gone.
		// Repeated exact-function evidence may repair a generic ANALYSIS void *, but
		// the single-call existingDataPointer control above must remain data.
		setAnalysisPointer(twoCallbacks, "callback0", "callback1");
		removeParamReference(twoCallbacksCaller.getEntryPoint().add(4),
			mallocTarget.getEntryPoint());
		removeParamReference(twoCallbacksCaller.getEntryPoint().add(12),
			freeTarget.getEntryPoint());
		removeParamReference(twoCallbacksCaller2.getEntryPoint().add(4),
			mallocTarget.getEntryPoint());
		removeParamReference(twoCallbacksCaller2.getEntryPoint().add(12),
			freeTarget.getEntryPoint());
		currentProgram.getReferenceManager().addMemoryReference(
			twoCallbacksCaller.getEntryPoint().add(4), wrongPagedAddress, RefType.PARAM,
			SourceType.ANALYSIS, Reference.MNEMONIC);
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "legacy data-pointer corruption repair failed");
		checkCodeSignature(twoCallbacks, "r13+r12", "r15+r14");
		checkParamReference(twoCallbacksCaller.getEntryPoint().add(4),
			wrongPagedAddress, false);

		String snapshot = snapshot(twoCallbacks, mixed, stackCallback, copiedCallback,
			twoStackCallbacks, ambiguousOverlap, nonEntry, userDefined, existingDataPointer,
			singleExactTarget, singleExactDataWrapper, dataWins, dispatcher,
			packedForwardingWrapper, packedNarrowingWrapper, packedStackSpill,
			indirectTarget, middleIndirectTarget, lateIndirectTarget,
			reversedIndirectTarget, savedIndirectTarget, branchSavedIndirectTarget,
			calleeSavedIndirectTarget, analysisPointerIndirectTarget,
			forwardingWrapper, secondLevelForwardingWrapper, stackForwardingWrapper,
			branchMerge, stalePush, rectangleScalar, rectangleForwardingTarget,
			nestedFixedStack, unknownStackMutation, staleRectangleFunctionPointer,
			orphanStaleFunctionPointer);
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "second code-pointer analysis failed");
		String secondSnapshot = snapshot(twoCallbacks, mixed, stackCallback, copiedCallback,
			twoStackCallbacks, ambiguousOverlap, nonEntry, userDefined, existingDataPointer,
			singleExactTarget, singleExactDataWrapper, dataWins, dispatcher,
			packedForwardingWrapper, packedNarrowingWrapper, packedStackSpill,
			indirectTarget, middleIndirectTarget, lateIndirectTarget,
			reversedIndirectTarget, savedIndirectTarget, branchSavedIndirectTarget,
			calleeSavedIndirectTarget, analysisPointerIndirectTarget,
			forwardingWrapper, secondLevelForwardingWrapper, stackForwardingWrapper,
			branchMerge, stalePush, rectangleScalar, rectangleForwardingTarget,
			nestedFixedStack, unknownStackMutation, staleRectangleFunctionPointer,
			orphanStaleFunctionPointer);
		check(snapshot.equals(secondSnapshot),
			"code-pointer inference is not idempotent\nBEFORE:\n" + snapshot +
				"\nAFTER:\n" + secondSnapshot);

		C166PointerReturnPhase returnAnalyzer = new C166PointerReturnPhase();
		MessageLog returnLog = new MessageLog();
		check(returnAnalyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			returnLog), "far-pointer return inference failed");
		check(!returnLog.hasMessages(),
			"far-pointer return diagnostics leaked into the Analysis Log: " + returnLog);
		checkDataPointerReturn(dataReturn);
		checkDataPointerReturn(directPagedReturn);
		checkDataPointerReturn(explicitSingleUseDataReturn);
		checkScalarReturn(explicitScalar32Return);
		checkUnsignedLongReturn(runtimeScalarReturn);
		checkFunctionPointerReturn(explicitCodeReturn);
		check(partialScalarReturn.getReturnType().getLength() != 4,
			"partial R4-only producer was widened from caller extraout evidence");
		check(protectedReturnSnapshot.equals(snapshot(userDefinedReturn, importedReturn)),
			"USER_DEFINED or IMPORTED return signature changed");
		check(Undefined.isUndefined(scalarReturn.getReturnType()),
			"two-word scalar return was inferred as a pointer");
		check(Undefined.isUndefined(conflictingReturn.getReturnType()),
			"conflicting data/code return was inferred as a data pointer");
		String returnSnapshot = snapshot(dataReturn, directPagedReturn,
			explicitSingleUseDataReturn, explicitScalar32Return, runtimeScalarReturn,
			explicitCodeReturn,
			partialScalarReturn, userDefinedReturn, importedReturn,
			scalarReturn, conflictingReturn);
		MessageLog repeatedReturnLog = new MessageLog();
		check(returnAnalyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			repeatedReturnLog), "second far-pointer return inference failed");
		check(!repeatedReturnLog.hasMessages(),
			"repeated return diagnostics leaked into the Analysis Log: " +
				repeatedReturnLog);
		check(returnSnapshot.equals(snapshot(dataReturn, directPagedReturn,
			explicitSingleUseDataReturn, explicitScalar32Return, runtimeScalarReturn,
			explicitCodeReturn,
			partialScalarReturn, userDefinedReturn, importedReturn,
			scalarReturn, conflictingReturn)),
			"R5:R4 return classification is not idempotent");

		// Keep references live so fixture creation cannot be optimized away by a
		// future test refactor.
		check(twoCallbacksCaller != null && twoCallbacksCaller2 != null &&
			typedCallbackCaller != null && mixedCaller != null &&
			copiedCallbackCaller != null && twoStackCallbacksCaller != null &&
			ambiguousOverlapCaller != null && nonEntryCaller != null && userDefinedCaller != null &&
			existingDataPointerCaller != null && dataWinsCaller != null &&
			singleExactTargetCaller != null &&
			dispatcherCaller != null && forwardingTarget != null &&
			analysisPointerIndirectThunk != null &&
			semanticInterveningCall != null &&
			stackForwardingInterveningCall != null &&
			branchMergeCaller != null && stalePushCaller != null &&
			nestedFixedStackCaller != null && unknownStackMutationCaller != null &&
			packedForwardingCaller != null && packedNarrowingCaller != null &&
			packedStackExactCaller != null &&
			packedStackScalarCaller != null &&
			explicitScalar32ReturnCaller != null &&
			explicitSingleUseDataReturnCaller != null &&
			explicitCodeReturnCaller != null &&
			partialScalarReturnCaller != null && userDefinedReturnCaller != null &&
			importedReturnCaller != null &&
			rectangleCallers.size() == 4,
			"missing caller fixture");
		println("TASKING code-pointer inference matrix passed.");
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

	private Function functionAt(long address, String name) throws Exception {
		Address entry = toAddr(address);
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, bytes(0xdb, 0x00), false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		return createFunction(entry, name);
	}

	private Function fixture(String name, byte[] code) throws Exception {
		Address entry = toAddr(nextFixture);
		nextFixture += 0x100;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private byte[] codePointerSetup(int lowRegister, int highRegister, Address target) {
		long address = target.getUnsignedOffset();
		return bytes(
			0xe6, 0xf0 | lowRegister, (int) address, (int) (address >> 8),
			0xe6, 0xf0 | highRegister, (int) (address >> 16), 0x00);
	}

	private byte[] calls(Function target) {
		long address = target.getEntryPoint().getUnsignedOffset();
		return bytes(0xda, (int) (address >> 16), (int) address, (int) (address >> 8));
	}

	private byte[] pagedRead(int highRegister, int lowRegister) {
		return concat(pagedAccess(highRegister, lowRegister), bytes(0xdb, 0x00));
	}

	private byte[] pagedAccess(int highRegister, int lowRegister) {
		return bytes(0xdc, 0x40 | highRegister, 0xa8, 0x40 | lowRegister);
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

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private void setAnalysisWords(Function function, String... names) throws Exception {
		setWords(function, SourceType.ANALYSIS, names);
	}

	private void setUserWords(Function function, String... names) throws Exception {
		setWords(function, SourceType.USER_DEFINED, names);
	}

	private void setUserDword(Function function, String name) throws Exception {
		Variable parameter = new ParameterImpl(name, Undefined.getUndefinedDataType(4),
			currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(parameter),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void setAnalysisPointer(Function function, String... names) throws Exception {
		List<Variable> pointers = new ArrayList<>();
		for (String name : names) {
			pointers.add(new ParameterImpl(name,
				new PointerDataType(VoidDataType.dataType,
					currentProgram.getDataTypeManager()), currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, pointers,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisDataPointerReturn(Function function) throws Exception {
		function.setCallingConvention("__tasking_c166_classic");
		function.setReturnType(new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager()), SourceType.ANALYSIS);
	}

	private void setUserDataPointer(Function function, String name) throws Exception {
		Variable pointer = new ParameterImpl(name,
			new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager()), currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(pointer),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void setUserFunctionPointer(Function function, String parameterName,
			String typedefName) throws Exception {
		FunctionDefinitionDataType prototype = new FunctionDefinitionDataType(
			typedefName + "_function", currentProgram.getDataTypeManager());
		prototype.setReturnType(new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager()));
		prototype.setArguments(new ParameterDefinitionImpl("size",
			new UnsignedShortDataType(currentProgram.getDataTypeManager()), null));
		PointerDataType pointer = new PointerDataType(prototype,
			currentProgram.getDataTypeManager());
		TypedefDataType typedef = new TypedefDataType(CategoryPath.ROOT, typedefName, pointer,
			currentProgram.getDataTypeManager());
		Variable parameter = new ParameterImpl(parameterName, typedef, currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(parameter),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void setUserWordsAndFunctionPointer(Function function) throws Exception {
		FunctionDefinitionDataType prototype = new FunctionDefinitionDataType(
			"stack_forwarded_cb_function", currentProgram.getDataTypeManager());
		PointerDataType callback = new PointerDataType(prototype,
			currentProgram.getDataTypeManager());
		List<Variable> parameters = List.of(
			new ParameterImpl("word0",
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram),
			new ParameterImpl("word1",
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram),
			new ParameterImpl("callback", callback, currentProgram));
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void setAnalysisWordsAndPointer(Function function) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < 4; i++) {
			parameters.add(new ParameterImpl("word" + i,
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram));
		}
		parameters.add(new ParameterImpl("callback",
			new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager()), currentProgram));
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setLegacyGenericFunctionPointers(Function function, String... names)
			throws Exception {
		FunctionDefinitionDataType prototype = new FunctionDefinitionDataType(
			"__c166_far_function", currentProgram.getDataTypeManager());
		prototype.setVarArgs(true);
		DataType pointer = new PointerDataType(prototype,
			currentProgram.getDataTypeManager());
		List<Variable> parameters = new ArrayList<>();
		for (String name : names) {
			parameters.add(new ParameterImpl(name, pointer, currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisWordsAndLegacyFunctionPointers(Function function,
			String[] wordNames, String[] pointerNames) throws Exception {
		FunctionDefinitionDataType prototype = new FunctionDefinitionDataType(
			"__c166_far_function", currentProgram.getDataTypeManager());
		prototype.setVarArgs(true);
		DataType pointer = new PointerDataType(prototype,
			currentProgram.getDataTypeManager());
		List<Variable> parameters = new ArrayList<>();
		for (String name : wordNames) {
			parameters.add(new ParameterImpl(name,
				Undefined.getUndefinedDataType(2), currentProgram));
		}
		for (String name : pointerNames) {
			parameters.add(new ParameterImpl(name, pointer, currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setWords(Function function, SourceType source, String... names) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (String name : names) {
			parameters.add(new ParameterImpl(name,
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source);
	}

	private void checkCodeSignature(Function function, String... expectedStorage) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == expectedStorage.length,
			function.getName() + ": expected " + expectedStorage.length +
				" parameters, got " + parameters.length);
		for (int i = 0; i < parameters.length; i++) {
			check(expectedStorage[i].equals(describe(parameters[i].getVariableStorage())),
				function.getName() + "[" + i + "]: unexpected storage " +
					describe(parameters[i].getVariableStorage()));
			if (parameters[i].getVariableStorage().size() == 4) {
				check(parameters[i].getFormalDataType().getLength() == 4 &&
					isFunctionPointer(parameters[i].getFormalDataType()),
					function.getName() + "[" + i + "]: expected function pointer, got " +
						parameters[i].getFormalDataType().getDisplayName());
				check(parameters[i].getFormalDataType() instanceof TypeDef typeDef &&
					"fpointer".equals(typeDef.getName()),
					function.getName() + "[" + i + "]: expected fpointer, got " +
						parameters[i].getFormalDataType().getDisplayName());
			}
		}
	}

	private void checkSemanticCodeEvidence(Function function, int start) {
		String slots = currentProgram.getOptions("C166 TASKING Code Pointer Inference")
			.getString("Semantic code-pointer parameter slots at " +
				function.getEntryPoint(), null);
		check(slots != null && ("," + slots + ",").contains("," + start + ","),
			function.getName() + ": missing semantic code-pointer evidence for slot " +
				start + ", got " + slots);
	}

	private void checkMixedSignature(Function function) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == 2, "mixed signature parameter count is " + parameters.length);
		check("r13+r12".equals(describe(parameters[0].getVariableStorage())),
			"mixed code pointer was not joined");
		check(parameters[0].getFormalDataType().getLength() == 4 &&
			isFunctionPointer(parameters[0].getFormalDataType()),
			"mixed code argument is not a function pointer");
		check("r15+r14".equals(describe(parameters[1].getVariableStorage())) &&
			parameters[1].getFormalDataType() instanceof Pointer &&
			!isFunctionPointer(parameters[1].getFormalDataType()),
			"mixed PAGE:OFFSET data pointer was not preserved");
		check("data_offset".equals(parameters[1].getName()),
			"mixed data-pointer parameter name was lost");
	}

	private void checkPackedScalar(Function function, String expectedStorage) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == 1,
			function.getName() + ": packed scalar parameter count is " + parameters.length);
		check(expectedStorage.equals(describe(parameters[0].getVariableStorage())),
			function.getName() + ": packed scalar storage is " +
				describe(parameters[0].getVariableStorage()));
		check(parameters[0].getFormalDataType().getLength() == 4 &&
			Undefined.isUndefined(parameters[0].getFormalDataType()) &&
			!isFunctionPointer(parameters[0].getFormalDataType()),
			function.getName() + ": packed scalar type is " +
				parameters[0].getFormalDataType().getDisplayName());
	}

	private void checkPackedStackScalars(Function function) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == 5,
			function.getName() + ": expected five parameters, got " + parameters.length);
		String[] expected = { "r12", "r13", "r14", "Stack[0x0]:4", "Stack[0x4]:4" };
		for (int i = 0; i < parameters.length; i++) {
			check(expected[i].equals(describe(parameters[i].getVariableStorage())),
				function.getName() + "[" + i + "]: unexpected storage " +
					describe(parameters[i].getVariableStorage()));
		}
		for (int i = 3; i < parameters.length; i++) {
			check(parameters[i].getFormalDataType().getLength() == 4 &&
				Undefined.isUndefined(parameters[i].getFormalDataType()) &&
				!isFunctionPointer(parameters[i].getFormalDataType()),
				function.getName() + "[" + i + "]: expected packed undefined4, got " +
					parameters[i].getFormalDataType().getDisplayName());
		}
	}

	private void checkDataPointer(Function function, String expectedStorage) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == 1 &&
			expectedStorage.equals(describe(parameters[0].getVariableStorage())) &&
			parameters[0].getFormalDataType() instanceof Pointer &&
			!isFunctionPointer(parameters[0].getFormalDataType()),
			function.getName() + ": semantic PAGE:OFFSET evidence did not win: " +
			function.getPrototypeString(true, true) + ", signature source=" +
			function.getSignatureSource());
	}

	private void checkDataPointerReturn(Function function) {
		check(function.getReturnType() instanceof Pointer &&
			!isFunctionPointer(function.getReturnType()),
			function.getName() + ": return is not a data pointer: " +
				function.getReturnType().getDisplayName());
		check("r5+r4".equals(describe(function.getReturn().getVariableStorage())),
			function.getName() + ": return storage is not R5:R4: " +
				describe(function.getReturn().getVariableStorage()));
	}

	private void checkScalarReturn(Function function) {
		check(function.getReturnType().getLength() == 4 &&
			Undefined.isUndefined(function.getReturnType()) &&
			!isFunctionPointer(function.getReturnType()),
			function.getName() + ": return is not a four-byte scalar: " +
				function.getReturnType().getDisplayName());
		check("r5+r4".equals(describe(function.getReturn().getVariableStorage())),
			function.getName() + ": scalar return storage is not R5:R4: " +
				describe(function.getReturn().getVariableStorage()));
	}

	private void checkUnsignedLongReturn(Function function) {
		check(function.getReturnType() instanceof UnsignedLongDataType,
			function.getName() + ": return is not an unsigned long scalar: " +
				function.getReturnType().getDisplayName());
		check("r5+r4".equals(describe(function.getReturn().getVariableStorage())),
			function.getName() + ": unsigned long return storage is not R5:R4: " +
				describe(function.getReturn().getVariableStorage()));
	}

	private void checkFunctionPointerReturn(Function function) {
		check(function.getReturnType().getLength() == 4 &&
			isFunctionPointer(function.getReturnType()),
			function.getName() + ": return is not a function pointer: " +
				function.getReturnType().getDisplayName());
		check("r5+r4".equals(describe(function.getReturn().getVariableStorage())),
			function.getName() + ": function-pointer return storage is not R5:R4: " +
				describe(function.getReturn().getVariableStorage()));
	}

	private boolean isFunctionPointer(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		if (!(current instanceof Pointer pointer)) {
			return false;
		}
		current = pointer.getDataType();
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof FunctionDefinition;
	}

	private void checkTypedSignature(Function function, String typedefName) {
		check(function.getSignatureSource() == SourceType.USER_DEFINED,
			function.getName() + ": user-defined signature source changed");
		Parameter[] parameters = function.getParameters();
		check(parameters.length == 1 &&
			parameters[0].getFormalDataType() instanceof TypeDef typeDef &&
			typedefName.equals(typeDef.getName()) &&
			isFunctionPointer(typeDef),
			function.getName() + ": callback typedef was not preserved");
	}

	private void checkDecompilerConstants(Function caller, Function first, Function second) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), "failed to initialize decompiler");
		try {
			DecompileResults result = decompiler.decompileFunction(caller, 30, monitor);
			check(result.decompileCompleted(), "code-pointer caller did not decompile");
			String code = result.getDecompiledFunction().getC();
			String firstAddress = "0x" + Long.toHexString(first.getEntryPoint().getUnsignedOffset());
			String secondAddress = "0x" + Long.toHexString(second.getEntryPoint().getUnsignedOffset());
			check((code.contains(first.getName()) || code.contains(firstAddress)) &&
				(code.contains(second.getName()) || code.contains(secondAddress)),
				"decompiler did not preserve SEGMENT:OFFSET code constants:\n" + code);
		}
		finally {
			decompiler.dispose();
		}
	}

	private void checkTypedCodePointer(Function caller, Function target, Address wrongPagedAddress) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), "failed to initialize decompiler");
		try {
			DecompileResults result = decompiler.decompileFunction(caller, 30, monitor);
			check(result.decompileCompleted(), "typed code-pointer caller did not decompile: " +
				result.getErrorMessage());
			String code = result.getDecompiledFunction().getC();
			check(code.contains(target.getName()),
				"function-pointer typedef did not resolve the SEGMENT:OFFSET target:\n" + code);
			check(!code.contains(wrongPagedAddress.toString()) &&
				!code.contains("wrong_paged_code_pointer_target"),
				"function pointer was resolved with PAGE:OFFSET semantics:\n" + code);
		}
		finally {
			decompiler.dispose();
		}
	}

	private void checkParamReference(Address source, Address target, boolean expected) {
		Reference reference = currentProgram.getReferenceManager().getReference(source, target,
			Reference.MNEMONIC);
		boolean present = reference != null && reference.getReferenceType() == RefType.PARAM;
		check(present == expected, "unexpected code-pointer PARAM reference " + source + " -> " +
			target + ": " + reference);
	}

	private void removeParamReference(Address source, Address target) {
		Reference reference = currentProgram.getReferenceManager().getReference(source, target,
			Reference.MNEMONIC);
		if (reference != null && reference.getSource() == SourceType.ANALYSIS &&
			reference.getReferenceType() == RefType.PARAM) {
			currentProgram.getReferenceManager().delete(reference);
		}
	}

	private void checkWordSignature(Function function, SourceType source,
			String... expectedStorage) {
		check(function.getSignatureSource() == source,
			function.getName() + ": signature source changed");
		Parameter[] parameters = function.getParameters();
		check(parameters.length == expectedStorage.length,
			function.getName() + ": parameter count changed");
		for (int i = 0; i < parameters.length; i++) {
			check(expectedStorage[i].equals(describe(parameters[i].getVariableStorage())),
				function.getName() + "[" + i + "]: storage changed");
			check(parameters[i].getVariableStorage().size() == 2,
				function.getName() + "[" + i + "]: preserved words were joined");
		}
	}

	private String snapshot(Function... functions) {
		StringBuilder result = new StringBuilder();
		for (Function function : functions) {
			result.append(function.getEntryPoint()).append(':')
				.append(function.getPrototypeString(true, true)).append(';');
			for (Parameter parameter : function.getParameters()) {
				result.append(parameter.getFormalDataType().getPathName()).append('@')
					.append(describe(parameter.getVariableStorage())).append('|');
			}
		}
		return result.toString();
	}

	private String describe(VariableStorage storage) {
		List<Register> registers = storage.getRegisters();
		if (registers != null && !registers.isEmpty()) {
			StringBuilder result = new StringBuilder();
			for (Register register : registers) {
				if (result.length() != 0) {
					result.append('+');
				}
				result.append(register.getName().toLowerCase());
			}
			return result.toString();
		}
		if (storage.isStackStorage()) {
			return "Stack[0x" + Long.toHexString(storage.getStackOffset()) + "]:" +
				storage.size();
		}
		return storage.toString();
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
