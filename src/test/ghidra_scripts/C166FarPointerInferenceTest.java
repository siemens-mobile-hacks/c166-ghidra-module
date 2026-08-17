// Headless regression test; run via tools/test-tasking-abi.sh.
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166FarPointerAnalyzer;

public class C166FarPointerInferenceTest extends GhidraScript {

	private static final long FIXTURE_BASE = 0x2000;
	private static final int FIXTURE_STRIDE = 0x100;

	private final List<Function> fixtures = new ArrayList<>();
	private final AddressSet bodies = new AddressSet();
	private int nextFixture;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"wrong compiler spec");

		// Documented consecutive PAGE:OFFSET argument positions.
		Function pair12 = fixture("pair_r12_r13", pagedRead(13, 12));
		Function pair13 = fixture("pair_r13_r14", pagedRead(14, 13));
		Function pair14 = fixture("pair_r14_r15", pagedRead(15, 14));
		Function dppPair = fixture("dpp0_r12_r13", dppRead(13, 12));
		Function extprPair = fixture("extpr_r12_r13", bytes(
			0xdc, 0xcd, 0xa8, 0x4c, 0xdb, 0x00));
		Function postIncrement = fixture("postincrement_offset", bytes(
			0xdc, 0x4d, 0x98, 0x4c, 0xdb, 0x00));
		Function storePair = fixture("far_pointer_store", bytes(
			0xdc, 0x4d, 0xb8, 0x4c, 0xdb, 0x00));
		createMemoryBlock("global_far_words", toAddr(0x1000), new byte[4], false);
		Function globalPair = fixture("global_far_pointer", bytes(
			0xf2, 0xfc, 0x00, 0x10, // R12 = [0x1000], offset
			0xf2, 0xfd, 0x02, 0x10, // R13 = [0x1002], page
			0xdc, 0x4d, 0xa8, 0x4c, 0xdb, 0x00));

		// Data flow may pass through temporaries and offset arithmetic.
		Function copiedPair = fixture("copied_pair", bytes(
			0xf0, 0x5d,                         // mov R5,R13 (page)
			0xf0, 0x6c,                         // mov R6,R12 (offset)
			0xdc, 0x45, 0xa8, 0x46, 0xdb, 0x00 // extp R5; mov R4,[R6]; rets
		));
		Function adjustedOffset = fixture("adjusted_offset", bytes(
			0xf0, 0x5d,                         // mov R5,R13
			0xf0, 0x6c,                         // mov R6,R12
			0x08, 0x61,                         // add R6,#1
			0xdc, 0x45, 0xa8, 0x46, 0xdb, 0x00
		));

		// Both legal non-overlapping pairs can coexist in one signature.
		Function twoPairs = fixture("two_far_pointers", bytes(
			0xdc, 0x4d, 0xa8, 0x4c, // R4 = *(R13:R12)
			0xdc, 0x4f, 0xa8, 0x5e, // R5 = *(R15:R14)
			0x00, 0x45,             // add R4,R5; keep both loads live
			0xdb, 0x00));
		Function pointerAndFlag = fixture("far_pointer_and_word_flag", bytes(
			0xdc, 0x4d, 0xa8, 0x4c, // R4 = *(R13:R12)
			0x00, 0x4e,             // add R4,R14: genuine scalar input
			0xdb, 0x00));
		Function twoPointersAndStackWord = fixture("two_pointers_and_stack_word", bytes(
			0xdc, 0x4d, 0xa8, 0x4c,
			0xdc, 0x4f, 0xa8, 0x5e, 0x00, 0x45,
			0xd4, 0x20, 0x00, 0x00, // R2 = [SP+0]
			0x00, 0x42, 0xdb, 0x00));

		// Four genuine pointer parameters: two register pairs followed by two
		// four-byte stack pairs at SP+0 and SP+4.
		Function registerAndStackPairs = fixture("register_and_stack_far_pointers", bytes(
			0xdc, 0x4d, 0xa8, 0x4c,             // R4 = *(R13:R12)
			0xdc, 0x4f, 0xa8, 0x5e,             // R5 = *(R15:R14)
			0x00, 0x45,                         // add R4,R5
			0xd4, 0xc0, 0x00, 0x00,             // R12 = [SP+0]
			0xd4, 0xd0, 0x02, 0x00,             // R13 = [SP+2]
			0xdc, 0x4d, 0xa8, 0x5c, 0x00, 0x45,
			0xd4, 0xc0, 0x04, 0x00,             // R12 = [SP+4]
			0xd4, 0xd0, 0x06, 0x00,             // R13 = [SP+6]
			0xdc, 0x4d, 0xa8, 0x5c, 0x00, 0x45,
			0xdb, 0x00));

		// Pointer types propagate through wrappers even when the wrapper only
		// forwards PAGE:OFFSET pairs and never dereferences them itself.  This is
		// the shape used by FUN_258e12: two register pointers and one stack pointer.
		Function forwardingTarget = fixture("forwarding_target", bytes(
			0xdc, 0x4d, 0xa8, 0x4c,
			0xdc, 0x4f, 0xa8, 0x5e, 0x00, 0x45,
			0xd4, 0xc0, 0x00, 0x00,
			0xd4, 0xd0, 0x02, 0x00,
			0xdc, 0x4d, 0xa8, 0x5c, 0x00, 0x45,
			0xdb, 0x00));
		Function forwardingWrapper = fixture("forwarding_wrapper", calls(forwardingTarget));
		Function secondLevelWrapper = fixture("second_level_wrapper", calls(forwardingWrapper));
		List<Function> deepForwardingChain = new ArrayList<>();
		Function previousWrapper = secondLevelWrapper;
		for (int level = 3; level <= 10; level++) {
			previousWrapper = fixture("forwarding_wrapper_level_" + level,
				calls(previousWrapper));
			deepForwardingChain.add(previousWrapper);
		}
		Function forwardingBranchLeft = fixture("forwarding_branch_left",
			calls(forwardingTarget));
		Function forwardingBranchRight = fixture("forwarding_branch_right",
			calls(forwardingTarget));

		// Mutual recursion is one strongly connected component.  The second
		// function has direct PAGE:OFFSET evidence; the first learns the same
		// parameter by forwarding it around the cycle.
		Address recursiveAEntry = nextFixtureAddress(0);
		Address recursiveBEntry = nextFixtureAddress(1);
		Function recursiveA = fixture("recursive_forwarder_a", calls(recursiveBEntry));
		Function recursiveB = fixture("recursive_forwarder_b", concat(
			bytes(0xdc, 0x4d, 0xb8, 0x4c), // *(R13:R12) = R4; observable side effect
			calls(recursiveAEntry)));
		Function typedStringTarget = fixture("typed_string_target", bytes(0xdb, 0x00));
		setUserCharPointer(typedStringTarget, "text");
		Function tailStringWrapper = fixture("tail_string_wrapper", jumps(typedStringTarget));
		StructureDataType messageDefinition = new StructureDataType(
			new CategoryPath("/test"), "Message", 0,
			currentProgram.getDataTypeManager());
		messageDefinition.add(wordType(), "type", null);
		messageDefinition.add(wordType(), "length", null);
		DataType messageType = currentProgram.getDataTypeManager().addDataType(
			messageDefinition, DataTypeConflictHandler.REPLACE_HANDLER);
		DataType messagePointer = new PointerDataType(messageType,
			currentProgram.getDataTypeManager());
		DataType wordPointer = new PointerDataType(wordType(),
			currentProgram.getDataTypeManager());
		Function typedMessageTarget = fixture("typed_message_target", bytes(0xdb, 0x00));
		setUserParameters(typedMessageTarget, messagePointer);
		Function messageWrapper = fixture("message_pointer_wrapper",
			calls(typedMessageTarget));
		Function typedWordPointerTarget = fixture("typed_word_pointer_target",
			bytes(0xdb, 0x00));
		setUserParameters(typedWordPointerTarget, wordPointer);
		Function wordPointerWrapper = fixture("word_pointer_wrapper",
			calls(typedWordPointerTarget));
		// M55 FUN_747f44 shape: a stale generic R15:R14 pointer is only an
		// artifact of an earlier analysis pass.  The wrapper forwards R14 and
		// R15 to two independently typed uint16_t parameters of sys_open.
		Function typedScalarForwardTarget = fixture("typed_scalar_forward_target",
			bytes(0xdb, 0x00));
		setUserParameters(typedScalarForwardTarget, charPointerType(), wordType(), wordType());
		Function staleMixedForwarder = fixture("repair_forwarded_scalar_pair_pointer",
			calls(typedScalarForwardTarget));
		setAnalysisPointerAndPointer(staleMixedForwarder, "path", "flags_and_mode");
		// M55 FUN_37d574 shape: an existing word-wise ANALYSIS signature forwards
		// two late stack words into a typed four-byte callee parameter.  The callee
		// storage, not a speculative HighFunction pointer type, proves the join.
		Function lateStackPointerTarget = fixture("late_stack_pointer_target",
			bytes(0xdb, 0x00));
		setUserParameters(lateStackPointerTarget, wordType(), wordType(), wordType(),
			wordType(), wordType(), wordType(), charPointerType());
		// A reset program has no DB parameters yet.  The decompiler nevertheless
		// recovers all live argument words from the typed call.  Those live R12-R15
		// slots must prove that the following stack pair is an argument in this same
		// pass, rather than requiring a second analyzer run.
		Function recoveredStackForwarder = fixture("recovered_stack_pointer_forwarder",
			calls(lateStackPointerTarget));
		Function splitStackForwarder = fixture("split_stack_pointer_forwarder",
			calls(lateStackPointerTarget));
		setAnalysisWords(splitStackForwarder, "word0", "word1", "word2", "word3",
			"word4", "word5", "pointer_offset", "pointer_page");
		// Stack storage alone does not prove why register allocation stopped.  It
		// may follow an FP/aggregate argument or a value that did not fit R15, so
		// fabricating four leading word parameters would be incorrect.
		Function unprovenStackPair = fixture("stack_without_full_register_bank", bytes(
			0xd4, 0xc0, 0x00, 0x00,
			0xd4, 0xd0, 0x02, 0x00,
			0xdc, 0x4d, 0xa8, 0x4c, 0xdb, 0x00));
		// A lone high stack offset looks like a local, not a proven parameter.
		Function sparseStackPair = fixture("sparse_stack_is_not_parameter", bytes(
			0xd4, 0xc0, 0x20, 0x00,             // R12 = [SP+0x20]
			0xd4, 0xd0, 0x22, 0x00,             // R13 = [SP+0x22]
			0xdc, 0x4d, 0xa8, 0x4c, 0xdb, 0x00));
		Function ambiguousStack = fixture("ambiguous_stack_overlap", bytes(
			0xd4, 0xc0, 0x00, 0x00,
			0xd4, 0xd0, 0x02, 0x00,
			0xdc, 0x4d, 0xa8, 0x4c,             // *(SP+2:SP+0)
			0xd4, 0xc0, 0x02, 0x00,
			0xd4, 0xd0, 0x04, 0x00,
			0xdc, 0x4d, 0xa8, 0x5c,             // *(SP+4:SP+2)
			0x00, 0x45, 0xdb, 0x00));

		// Equal evidence for overlapping pairs must be rejected as ambiguous.
		Function ambiguous = fixture("ambiguous_overlap", bytes(
			0xdc, 0x4d, 0xa8, 0x4c, // R4 = *(R13:R12)
			0xdc, 0x4e, 0xa8, 0x5d, // R5 = *(R14:R13)
			0x00, 0x45, 0xdb, 0x00));

		// Unequal overlapping evidence has one deterministic best explanation.
		Function strongerPair = fixture("stronger_nonoverlap", bytes(
			0xdc, 0x4d, 0xa8, 0x4c, // first *(R13:R12)
			0xdc, 0x4d, 0xa8, 0x5c, // second *(R13:R12)
			0x00, 0x45,             // combine them
			0xdc, 0x4e, 0xa8, 0x5d, // *(R14:R13)
			0x00, 0x45, 0xdb, 0x00));

		// Some library wrappers only copy or store the two argument words, so
		// their body contains no SEGMENTOP.  Two independent callers nevertheless
		// provide decisive data evidence when PAGE is wider than a code SEGMENT
		// and both canonical PAGE:OFFSET values resolve to mapped memory.  This is
		// the FUN_242066 -> FUN_29ffde/FUN_9bc5a8 shape.
		createMemoryBlock("constant_callsite_data", toAddr(0x563100),
			new byte[0x100], false);
		Function constantSeedStore = fixture("constant_callsite_pair_store",
			bytes(0x88, 0xd0, 0x88, 0xc0, 0xdb, 0x00));
		fixture("constant_callsite_caller_a",
			constantPairCall(constantSeedStore, 0x31be, 0x158));
		fixture("constant_callsite_caller_b",
			constantPairCall(constantSeedStore, 0x316a, 0x158));
		// A stale generic code pointer cannot survive repeated PAGE values above
		// the 8-bit C166 code-segment limit.  This is the M55 FUN_c393da failure
		// mode which otherwise makes the decompiler map raw 0x1950e3b.
		Function staleGenericCodePointer = fixture(
			"repair_impossible_generic_code_pointer", bytes(0xdb, 0x00));
		setAnalysisGenericFunctionPointer(staleGenericCodePointer, "misclassified");
		fixture("stale_generic_code_pointer_caller_a",
			constantPairCall(staleGenericCodePointer, 0x313e, 0x158));
		Function staleConsumedGenericCodePointer = fixture(
			"repair_consumed_generic_code_pointer",
			bytes(0x88, 0xd0, 0x88, 0xc0, 0xdb, 0x00));
		setAnalysisGenericFunctionPointer(staleConsumedGenericCodePointer, "misclassified");
		fixture("stale_consumed_code_pointer_caller_a",
			constantPairCall(staleConsumedGenericCodePointer, 0x313e, 0x158));
		fixture("stale_consumed_code_pointer_caller_b",
			constantPairCall(staleConsumedGenericCodePointer, 0x316a, 0x158));
		Function objectAndConstantSeed = fixture("object_and_constant_callsite_pair",
			bytes(0x88, 0xf0, 0x88, 0xe0, 0xdb, 0x00));
		setAnalysisObjectAndWords(objectAndConstantSeed);
		fixture("object_and_constant_caller_a",
			constantPairCallAtSlot2(objectAndConstantSeed, 0x31be, 0x158));
		fixture("object_and_constant_caller_b",
			constantPairCallAtSlot2(objectAndConstantSeed, 0x313e, 0x158));
		Function typedVariadicTarget = fixture("typed_variadic_signature_preserved",
			bytes(0xdb, 0x00));
		setAnalysisWords(typedVariadicTarget, "fixed0", "fixed1");
		typedVariadicTarget.setVarArgs(true);
		fixture("typed_variadic_caller_a",
			constantPairCallAtSlot2(typedVariadicTarget, 0x31be, 0x158));
		fixture("typed_variadic_caller_b",
			constantPairCallAtSlot2(typedVariadicTarget, 0x316a, 0x158));

		// M55 FUN_99b53a shape: R12 is tested as a boolean while R13 is an
		// independent LGP id.  The adjacent constants (1, 0x2c3) happen to decode
		// to mapped address 0xb0c001, but scalar use in the callee must defeat the
		// constant-only seed.  Cover both a fresh signature and repair of a stale
		// generic ANALYSIS void * left by an earlier analyzer version.
		createMemoryBlock("scalar_pair_collision_data", toAddr(0xb0c000),
			new byte[0x100], false);
		byte[] scalarBitTest = bytes(
			0x9a, 0xfc, 0x01, 0x00, // jnb R12.0, second RETS
			0xdb, 0x00,
			0xdb, 0x00);
		Function freshScalarPair = fixture("constant_pair_is_two_scalars",
			scalarBitTest);
		fixture("scalar_pair_fresh_caller_a",
			constantPairCall(freshScalarPair, 0x0001, 0x02c3));
		fixture("scalar_pair_fresh_caller_b",
			constantPairCall(freshScalarPair, 0x0001, 0x02c3));
		Function staleScalarPair = fixture("repair_stale_scalar_pair_pointer",
			scalarBitTest);
		setAnalysisPointer(staleScalarPair, "misclassified");
		fixture("scalar_pair_stale_caller_a",
			constantPairCall(staleScalarPair, 0x0001, 0x02c3));
		fixture("scalar_pair_stale_caller_b",
			constantPairCall(staleScalarPair, 0x0001, 0x02c3));

		// M55 FUN_c3ca42 shape: an old generic pointer survives because the wrapper
		// forwards it before either word is tested.  A complete call-site rectangle
		// proves that both words vary independently: (0x39,0xae/0xaf) and
		// (0x3b,0xae/0xaf).  The scalar fact also follows a literal entry call into
		// the first forwarding target, but must not override real paged access or a
		// concrete pointed-to type.
		Function rectangleForwardTarget = fixture("rectangle_scalar_forward_target",
			bytes(0xdb, 0x00));
		setAnalysisPointer(rectangleForwardTarget, "misclassified");
		Function rectangleTypedSink = fixture("rectangle_typed_sink",
			bytes(0xdb, 0x00));
		setAnalysisCharPointer(rectangleTypedSink, "text");
		Function rectangleScalarPair = fixture("rectangle_pair_is_two_scalars",
			concat(callInstruction(rectangleForwardTarget.getEntryPoint()),
				callInstruction(rectangleTypedSink.getEntryPoint()), bytes(0xdb, 0x00)));
		setAnalysisPointer(rectangleScalarPair, "misclassified");
		fixture("rectangle_scalar_caller_39_ae",
			constantPairCall(rectangleScalarPair, 0x0039, 0x00ae));
		fixture("rectangle_scalar_caller_39_af",
			constantPairCall(rectangleScalarPair, 0x0039, 0x00af));
		fixture("rectangle_scalar_caller_3b_ae",
			constantPairCall(rectangleScalarPair, 0x003b, 0x00ae));
		fixture("rectangle_scalar_caller_3b_af",
			constantPairCall(rectangleScalarPair, 0x003b, 0x00af));

		Function freshRectangleScalarPair = fixture(
			"fresh_rectangle_pair_is_not_a_pointer", bytes(0xdb, 0x00));
		fixture("fresh_rectangle_caller_39_ae",
			constantPairCall(freshRectangleScalarPair, 0x0039, 0x00ae));
		fixture("fresh_rectangle_caller_39_af",
			constantPairCall(freshRectangleScalarPair, 0x0039, 0x00af));
		fixture("fresh_rectangle_caller_3b_ae",
			constantPairCall(freshRectangleScalarPair, 0x003b, 0x00ae));
		fixture("fresh_rectangle_caller_3b_af",
			constantPairCall(freshRectangleScalarPair, 0x003b, 0x00af));

		// M55 FUN_c3ca4a shape: both scalar words are spilled before a call, then
		// an unrelated returned R5:R4 pointer is dereferenced.  That EXTP must not
		// suppress the scalar rectangle for R13:R12.
		Function unrelatedPointerProducer = fixture(
			"unrelated_paged_pointer_producer", bytes(0xdb, 0x00));
		Function rectangleWithUnrelatedExtp = fixture(
			"rectangle_with_unrelated_extp",
			concat(bytes(0x88, 0xd0, 0x88, 0xc0),
				callInstruction(unrelatedPointerProducer.getEntryPoint()),
				bytes(0x98, 0xc0, 0xdc, 0x45, 0xc4, 0xc4, 0x2c, 0x00,
					0x98, 0xd0, 0xdb, 0x00)));
		fixture("unrelated_extp_caller_313e_158",
			constantPairCall(rectangleWithUnrelatedExtp, 0x313e, 0x158));
		fixture("unrelated_extp_caller_316a_158",
			constantPairCall(rectangleWithUnrelatedExtp, 0x316a, 0x158));
		fixture("unrelated_extp_caller_313e_159",
			constantPairCall(rectangleWithUnrelatedExtp, 0x313e, 0x159));
		fixture("unrelated_extp_caller_316a_159",
			constantPairCall(rectangleWithUnrelatedExtp, 0x316a, 0x159));

		Function rectangleRealPointer = fixture("rectangle_with_real_paged_access",
			pagedRead(13, 12));
		setAnalysisPointer(rectangleRealPointer, "buffer");
		fixture("rectangle_pointer_caller_39_ae",
			constantPairCall(rectangleRealPointer, 0x0039, 0x00ae));
		fixture("rectangle_pointer_caller_39_af",
			constantPairCall(rectangleRealPointer, 0x0039, 0x00af));
		fixture("rectangle_pointer_caller_3b_ae",
			constantPairCall(rectangleRealPointer, 0x003b, 0x00ae));
		fixture("rectangle_pointer_caller_3b_af",
			constantPairCall(rectangleRealPointer, 0x003b, 0x00af));

		Function rectangleConcretePointer = fixture("rectangle_concrete_pointer",
			bytes(0xdb, 0x00));
		setAnalysisCharPointer(rectangleConcretePointer, "text");
		fixture("rectangle_concrete_caller_39_ae",
			constantPairCall(rectangleConcretePointer, 0x0039, 0x00ae));
		fixture("rectangle_concrete_caller_39_af",
			constantPairCall(rectangleConcretePointer, 0x0039, 0x00af));
		fixture("rectangle_concrete_caller_3b_ae",
			constantPairCall(rectangleConcretePointer, 0x003b, 0x00ae));
		fixture("rectangle_concrete_caller_3b_af",
			constantPairCall(rectangleConcretePointer, 0x003b, 0x00af));

		// One occurrence is insufficient even if it maps, a PAGE that also fits
		// the 8-bit code SEGMENT remains ambiguous, and an unmapped PAGE:OFFSET is
		// not evidence at all.
		Function singleConstantStore = fixture("single_constant_pair_store",
			bytes(0xdb, 0x00));
		fixture("single_constant_pair_caller",
			constantPairCall(singleConstantStore, 0x313e, 0x158));
		Function codeSizedPageStore = fixture("code_sized_page_pair_store",
			bytes(0xdb, 0x00));
		fixture("code_sized_page_caller_a",
			constantPairCall(codeSizedPageStore, 0x3d0e, 0x25));
		fixture("code_sized_page_caller_b",
			constantPairCall(codeSizedPageStore, 0x3d0e, 0x25));
		Function unmappedConstantStore = fixture("unmapped_constant_pair_store",
			bytes(0xdb, 0x00));
		fixture("unmapped_constant_pair_caller_a",
			constantPairCall(unmappedConstantStore, 0x31be, 0x159));
		fixture("unmapped_constant_pair_caller_b",
			constantPairCall(unmappedConstantStore, 0x316a, 0x159));

		// Negative controls: none proves adjacent PAGE:OFFSET provenance.
		Function wrongOffset = fixture("wrong_offset_register", pagedRead(14, 12));
		Function sameWord = fixture("same_page_and_offset", pagedRead(13, 13));
		Function constantPage = fixture("constant_dpp_page", bytes(
			0xe6, 0x00, 0x01, 0x00,             // mov DPP0,#1
			0xa8, 0x4c, 0xdb, 0x00              // mov R4,[R12]; rets
		));
		Function setupWithoutAccess = fixture("extp_without_access", bytes(
			0xdc, 0x4d, 0xcc, 0x00, 0xdb, 0x00 // extp R13; nop; rets
		));
		Function accessWithoutSetup = fixture("ordinary_indirect", bytes(
			0xa8, 0x8c, 0xdb, 0x00));
		Function reversedPair = fixture("reversed_pair", pagedRead(12, 13));
		Function nonArgumentPage = fixture("non_argument_page", pagedRead(11, 12));
		Function dpp1Only = fixture("dpp1_is_not_far_scratch", bytes(
			0xf6, 0xfd, 0x02, 0xfe,             // mov DPP1,R13
			0xa8, 0x4c, 0xdb, 0x00));

		// Existing ANALYSIS information must survive signature reconstruction.
		Function preserved = fixture("preserve_analysis_signature", pagedRead(14, 13));
		setAnalysisWords(preserved, "count", "page_offset", "page");

		// Existing correct pointer is a fixed point of the analyzer.
		Function alreadyTyped = fixture("already_typed", pagedRead(13, 12));
		setAnalysisPointer(alreadyTyped, "buffer");
		Function analysisDword = fixture("analysis_dword_preserved", pagedRead(13, 12));
		setAnalysisDword(analysisDword, "candidate");
		// A manually rerun far-data pass must never demote a code pointer inferred
		// by the later-priority code analyzer.  Real M55 wrappers can produce
		// apparent paged evidence while forwarding allocator callbacks.
		Function codePointerWithPagedEvidence = fixture(
			"code_pointer_survives_paged_evidence", pagedRead(13, 12));
		setAnalysisFunctionPointer(codePointerWithPagedEvidence, "callback");
		Function overlappingCodePointer = fixture(
			"code_pointer_survives_overlapping_paged_evidence", pagedRead(14, 13));
		setAnalysisFunctionPointerAndWord(overlappingCodePointer, "callback", "word2");

		// USER_DEFINED signatures are authoritative and must never be rewritten.
		Function userDefined = fixture("user_defined_signature", pagedRead(13, 12));
		setUserWords(userDefined, "offset", "page");

		// A non-default convention is outside this analyzer's scope.
		Function otherConvention = fixture("other_convention", pagedRead(13, 12));
		otherConvention.setCallingConvention("__tasking_c166_classic_vararg_1");

		runAnalyzer();

		checkSignature(pair12, Set.of(0), "r13+r12");
		checkSignature(pair13, Set.of(1), "r12", "r14+r13");
		checkSignature(pair14, Set.of(2), "r12", "r13", "r15+r14");
		checkSignature(dppPair, Set.of(0), "r13+r12");
		checkSignature(extprPair, Set.of(0), "r13+r12");
		checkSignature(postIncrement, Set.of(0), "r13+r12");
		checkSignature(storePair, Set.of(0), "r13+r12");
		checkNoParameters(globalPair);
		Data globalPointer = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
		check(globalPointer != null && globalPointer.getDataType() instanceof Pointer &&
			globalPointer.getLength() == 4,
			"adjacent global PAGE:OFFSET words were not joined as a far pointer");
		checkSignature(copiedPair, Set.of(0), "r13+r12");
		checkSignature(adjustedOffset, Set.of(0), "r13+r12");
		checkSignature(twoPairs, Set.of(0, 1), "r13+r12", "r15+r14");
		checkSignature(pointerAndFlag, Set.of(0), "r13+r12", "r14");
		checkSignature(twoPointersAndStackWord, Set.of(0, 1),
			"r13+r12", "r15+r14", "Stack[0x0]:2");
		checkSignature(registerAndStackPairs, Set.of(0, 1, 2, 3),
			"r13+r12", "r15+r14", "Stack[0x0]:4", "Stack[0x4]:4");
		checkSignature(forwardingTarget, Set.of(0, 1, 2),
			"r13+r12", "r15+r14", "Stack[0x0]:4");
		checkSignature(forwardingWrapper, Set.of(0, 1, 2),
			"r13+r12", "r15+r14", "Stack[0x0]:4");
		checkSignature(secondLevelWrapper, Set.of(0, 1, 2),
			"r13+r12", "r15+r14", "Stack[0x0]:4");
		for (Function wrapper : deepForwardingChain) {
			checkSignature(wrapper, Set.of(0, 1, 2),
				"r13+r12", "r15+r14", "Stack[0x0]:4");
		}
		checkSignature(forwardingBranchLeft, Set.of(0, 1, 2),
			"r13+r12", "r15+r14", "Stack[0x0]:4");
		checkSignature(forwardingBranchRight, Set.of(0, 1, 2),
			"r13+r12", "r15+r14", "Stack[0x0]:4");
		checkSignature(recursiveA, Set.of(0), "r13+r12");
		checkSignature(recursiveB, Set.of(0), "r13+r12");
		checkCharPointer(tailStringWrapper, "r13+r12");
		checkPointerTarget(messageWrapper, 0, messageType, "struct pointer type was lost");
		checkPointerTarget(wordPointerWrapper, 0, wordType(),
			"uint16_t pointer type was lost");
		checkSignature(staleMixedForwarder, Set.of(0),
			"r13+r12", "r14", "r15");
		check(!(staleMixedForwarder.getParameter(1).getFormalDataType() instanceof Pointer) &&
			!(staleMixedForwarder.getParameter(2).getFormalDataType() instanceof Pointer),
			"forwarded scalar words were rejoined as a stale generic pointer");
		checkPointerTypeConflict(messagePointer, wordPointer);
		checkSignature(recoveredStackForwarder, Set.of(6), "r12", "r13", "r14", "r15",
			"Stack[0x0]:2", "Stack[0x2]:2", "Stack[0x4]:4");
		check(((Pointer) recoveredStackForwarder.getParameter(6).getFormalDataType())
			.getDataType() instanceof CharDataType,
			"recovered stack pointer lost its char type");
		checkSignature(splitStackForwarder, Set.of(6), "r12", "r13", "r14", "r15",
			"Stack[0x0]:2", "Stack[0x2]:2", "Stack[0x4]:4");
		check(((Pointer) splitStackForwarder.getParameter(6).getFormalDataType())
			.getDataType() instanceof CharDataType,
			"late forwarded stack pointer lost its char type");
		checkNoParameters(unprovenStackPair);
		checkNoParameters(sparseStackPair);
		checkNoParameters(ambiguousStack);
		// R14 still contributes to the weaker rejected interpretation and is a
		// genuine live 16-bit input even though R13:R12 is the selected pointer.
		checkSignature(strongerPair, Set.of(0), "r13+r12", "r14");

		checkNoParameters(ambiguous);
		checkSignature(constantSeedStore, Set.of(0), "r13+r12");
		checkWordSignature(staleGenericCodePointer, SourceType.ANALYSIS, "r12", "r13");
		checkSignature(staleConsumedGenericCodePointer, Set.of(0), "r13+r12");
		check(!(((Pointer) staleConsumedGenericCodePointer.getParameter(0)
			.getFormalDataType()).getDataType() instanceof FunctionDefinition),
			"consumed impossible generic code pointer was not repaired as data");
		checkSignature(objectAndConstantSeed, Set.of(0, 1),
			"r13+r12", "r15+r14");
		check(typedVariadicTarget.hasVarArgs(),
			"far-pointer inference removed a variadic declaration");
		checkWordSignature(typedVariadicTarget, SourceType.ANALYSIS, "r12", "r13");
		checkNoParameters(freshScalarPair);
		checkWordSignature(staleScalarPair, SourceType.ANALYSIS, "r12", "r13");
		checkWordSignature(rectangleScalarPair, SourceType.ANALYSIS, "r12", "r13");
		checkWordSignature(rectangleForwardTarget, SourceType.ANALYSIS, "r12", "r13");
		checkNoParameters(freshRectangleScalarPair);
		checkNoParameters(rectangleWithUnrelatedExtp);
		checkCharPointer(rectangleTypedSink, "r13+r12");
		checkSignature(rectangleRealPointer, Set.of(0), "r13+r12");
		checkCharPointer(rectangleConcretePointer, "r13+r12");
		checkNoParameters(singleConstantStore);
		checkNoParameters(codeSizedPageStore);
		checkNoParameters(unmappedConstantStore);
		checkNoParameters(wrongOffset);
		checkNoParameters(sameWord);
		checkNoParameters(constantPage);
		checkNoParameters(setupWithoutAccess);
		checkNoParameters(accessWithoutSetup);
		checkNoParameters(reversedPair);
		checkNoParameters(nonArgumentPage);
		checkNoParameters(dpp1Only);

		checkSignature(preserved, Set.of(1), "r12", "r14+r13");
		check("count".equals(preserved.getParameter(0).getName()),
			"existing ANALYSIS parameter name was lost");
		check("page_offset".equals(preserved.getParameter(1).getName()),
			"inferred pointer did not retain the first word's name");
		checkSignature(alreadyTyped, Set.of(0), "r13+r12");
		check("buffer".equals(alreadyTyped.getParameter(0).getName()),
			"existing pointer name was changed");
		checkSignature(analysisDword, Set.of(), "r13+r12");
		check("candidate".equals(analysisDword.getParameter(0).getName()),
			"preserved ANALYSIS dword name was lost");
		checkFunctionPointer(codePointerWithPagedEvidence, 0,
			"direct paged evidence demoted an existing function pointer");
		checkFunctionPointer(overlappingCodePointer, 0,
			"overlapping paged evidence split an existing function pointer");
		checkSignature(overlappingCodePointer, Set.of(0), "r13+r12", "r14");
		checkWordSignature(userDefined, SourceType.USER_DEFINED, "r12", "r13");
		checkNoParameters(otherConvention);

		// A second run must not add, split, rename, or retype anything.
		String beforeSecondRun = snapshotSignatures();
		runAnalyzer();
		check(beforeSecondRun.equals(snapshotSignatures()),
			"far-pointer inference is not idempotent");

		println("TASKING far-pointer inference matrix passed: " + fixtures.size() +
			" fixture functions, including positive, negative, ambiguous and idempotence cases.");
	}

	private Function fixture(String name, byte[] code) throws Exception {
		Address entry = toAddr(FIXTURE_BASE + (long) nextFixture * FIXTURE_STRIDE);
		nextFixture++;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		fixtures.add(function);
		bodies.add(function.getBody());
		return function;
	}

	private void runAnalyzer() throws Exception {
		C166FarPointerAnalyzer analyzer = new C166FarPointerAnalyzer();
		check(analyzer.added(currentProgram, bodies, monitor, new MessageLog()),
			"far-pointer analyzer failed");
	}

	private byte[] pagedRead(int highRegister, int lowRegister) {
		return bytes(0xdc, 0x40 | highRegister, 0xa8, 0x40 | lowRegister, 0xdb, 0x00);
	}

	private byte[] dppRead(int highRegister, int lowRegister) {
		return bytes(0xf6, 0xf0 | highRegister, 0x00, 0xfe,
			0xa8, 0x40 | lowRegister, 0xdb, 0x00);
	}

	private byte[] calls(Function target) {
		return calls(target.getEntryPoint());
	}

	private byte[] calls(Address target) {
		return concat(callInstruction(target), bytes(0xdb, 0x00));
	}

	private byte[] callInstruction(Address target) {
		long address = target.getOffset();
		return bytes(0xda, (int) (address >> 16), (int) address, (int) (address >> 8));
	}

	private byte[] constantPairCall(Function target, int offset, int page) {
		return concat(bytes(
			0xe6, 0xfc, offset, offset >> 8, // mov R12,#OFFSET
			0xe6, 0xfd, page, page >> 8),    // mov R13,#PAGE
			calls(target));
	}

	private byte[] constantPairCallAtSlot2(Function target, int offset, int page) {
		return concat(bytes(
			0xe6, 0xfc, 0x00, 0x00,       // object OFFSET in R12
			0xe6, 0xfd, 0x00, 0x00,       // object PAGE in R13
			0xe6, 0xfe, offset, offset >> 8,
			0xe6, 0xff, page, page >> 8),
			calls(target));
	}

	private Address nextFixtureAddress(int delta) {
		return toAddr(FIXTURE_BASE + (long) (nextFixture + delta) * FIXTURE_STRIDE);
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

	private byte[] jumps(Function target) {
		long address = target.getEntryPoint().getOffset();
		return bytes(0xfa, (int) (address >> 16), (int) address, (int) (address >> 8));
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private void setAnalysisWords(Function function, String... names) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (String name : names) {
			parameters.add(new ParameterImpl(name,
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisPointer(Function function, String name) throws Exception {
		Variable pointer = new ParameterImpl(name,
			new PointerDataType(VoidDataType.dataType, currentProgram.getDataTypeManager()),
			currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(pointer),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisPointerAndPointer(Function function, String firstName,
			String secondName) throws Exception {
		DataType genericPointer = new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager());
		List<Variable> parameters = List.of(
			new ParameterImpl(firstName, charPointerType(), currentProgram),
			new ParameterImpl(secondName, genericPointer, currentProgram));
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisCharPointer(Function function, String name) throws Exception {
		Variable pointer = new ParameterImpl(name,
			new PointerDataType(CharDataType.dataType,
				currentProgram.getDataTypeManager()), currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(pointer),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisObjectAndWords(Function function) throws Exception {
		List<Variable> parameters = List.of(
			new ParameterImpl("object",
				new PointerDataType(VoidDataType.dataType,
					currentProgram.getDataTypeManager()), currentProgram),
			new ParameterImpl("offset", wordType(), currentProgram),
			new ParameterImpl("page", wordType(), currentProgram));
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisDword(Function function, String name) throws Exception {
		Variable value = new ParameterImpl(name,
			new UnsignedLongDataType(currentProgram.getDataTypeManager()), currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(value),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private DataType functionPointerType() {
		FunctionDefinitionDataType definition = new FunctionDefinitionDataType(
			new CategoryPath("/test"), "generic_far_callback",
			currentProgram.getDataTypeManager());
		DataType resolved = currentProgram.getDataTypeManager().addDataType(definition,
			DataTypeConflictHandler.KEEP_HANDLER);
		return new PointerDataType(resolved, currentProgram.getDataTypeManager());
	}

	private void setAnalysisFunctionPointer(Function function, String name) throws Exception {
		Variable pointer = new ParameterImpl(name, functionPointerType(), currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(pointer),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisGenericFunctionPointer(Function function, String name)
			throws Exception {
		FunctionDefinitionDataType definition = new FunctionDefinitionDataType(
			new CategoryPath("/c166"), "function", currentProgram.getDataTypeManager());
		DataType resolved = currentProgram.getDataTypeManager().addDataType(definition,
			DataTypeConflictHandler.KEEP_HANDLER);
		Variable pointer = new ParameterImpl(name,
			new PointerDataType(resolved, currentProgram.getDataTypeManager()), currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(pointer),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void setAnalysisFunctionPointerAndWord(Function function, String pointerName,
			String wordName) throws Exception {
		List<Variable> parameters = List.of(
			new ParameterImpl(pointerName, functionPointerType(), currentProgram),
			new ParameterImpl(wordName, wordType(), currentProgram));
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void checkFunctionPointer(Function function, int parameterIndex,
			String message) {
		DataType type = function.getParameter(parameterIndex).getFormalDataType();
		check(type instanceof Pointer &&
			((Pointer) type).getDataType() instanceof FunctionDefinition,
			message + ": got " + type.getDisplayName());
	}

	private void setUserWords(Function function, String... names) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (String name : names) {
			parameters.add(new ParameterImpl(name,
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void setUserCharPointer(Function function, String name) throws Exception {
		Variable pointer = new ParameterImpl(name,
			new PointerDataType(CharDataType.dataType, currentProgram.getDataTypeManager()),
			currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(pointer),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void setUserParameters(Function function, DataType... types) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < types.length; i++) {
			parameters.add(new ParameterImpl("arg" + i, types[i], currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private DataType wordType() {
		return new UnsignedShortDataType(currentProgram.getDataTypeManager());
	}

	private DataType charPointerType() {
		return new PointerDataType(CharDataType.dataType,
			currentProgram.getDataTypeManager());
	}

	private void checkCharPointer(Function function, String expectedStorage) {
		checkSignature(function, Set.of(0), expectedStorage);
		Pointer pointer = (Pointer) function.getParameter(0).getFormalDataType();
		check(pointer.getDataType() instanceof CharDataType,
			function.getName() + ": char * evidence was reduced to void *");
	}

	private void checkPointerTarget(Function function, int parameterIndex,
			DataType expectedTarget, String message) {
		checkSignature(function, Set.of(parameterIndex), "r13+r12");
		checkPointerTargetType(function, parameterIndex, expectedTarget, message);
	}

	private void checkPointerTargetType(Function function, int parameterIndex,
			DataType expectedTarget, String message) {
		Pointer pointer = (Pointer) function.getParameter(parameterIndex).getFormalDataType();
		check(pointer.getDataType().isEquivalent(expectedTarget), message + ": got " +
			pointer.getDataType().getDisplayName());
	}

	private void checkPointerTypeConflict(DataType first, DataType second) throws Exception {
		C166FarPointerAnalyzer analyzer = new C166FarPointerAnalyzer();
		Map<Integer, DataType> types = new HashMap<>();
		var method = C166FarPointerAnalyzer.class.getDeclaredMethod("mergePointerType",
			ghidra.program.model.listing.Program.class, Map.class, int.class, DataType.class);
		method.setAccessible(true);
		method.invoke(analyzer, currentProgram, types, 0, first);
		method.invoke(analyzer, currentProgram, types, 0, second);
		Pointer merged = (Pointer) types.get(0);
		check(merged.getDataType() instanceof VoidDataType,
			"conflicting pointer types did not degrade to void pointer: got " +
				merged.getDataType().getDisplayName());
	}

	private void checkSignature(Function function, Set<Integer> pointerParameters,
			String... expectedStorage) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == expectedStorage.length,
			function.getName() + ": expected " + expectedStorage.length +
				" parameters, got " + parameters.length);
		for (int i = 0; i < parameters.length; i++) {
			String storage = describe(parameters[i].getVariableStorage());
			check(expectedStorage[i].equals(storage), function.getName() + "[" + i +
				"]: expected " + expectedStorage[i] + ", got " + storage);
			check((parameters[i].getFormalDataType() instanceof Pointer) ==
				pointerParameters.contains(i), function.getName() + "[" + i +
				"]: unexpected type " + parameters[i].getFormalDataType().getDisplayName());
		}
	}

	private void checkNoParameters(Function function) {
		check(function.getParameterCount() == 0,
			function.getName() + ": false-positive parameters were inferred");
	}

	private void checkWordSignature(Function function, SourceType source,
			String... expectedStorage) {
		check(function.getSignatureSource() == source,
			function.getName() + ": signature source changed");
		checkSignature(function, Set.of(), expectedStorage);
	}

	private String snapshotSignatures() {
		return fixtures.stream().map(function -> function.getName() + ":" +
			function.getSignatureSource() + ":" + Arrays.stream(function.getParameters())
				.map(parameter -> parameter.getName() + "/" +
					parameter.getFormalDataType().getDisplayName() + "/" +
					describe(parameter.getVariableStorage()))
				.collect(Collectors.joining(",")))
			.collect(Collectors.joining("\n"));
	}

	private String describe(VariableStorage storage) {
		if (storage.isStackStorage()) {
			return "Stack[0x" + Integer.toHexString(storage.getStackOffset()) + "]:" +
				storage.size();
		}
		return storage.getRegisters().stream()
			.map(register -> register.getName().toLowerCase())
			.reduce((left, right) -> left + "+" + right)
			.orElse(storage.toString());
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
