package ghidrainfineon;

import java.math.BigInteger;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;

/**
 * Single p-code implementation of C166 data-address formation.
 *
 * <p>EXTP/EXTS mode is instruction context, but DPP0..DPP3 are ordinary
 * architectural registers.  In particular, DPP values must remain varnodes in
 * p-code so normal data-flow follows writes such as {@code mov DPP0,#page}.
 * Reading a previously propagated DPP value from {@link ProgramContext} here
 * makes decompilation depend on analyzer order and on stale database state.</p>
 */
final class C166PagedAddressEmitter {
	private static final long PAGE_MASK = 0x3fffL;

	private final SleighLanguage language;
	private final int segmentUseropIndex;

	C166PagedAddressEmitter(SleighLanguage language) {
		this.language = language;
		Symbol symbol = language.getSymbolTable().findGlobalSymbol("segment");
		segmentUseropIndex = symbol instanceof UseropSymbol userop ? userop.getIndex() : -1;
	}

	boolean hasOverride(Program program, Address address) {
		ProgramContext context = program.getProgramContext();
		return isContextOne(context, "ExtpEn", address) ||
			isContextOne(context, "ExtsEn", address);
	}

	PcodeOp[] emit(Program program, Address address, Varnode base, long encodedOffset,
			Varnode output, long uniqueBase) {
		return emit(program, address, base, encodedOffset,
			(int) ((encodedOffset >>> 14) & 3), output, uniqueBase);
	}

	PcodeOp[] emitIndirect(Program program, Address address, Varnode logicalAddress,
			int dppIndex, Varnode output, long uniqueBase) {
		return emit(program, address, logicalAddress, 0, dppIndex, output, uniqueBase);
	}

	private PcodeOp[] emit(Program program, Address address, Varnode base,
			long encodedOffset, int dppIndex, Varnode output, long uniqueBase) {
		ProgramContext context = program.getProgramContext();

		if (isContextOne(context, "ExtsEn", address)) {
			EffectiveExt exts = readEffectiveExt(program, address,
				"Exts", "ExtsReg", "ExtsRegMode");
			if (exts == null) {
				return emitRaw(address, base, encodedOffset, output, uniqueBase);
			}
			if (exts.immediate != null) {
				return emitFixed(address, base, encodedOffset & 0xffffL,
					(exts.immediate & 0xffL) << 16, 0xffffL, output, uniqueBase);
			}
			return emitRegisterPage(address, base, encodedOffset & 0xffffL,
				exts.register, 16, 0xffffL, output, uniqueBase);
		}

		if (isContextOne(context, "ExtpEn", address)) {
			EffectiveExt extp = readEffectiveExt(program, address,
				"Extp", "ExtpReg", "ExtpRegMode");
			if (extp == null) {
				return emitRaw(address, base, encodedOffset, output, uniqueBase);
			}
			if (extp.immediate != null) {
				return emitFixed(address, base, encodedOffset & PAGE_MASK,
					(extp.immediate & 0x3ffL) << 14, PAGE_MASK, output, uniqueBase);
			}
			// Register-mode EXTP is the architectural dereference of a TASKING
			// PAGE:OFFSET far pointer.  Keep that relationship explicit for the
			// decompiler instead of lowering it to page<<14 arithmetic.  The
			// segmentop definition supplies the exact 14-bit offset semantics.
			if (segmentUseropIndex >= 0) {
				return emitSegment(address, base, encodedOffset & PAGE_MASK,
					extp.register, output, uniqueBase);
			}
			return emitRegisterPage(address, base, encodedOffset & PAGE_MASK,
				extp.register, 14, PAGE_MASK, output, uniqueBase);
		}

		dppIndex &= 3;
		Register dpp = program.getRegister("DPP" + dppIndex);
		boolean functionWritesDpp = dpp != null &&
			containingFunctionWrites(program, address, dpp);
		if (base == null && dpp != null && !functionWritesDpp) {
			return emitFixed(address, null, encodedOffset & PAGE_MASK,
				(long) dppIndex << 14, PAGE_MASK, output, uniqueBase);
		}
		if (dpp == null || segmentUseropIndex < 0) {
			return emitRaw(address, base, encodedOffset, output, uniqueBase);
		}
		return emitSegment(address, base, encodedOffset & PAGE_MASK, dpp,
			output, uniqueBase);
	}

	static boolean containingFunctionWrites(Program program, Address address,
			Register expected) {
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return false;
		}
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.getNumOperands() == 0 ||
				OperandType.isIndirect(instruction.getOperandType(0))) {
				continue;
			}
			for (Object destination : instruction.getOpObjects(0)) {
				if (destination instanceof Register actual && overlaps(actual, expected)) {
					return true;
				}
			}
			if (hasRegisterResult(instruction, expected) &&
				isDppSfrOperand(instruction, expected)) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasRegisterResult(Instruction instruction, Register expected) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register actual && overlaps(actual, expected)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isDppSfrOperand(Instruction instruction, Register expected) {
		long sfrAddress = switch (expected.getName()) {
			case "DPP0" -> 0xfe00L;
			case "DPP1" -> 0xfe02L;
			case "DPP2" -> 0xfe04L;
			case "DPP3" -> 0xfe06L;
			default -> -1L;
		};
		if (sfrAddress < 0) {
			return false;
		}
		Scalar scalar = instruction.getScalar(0);
		if (scalar != null) {
			return scalar.getUnsignedValue() == sfrAddress;
		}
		for (Object object : instruction.getOpObjects(0)) {
			if (object instanceof Scalar operand) {
				return operand.getUnsignedValue() == sfrAddress;
			}
		}
		return false;
	}

	private static boolean overlaps(Register first, Register second) {
		return first.contains(second) || second.contains(first);
	}

	private PcodeOp[] emitSegment(Address address, Varnode base, long offset,
			Register pageRegister, Varnode output, long uniqueBase) {
		AddressSpace constantSpace = constantSpace();
		Varnode inner;
		PcodeOp[] operations;
		int next;
		if (base == null) {
			inner = constant(offset, 2);
			operations = new PcodeOp[1];
			next = 0;
		}
		else {
			Varnode sum = unique(uniqueBase, 2);
			inner = unique(uniqueBase + 4, 2);
			operations = new PcodeOp[3];
			operations[0] = op(address, 0, PcodeOp.INT_ADD,
				new Varnode[] { base, constant(offset, 2) }, sum);
			operations[1] = op(address, 1, PcodeOp.INT_AND,
				new Varnode[] { sum, constant(PAGE_MASK, 2) }, inner);
			next = 2;
		}
		Varnode userop = new Varnode(constantSpace.getAddress(segmentUseropIndex), 4);
		Varnode page = new Varnode(pageRegister.getAddress(),
			pageRegister.getMinimumByteSize());
		operations[next] = op(address, next, PcodeOp.CALLOTHER,
			new Varnode[] { userop, page, inner }, output);
		return operations;
	}

	private PcodeOp[] emitFixed(Address address, Varnode base, long offset,
			long highBase, long innerMask, Varnode output, long uniqueBase) {
		if (base == null) {
			return new PcodeOp[] {
				op(address, 0, PcodeOp.COPY,
					new Varnode[] { constant(highBase + (offset & innerMask), 3) }, output)
			};
		}

		Varnode sum = unique(uniqueBase, 2);
		Varnode inner = sum;
		int operationCount = innerMask == 0xffffL ? 3 : 4;
		PcodeOp[] operations = new PcodeOp[operationCount];
		operations[0] = op(address, 0, PcodeOp.INT_ADD,
			new Varnode[] { base, constant(offset, 2) }, sum);
		int next = 1;
		if (innerMask != 0xffffL) {
			inner = unique(uniqueBase + 4, 2);
			operations[next] = op(address, next++, PcodeOp.INT_AND,
				new Varnode[] { sum, constant(innerMask, 2) }, inner);
		}
		Varnode extended = unique(uniqueBase + 8, 3);
		operations[next] = op(address, next++, PcodeOp.INT_ZEXT,
			new Varnode[] { inner }, extended);
		operations[next] = op(address, next, PcodeOp.INT_ADD,
			new Varnode[] { extended, constant(highBase, 3) }, output);
		return operations;
	}

	private PcodeOp[] emitRegisterPage(Address address, Varnode base, long offset,
			Register highRegister, int shift, long innerMask, Varnode output,
			long uniqueBase) {
		Varnode inner;
		int next = 0;
		int prefixCount;
		PcodeOp[] operations;
		if (base == null) {
			inner = constant(offset & innerMask, 3);
			prefixCount = 0;
			operations = new PcodeOp[4];
		}
		else {
			Varnode sum = unique(uniqueBase, 2);
			Varnode masked = unique(uniqueBase + 4, 2);
			inner = unique(uniqueBase + 8, 3);
			operations = new PcodeOp[7];
			operations[next] = op(address, next++, PcodeOp.INT_ADD,
				new Varnode[] { base, constant(offset, 2) }, sum);
			operations[next] = op(address, next++, PcodeOp.INT_AND,
				new Varnode[] { sum, constant(innerMask, 2) }, masked);
			operations[next] = op(address, next++, PcodeOp.INT_ZEXT,
				new Varnode[] { masked }, inner);
			prefixCount = 3;
		}

		long highUniqueBase = uniqueBase + (prefixCount == 0 ? 0 : 12);
		Varnode high = new Varnode(highRegister.getAddress(),
			highRegister.getMinimumByteSize());
		Varnode extendedHigh = unique(highUniqueBase, 3);
		Varnode shiftedHigh = unique(highUniqueBase + 4, 3);
		Varnode maskedHigh = unique(highUniqueBase + 8, 3);
		operations[next] = op(address, next++, PcodeOp.INT_ZEXT,
			new Varnode[] { high }, extendedHigh);
		operations[next] = op(address, next++, PcodeOp.INT_LEFT,
			new Varnode[] { extendedHigh, constant(shift, 4) }, shiftedHigh);
		operations[next] = op(address, next++, PcodeOp.INT_AND,
			new Varnode[] { shiftedHigh,
				constant(shift == 14 ? 0xffc000L : 0xff0000L, 3) }, maskedHigh);
		operations[next] = op(address, next, PcodeOp.INT_ADD,
			new Varnode[] { maskedHigh, inner }, output);
		return operations;
	}

	private PcodeOp[] emitRaw(Address address, Varnode base, long offset,
			Varnode output, long uniqueBase) {
		if (base == null) {
			return new PcodeOp[] {
				op(address, 0, PcodeOp.COPY,
					new Varnode[] { constant(offset & 0xffffL, 3) }, output)
			};
		}
		Varnode sum = unique(uniqueBase, 2);
		return new PcodeOp[] {
			op(address, 0, PcodeOp.INT_ADD,
				new Varnode[] { base, constant(offset & 0xffffL, 2) }, sum),
			op(address, 1, PcodeOp.INT_ZEXT, new Varnode[] { sum }, output)
		};
	}

	private EffectiveExt readEffectiveExt(Program program, Address address,
			String immediateName, String indexName, String modeName) {
		ProgramContext context = program.getProgramContext();
		if (isContextOne(context, modeName, address)) {
			Long index = readContext(context, indexName, address);
			Register register = index == null ? null : program.getRegister("r" + (index & 0xf));
			return register == null ? null : EffectiveExt.register(register);
		}
		Long immediate = readContext(context, immediateName, address);
		return immediate == null ? null : EffectiveExt.immediate(immediate);
	}

	private static boolean isContextOne(ProgramContext context, String name, Address address) {
		Long value = readContext(context, name, address);
		return value != null && value == 1L;
	}

	private static Long readContext(ProgramContext context, String name, Address address) {
		Register register = context.getRegister(name);
		BigInteger value = register == null ? null : context.getValue(register, address, false);
		return value == null ? null : value.longValue();
	}

	private AddressSpace constantSpace() {
		return language.getAddressFactory().getConstantSpace();
	}

	private Varnode constant(long value, int size) {
		return new Varnode(constantSpace().getAddress(value), size);
	}

	private Varnode unique(long offset, int size) {
		return new Varnode(language.getAddressFactory().getUniqueSpace().getAddress(offset), size);
	}

	private static PcodeOp op(Address address, int sequence, int opcode,
			Varnode[] inputs, Varnode output) {
		return new PcodeOp(address, sequence, opcode, inputs, output);
	}

	private record EffectiveExt(Long immediate, Register register) {
		static EffectiveExt immediate(long value) {
			return new EffectiveExt(value, null);
		}

		static EffectiveExt register(Register register) {
			return new EffectiveExt(null, register);
		}
	}
}
