# Phoenix ARM64 Disassembly Analyzer

Read-only analyzer for textual ARM64 disassembly listings, such as output produced by LLVM's llvm-objdump. Python 3.10+; standard library only.

## Produce a listing

    llvm-objdump --arch=arm64 --disassemble --no-show-raw-insn kernel-or-object > listing.txt

Exact options vary by LLVM version and Mach-O input format. Preserve the original binary, tool version, command line, and hashes alongside the listing.

## Analyze one or more listings

    python tools/phoenix-arm64-disasm/phoenix_arm64_disasm.py \
      --source pmu-before=reports/pmu-before.txt \
      --source pmu-after=reports/pmu-after.txt \
      --out-json reports/arm64-analysis.json \
      --out-md reports/arm64-analysis.md

Or compare two address-aligned listings:

    python tools/phoenix-arm64-disasm/phoenix_arm64_disasm.py \
      --before reports/before.txt --after reports/after.txt

## Current analysis

- Parses address-prefixed disassembly lines.
- Identifies branch, call, return, and conditional-branch instructions when numeric targets are printed.
- Records ADRP page-address instructions and conservatively associates a nearby ADD using the same source register.
- Records immediate ADD/SUB patterns and common compare/test instructions.
- Compares before/after listings by instruction address.
- Records SHA-256 hashes and emits JSON plus Markdown reports.

## Important limitations

This tool does **not** decode raw ARM64 machine code. It analyzes text emitted by a disassembler. ADRP+ADD association is a heuristic, not complete symbolic execution. It does not model every instruction alias, register/flag effect, memory operation, branch reachability, relocation, or control-flow path. Symbolic branch targets may remain unresolved. Before/after diffs are meaningful only when listings use comparable address spaces, symbols, and disassembler settings.

No patcher is executed. No IPSW is built or restored. No device or firmware is modified. A report is research evidence, not proof of A9 compatibility or patch safety.
