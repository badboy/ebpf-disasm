# ebpf-disasm

A simple eBPF disassembler, based on [rbpf](https://github.com/qmonnet/rbpf).

It loads the compiled eBPF code from an ELF file and prints it out.

## Installation

```
cargo install --git https://github.com/badboy/ebpf-disasm
```

## Usage

If your code is in the section `.classifier` of your ELF file `bpf.o`:

```
ebpf-disasm --section .classifier bpf.o
```

### Example output

```
$ ebpf-disasm -s .classifier bpf.o
mov64	r6,	r1
ldabsh	0x4
mov64	r7,	r0
ldabsw	0x0
lsh64	r0,	0x10
or64	r0,	r7
stxdw	[r10+0xfff8],	r0
mov64	r2,	r10
add64	r2,	0xfffffff8
lddw	r1,	0x0
call	0x1
jeq	r0,	0x0,	+0x5
ldxw	[r3+0x0],	r0
mov64	r1,	r6
lddw	r2,	0x0
call	0xc
mov64	r0,	0x0
exit
```

## License

MIT. See [LICENSE](LICENSE).
