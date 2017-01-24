extern crate clap;
extern crate elf;
extern crate rbpf;

use std::process;
use clap::{Arg, App};

fn main() {
    let matches = App::new("ebpf-disasm")
        .version("1.0")
        .author("Jan-Erik Rediger")
        .about("Output disassembled eBPF read from an ELF file")
        .arg(Arg::with_name("section")
             .short("s")
             .long("section")
             .value_name("SECTION")
             .help("Specify a section name")
             .takes_value(true))
        .arg(Arg::with_name("INPUT")
             .help("Sets the input ELF file to use")
             .required(true)
             .index(1))
        .arg(Arg::with_name("bytecode")
            .short("b")
            .long("bytecode")
            .help("Only show raw bytecode"))
        .arg(Arg::with_name("ccode")
            .short("c")
            .long("ccode")
            .help("Only show a C compatible bpf_insn array"))
        .get_matches();

    let section = matches.value_of("section").unwrap_or(".classifier");
    let input_file = matches.value_of("INPUT").unwrap();
    let show_bytecode = matches.is_present("bytecode");
    let show_ccode = matches.is_present("ccode");

    if show_bytecode && show_ccode {
        println!("Can't show both bytecode and C code.");
        process::exit(1);
    }

    let file = match elf::File::open_path(&input_file) {
        Ok(f) => f,
        Err(e) => {
            println!("Could not read elf file.");
            println!("Error: {:?}", e);
            process::exit(1);
        }
    };

    let text_scn = match file.get_section(&section) {
        Some(s) => s,
        None => {
            println!("Failed to lookup '{}' section.", section);
            process::exit(1);
        }
    };

    let prog = &text_scn.data;

    if show_bytecode {
        for insn in prog.chunks(8) {
            for i in insn {
                print!("0x{:>02x}, ", i);
            }
            println!("");
        }
    } else if show_ccode {
        println!("struct bpf_insn prog[] = {{");
        for insn in prog.chunks(8) {
            print!("\t{{ ");
            print!(".code = 0x{:>02x}, ", insn[0]);
            print!(".dst_reg = 0x{:>x}, ", insn[1]&0x0f);
            print!(".src_reg = 0x{:>x}, ", insn[1]>>4);
            let off = (insn[2] as u16)<<8 | (insn[3] as u16);
            print!(".off = 0x{:>04x}, ", off);
            let imm = (insn[7] as u32)<<24 |
                (insn[6] as u32)<<16 |
                (insn[5] as u32)<<8 |
                (insn[4] as u32)<<0;
            print!(".imm = 0x{:>08x}", imm);
            println!(" }},");
        }
        println!("}};");
    } else {
        for insn in rbpf::disassembler::to_insn_vec(prog) {
            println!("{}", insn.desc.replace(" ", "\t"));
        }
    }
}
