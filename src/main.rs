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
        .get_matches();

    let section = matches.value_of("section").unwrap_or(".classifier");
    let input_file = matches.value_of("INPUT").unwrap();
    let show_bytecode = matches.is_present("bytecode");

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
    } else {
        for insn in rbpf::disassembler::to_insn_vec(prog) {
            println!("{}", insn.desc.replace(" ", "\t"));
        }
    }
}
