extern crate clap;
extern crate elf;
extern crate rbpf;

use std::process;
use clap::{Arg, App};
use std::fs::File;
use std::io::Read;

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
        .arg(Arg::with_name("raw")
            .short("r")
            .long("raw")
            .help("Treat input as raw bytes"))
        .arg(Arg::with_name("list-sections")
            .short("l")
            .long("list")
            .help("List sections of the object file"))
        .arg(Arg::with_name("number")
            .short("n")
            .long("number")
            .help("Number all output lines"))
        .get_matches();

    let section = matches.value_of("section").unwrap_or(".classifier");
    let input_file = matches.value_of("INPUT").unwrap();
    let show_bytecode = matches.is_present("bytecode");
    let show_ccode = matches.is_present("ccode");
    let raw = matches.is_present("raw");
    let list_sections = matches.is_present("list-sections");
    let number = matches.is_present("number");

    if show_bytecode && show_ccode {
        println!("Can't show both bytecode and C code.");
        process::exit(1);
    }

    if raw && list_sections {
        println!("Can't list sections of raw bytecode.");
        process::exit(1);
    }

    let prog;
    if raw {
        let mut file = match File::open(&input_file) {
            Ok(f) => f,
            Err(e) => {
                println!("Could not read file.");
                println!("Error: {:?}", e);
                process::exit(1);
            }
        };

        let mut buf = Vec::new();
        match file.read_to_end(&mut buf) {
            Ok(_) => {},
            Err(e) => {
                println!("Could not read file.");
                println!("Error: {:?}", e);
                process::exit(1);
            }
        }
        prog = buf;
    } else {
        let file = match elf::File::open_path(&input_file) {
            Ok(f) => f,
            Err(e) => {
                println!("Could not read elf file.");
                println!("Error: {:?}", e);
                process::exit(1);
            }
        };

        if list_sections {
            println!("Sections of {}:", input_file);
            for section in file.sections {
                println!("  {}", section.shdr.name);
            }
            process::exit(0);
        }

        let text_scn = match file.get_section(&section) {
            Some(s) => s,
            None => {
                println!("Failed to lookup '{}' section.", section);
                process::exit(1);
            }
        };

        prog = text_scn.data.clone();
    }

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
            let off = (insn[3] as u16)<<8 | (insn[2] as u16);
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
        for (idx, insn) in rbpf::disassembler::to_insn_vec(&prog).iter().enumerate() {
            if number {
                print!("{:>6}  ", idx);
            }
            println!("{}", insn.desc.replace(" ", "\t"));
        }
    }
}
