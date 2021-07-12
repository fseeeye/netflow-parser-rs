#[macro_use]
extern crate clap;
use clap::App;
use colored::*;

use std::process;
use std::fs::metadata;
use std::path::Path;
use std::ffi::OsStr;

use parsing_pcap::parse_pcap;
use walkdir::{DirEntry, WalkDir};

fn main() {
    let args = Args::new().unwrap_or_else(|e| {
        eprintln!(
            "[!] Problem parsing arguments: {}",
            e.to_string().color("red")
        );
        process::exit(1);
    });

    for path in args.paths.iter() {
        let path_metadata = match metadata(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "[!] Metadata analysis Error: {}",
                    e.to_string().color("red")
                );
                process::exit(1);
            }
        };

        if path_metadata.is_file() { // 解析单个pcap文件
            println!("[*] Parsing File: {}", path.color("cyan"));
            parse_pcap(path)
        } else if path_metadata.is_dir() { // 解析文件夹下所有pcap文件
            println!("[*] Parsing Dir: {}", path.color("cyan"));
            let files: Vec<DirEntry> = WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .collect();
            for entry in files {
                let file_path = entry.path().to_str().unwrap(); // Warning: unhandle error.
                // ref: https://stackoverflow.com/questions/45291832/extracting-a-file-extension-from-a-given-path-in-rust-idiomatically
                let file_extension = Path::new(file_path).extension().and_then(OsStr::to_str);
                if file_extension == Some("pcap") {
                    println!("[*] Parsing Sub File: {} of {}", file_path.color("cyan") ,path.color("cyan"));
                    parse_pcap(file_path)
                }
            }
        }
    }
}

// 程序参数配置
struct Args {
    paths: Vec<String>,
}

impl Args {
    fn new() -> Result<Args, &'static str> {
        /* 读取命令行参数 */
        let yaml = load_yaml!("cli.yml");
        let matches = App::from_yaml(yaml).get_matches();

        if !matches.is_present("paths") { 
            return Err("please set arg 'path'")
        } else {
            let paths: Vec<String> = matches
                .values_of("paths")
                .unwrap()
                .map(|s| s.to_string())
                .collect();
            if paths.is_empty() { 
                return Err("empty arg 'paths'");
            }
            Ok(Args { paths })
        }
    }
}