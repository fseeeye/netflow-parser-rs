extern crate cbindgen;

use std::{env, path::PathBuf};

fn main() {
	let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let bindings = cbindgen::generate(crate_dir)
    	.expect("Unable to generate bindings");
    
	let out_path = PathBuf::from("./output/"); // 在此修改头文件输出路径
	
	// bindings.write_to_file(out_path.join(format!("{}.h", env::var("CARGO_PKG_NAME").unwrap().replace("-", "_"))));
    bindings.write_to_file(out_path.join("parser_rs.h"));
}