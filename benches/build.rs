fn main() {
    println!("cargo:rustc-link-lib=pypkt"); //指定库
    println!("cargo:rerun-if-changed=/usr/local/include/pypkt/dissect.h");
    let bindings = bindgen::Builder::default()
        .header("/usr/local/include/pypkt/dissect.h") //指定头文件，可以指定多个.h文件作为输入
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file("./benches/parsing/output.rs")
        .expect("Couldn't write bindings!"); //输出到那个目录
}
