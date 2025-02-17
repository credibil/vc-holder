use std::path::PathBuf;

use crux_core::typegen::TypeGen;
use crux_http::HttpError;
use wallet::{App, Aspect};

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../shared");

    let mut gen = TypeGen::new();
    let out_dir = PathBuf::from("./generated");
    gen.register_app::<App>()?;
    
    // Register types from crux capability crates that the code generator is
    // having trouble with.
    gen.register_type::<HttpError>()?;


    // Register other types the code generator is having trouble inferring
    gen.register_type::<Aspect>()?;

    gen.swift("SharedTypes", out_dir.join("swift"))?;
    gen.java("io.credibil.wallet.shared_types", out_dir.join("java"))?;
    gen.typescript("shared_types", out_dir.join("typescript"))?;

    Ok(())
}
