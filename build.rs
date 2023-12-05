use std::env;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR should exist");
    protobuf_codegen::Codegen::new()
        .out_dir(out_dir)
        .inputs([
            "src/dcp_edek.proto",
            "src/cmk_edek.proto",
            "src/icl_header_v4.proto",
            "src/vector_encryption_metadata.proto",
            "src/icl_header_v3.proto",
        ])
        .include("src")
        .customize(
            protobuf_codegen::Customize::default()
                .tokio_bytes(true)
                .tokio_bytes_for_string(true),
        )
        .pure()
        .run()
        .expect("protobuf codegen failed");
}
