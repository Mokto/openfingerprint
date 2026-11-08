// The descriptor set is committed so the build needs no protoc. After editing
// proto/openfingerprint.proto, regenerate it:
//   protoc -I proto --include_imports --descriptor_set_out=proto/openfingerprint.fds.bin proto/openfingerprint.proto
// api/test-proto.mjs fails when the two differ.
fn main() {
    connectrpc_build::Config::new()
        .descriptor_set("proto/openfingerprint.fds.bin")
        .files(&["openfingerprint.proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .unwrap();
    println!("cargo:rerun-if-changed=proto/openfingerprint.fds.bin");
}
