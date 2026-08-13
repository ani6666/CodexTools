#![forbid(unsafe_code)]
// Cargo package 依赖由 library target 使用；二进制只负责调用统一入口。
#![allow(unused_crate_dependencies)]

fn main() {
    codextools_desktop_lib::run();
}
