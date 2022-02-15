/// 启用日志输出
#[no_mangle]
pub extern "C" fn enable_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
}