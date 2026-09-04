#![forbid(unsafe_code)]

/// This command is a deliberately narrow smoke seam proving that the desktop
/// shell links the native crypto boundary without ever exposing key material.
#[tauri::command]
fn native_protocol_status() -> String {
    crypto_ffi::protocol_status()
}

#[cfg(test)]
mod tests {
    use super::native_protocol_status;

    #[test]
    fn desktop_shell_links_the_implemented_native_protocol() {
        assert_eq!(native_protocol_status(), "crypto-envelope/v1");
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![native_protocol_status])
        .run(tauri::generate_context!())
        .expect("failed to run desktop application");
}
