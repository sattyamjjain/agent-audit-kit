pub fn session_exists(token: &str) -> bool {
    let path = format!("sessions/{}.session", token);
    std::fs::metadata(path).is_ok()
}
