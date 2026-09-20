fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(galata_vault_cli::run_with(
        &galata_vault_cli::Branding::GV,
        std::env::args_os(),
    ))
}
