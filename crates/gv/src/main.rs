fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(galata_vault::cli::run_with(
        &galata_vault::cli::Branding::GV,
        std::env::args_os(),
    ))
}
