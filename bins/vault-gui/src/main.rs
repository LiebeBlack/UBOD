//! vault-gui — punto de entrada gráfico (sin consola).
//!
//! El usuario ejecuta `vault-gui` desde el menú/escritorio y TODO sucede en
//! ventanas: bootstrap, login por roles, gestión documental, auditoría.
//! Ningún flujo requiere terminal.
fn main() -> Result<(), eframe::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init()
        .ok();
    vault_gui::run_gui()
}
