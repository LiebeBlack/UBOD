//! vault-gui — punto de entrada gráfico (sin consola).
//!
//! El usuario ejecuta `vault-gui` desde el menú/escritorio y TODO sucede en
//! ventanas: bootstrap, login por roles, gestión documental, auditoría.
//! Ningún flujo requiere terminal.
//!
//! La administración de usuarios y sistema sólo se habilita con el argumento
//! `--ITA`, pensado para lanzarse explícitamente desde una terminal; además
//! exige una sesión de administración vigente abierta por la consola `vault-it`.
//!
//! Uso:
//!   vault-gui [--ITA] [--no-landlock]

use vault_gui::{GuiOptions, ItMode};

fn print_help() {
    println!("vault-gui — aplicación de escritorio de la bóveda académica");
    println!();
    println!("  --ITA            habilita las pantallas de administración de esta ejecución");
    println!("                   (requiere además una sesión abierta con «vault-it door open»)");
    println!("  --no-landlock    no confina la escritura del proceso a la bóveda (Linux)");
    println!("  --help, -h       muestra esta ayuda");
    println!();
    println!("Sin argumentos la aplicación se abre en modo usuario: gestión documental");
    println!("según el rol de la sesión, sin ninguna pantalla de administración.");
}

fn main() -> Result<(), eframe::Error> {
    let mut options = GuiOptions::default();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            // La habilitación es explícita y viene siempre de la línea de
            // órdenes: nunca se activa desde la interfaz ni desde un archivo.
            "--ITA" => options.it_mode = ItMode::ConsoleLaunched,
            "--no-landlock" => options.landlock = false,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                eprintln!("argumento desconocido: {other} (vea --help)");
                std::process::exit(2);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init()
        .ok();

    vault_gui::run_gui(options)
}
