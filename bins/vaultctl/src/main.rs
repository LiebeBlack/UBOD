//! vaultctl — CLI del dispositivo móvil (simulador) para la bóveda.
//!
//! Flujo:
//!   1. `pair   <ip:puerto> <código> <device_id> [--ca ca.pem]` → guarda identidad.
//!   2. `ping   <ip:puerto>`            → verifica sesión mTLS.
//!   3. `manifest <ip:puerto>`          → hashes presentes en la bóveda.
//!   4. `upload <ip:puerto> <archivo> [--categoria C]` → envía y muestra el ACK.
//!   5. `discover`                      → busca bóvedas por mDNS en la LAN.
//!
//! La identidad del dispositivo queda en `./vaultctl-identity/` (cert.pem,
//! key.pem 0600, ca.pem, device_id). Reutilizable entre invocaciones.

use std::path::PathBuf;

use vault_client::{build_envelope, pair, upload_file, PairedDevice};

const IDENTITY_DIR: &str = "vaultctl-identity";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage_and_exit();
    }
    let cmd = args[0].clone();
    let rest = &args[1..];

    // Endurecimiento (Linux): el cliente sólo puede ESCRIBIR en su carpeta de
    // identidad. La lectura queda libre porque `upload` debe poder leer el
    // documento indicado esté donde esté.
    confine_writes();

    let code = match cmd.as_str() {
        "pair" => cmd_pair(rest),
        "ping" => cmd_ping(rest),
        "manifest" => cmd_manifest(rest),
        "upload" => cmd_upload(rest),
        "discover" => cmd_discover(rest),
        "--help" | "-h" | "help" => {
            print_usage_and_exit();
        }
        other => {
            eprintln!("comando desconocido: {other}");
            print_usage_and_exit();
        }
    };
    std::process::exit(code);
}

fn print_usage_and_exit() -> ! {
    println!("vaultctl — cliente del dispositivo móvil para la bóveda académica");
    println!();
    println!("USO:");
    println!("  vaultctl discover                          busca bóvedas en la LAN (mDNS)");
    println!("  vaultctl pair <addr> <código> <device_id>  empareja con código de un solo uso");
    println!("  vaultctl ping <addr>                       verifica la sesión mTLS");
    println!("  vaultctl manifest <addr>                   lista hashes de la bóveda");
    println!("  vaultctl upload <addr> <archivo> [--categoria C]  envía un documento");
    println!();
    println!("La identidad del dispositivo se guarda en ./{IDENTITY_DIR}/");
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// Confina la ESCRITURA del cliente a su carpeta de identidad (Linux; en otros
/// sistemas no hace nada).
///
/// La carpeta se crea antes porque Landlock no puede conceder acceso a una ruta
/// que todavía no existe. Un fallo no es fatal: el comando sigue adelante sin
/// confinamiento y se avisa por la salida de error.
fn confine_writes() {
    #[cfg(unix)]
    {
        let dir = identity_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("aviso: no se pudo preparar {}: {e}", dir.display());
            return;
        }
        let abs = std::fs::canonicalize(&dir).unwrap_or(dir);
        if let Err(e) = vault_fs::apply_landlock_write_only(&[abs.as_path()]) {
            eprintln!("aviso: confinamiento de escritura no aplicado: {e}");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = identity_dir();
    }
}

fn identity_dir() -> PathBuf {
    PathBuf::from(IDENTITY_DIR)
}

fn load_identity() -> (PairedDevice, String) {
    let dir = identity_dir();
    let read = |name: &str| -> String {
        std::fs::read_to_string(dir.join(name)).unwrap_or_else(|_| {
            fail(&format!(
                "sin identidad: falta {name} en {IDENTITY_DIR}/ (ejecute pair primero)"
            ))
        })
    };
    let device = PairedDevice {
        device_id: read("device_id").trim().to_string(),
        cert_pem: read("cert.pem"),
        key_pem: read("key.pem"),
        fingerprint: read("fingerprint").trim().to_string(),
    };
    let ca = read("ca.pem");
    (device, ca)
}

fn save_identity(device: &PairedDevice, ca_pem: &str) -> Result<(), String> {
    let dir = identity_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("crear {IDENTITY_DIR}/: {e}"))?;
    for (name, content) in [
        ("device_id", &device.device_id),
        ("cert.pem", &device.cert_pem),
        ("key.pem", &device.key_pem),
        ("fingerprint", &device.fingerprint),
        ("ca.pem", &ca_pem.to_string()),
    ] {
        std::fs::write(dir.join(name), content).map_err(|e| format!("guardar {name}: {e}"))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(dir.join("key.pem"), std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Obtiene la CA de la bóveda: del argumento --ca (ruta o PEM) o de la
/// identidad previa guardada por un `pair` anterior.
fn resolve_ca(explicit: Option<&str>) -> String {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if path.exists() {
            return std::fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("--ca: {e}")));
        }
        // puede ser el PEM directamente
        if p.contains("BEGIN CERTIFICATE") {
            return p.to_string();
        }
        fail(&format!("--ca {p}: archivo no encontrado"));
    }
    let ca_path = identity_dir().join("ca.pem");
    if ca_path.exists() {
        return std::fs::read_to_string(&ca_path)
            .unwrap_or_else(|e| fail(&format!("ca.pem de la identidad: {e}")));
    }
    fail("sin CA de la bóveda: indique --ca <ca.pem> (la bóveda la exporta en el emparejamiento)");
}

fn parse_addr(s: &str) -> std::net::SocketAddr {
    // acepta ip:puerto o hostname:puerto (resuelve A/AAAA)
    if let Ok(a) = s.parse() {
        return a;
    }
    let (host, port) = s
        .rsplit_once(':')
        .unwrap_or_else(|| fail("dirección inválida: espere host:puerto"));
    use std::net::ToSocketAddrs;
    (
        host,
        port.parse::<u16>()
            .unwrap_or_else(|_| fail("puerto inválido")),
    )
        .to_socket_addrs()
        .unwrap_or_else(|e| fail(&format!("resolución de {host}: {e}")))
        .next()
        .unwrap_or_else(|| fail("sin direcciones para el host"))
}

fn cmd_pair(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("uso: vaultctl pair <addr> <código> <device_id> [--ca ca.pem]");
        return 2;
    }
    let (rest, ca_arg) = strip_flag(args, "--ca");
    if rest.len() < 3 {
        eprintln!("uso: vaultctl pair <addr> <código> <device_id> [--ca ca.pem]");
        return 2;
    }
    let addr = parse_addr(&rest[0]);
    let code = rest[1].clone();
    let device_id = rest[2].clone();
    // Para pair hace falta la CA del servidor (confianza del canal anónimo).
    let ca = resolve_ca(ca_arg.as_deref());

    match pair(addr, &ca, &code, &device_id) {
        Ok(device) => {
            if let Err(e) = save_identity(&device, &ca) {
                eprintln!("✗ emparejado, pero no se pudo guardar la identidad: {e}");
                return 1;
            }
            println!("✓ dispositivo emparejado: {}", device.device_id);
            println!("  huella del certificado: {}", device.fingerprint);
            println!("  identidad guardada en {IDENTITY_DIR}/");
            0
        }
        Err(e) => {
            eprintln!("✗ emparejamiento falló: {e}");
            1
        }
    }
}

fn cmd_ping(args: &[String]) -> i32 {
    let Some(addr_s) = args.first() else {
        eprintln!("uso: vaultctl ping <addr>");
        return 2;
    };
    let addr = parse_addr(addr_s);
    let (device, ca) = load_identity();
    match vault_client::ping(addr, &device, &ca) {
        Ok(true) => {
            println!(
                "✓ bóveda viva y dispositivo autorizado ({})",
                device.device_id
            );
            0
        }
        Ok(false) => {
            eprintln!("✗ la bóveda respondió pero rechazó la sesión (¿certificado revocado?)");
            1
        }
        Err(e) => {
            eprintln!("✗ sin contacto: {e}");
            1
        }
    }
}

fn cmd_manifest(args: &[String]) -> i32 {
    let Some(addr_s) = args.first() else {
        eprintln!("uso: vaultctl manifest <addr>");
        return 2;
    };
    let addr = parse_addr(addr_s);
    let (device, ca) = load_identity();
    let tls = match vault_sync::client::load_client_tls(
        &device.cert_pem,
        &device.key_pem,
        &ca,
        "vault.local",
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("✗ identidad inválida: {e}");
            return 1;
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let result = rt.block_on(async move {
        let client = vault_sync::client::VaultClient::connect(&tls, addr)?;
        client.manifest().await
    });
    match result {
        Ok(resp) if resp.status == 200 => {
            println!("{}", resp.text());
            0
        }
        Ok(resp) => {
            eprintln!("✗ HTTP {}: {}", resp.status, resp.text());
            1
        }
        Err(e) => {
            eprintln!("✗ sin contacto: {e}");
            1
        }
    }
}

/// Extrae `--flag valor` (o `--flag=valor`) de los argumentos y devuelve el
/// resto junto al valor, si lo había. Un flag sin valor se descarta sin
/// romper la línea de órdenes.
fn strip_flag(args: &[String], flag: &str) -> (Vec<String>, Option<String>) {
    let with_eq = format!("{flag}=");
    let mut rest = Vec::with_capacity(args.len());
    let mut value = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == flag {
            if let Some(v) = args.get(i + 1) {
                value = Some(v.clone());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(v) = a.strip_prefix(&with_eq) {
            value = Some(v.to_string());
            i += 1;
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    (rest, value)
}

fn cmd_upload(args: &[String]) -> i32 {
    let (rest, category) = strip_flag(args, "--categoria");
    if rest.len() < 2 {
        eprintln!("uso: vaultctl upload <addr> <archivo> [--categoria C]");
        return 2;
    }
    let addr = parse_addr(&rest[0]);
    let file = PathBuf::from(&rest[1]);
    if !file.exists() {
        fail(&format!("archivo no encontrado: {}", file.display()));
    }
    let (device, ca) = load_identity();

    // previsualizar el envelope antes de enviar
    let (envelope, size) = match build_envelope(&file, &device.device_id, category.as_deref()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("✗ {e}");
            return 1;
        }
    };
    println!(
        "→ enviando {} ({} bytes) como {}",
        envelope.payload.file_name, size, envelope.payload.file_category
    );

    match upload_file(addr, &device, &ca, &file, category.as_deref()) {
        Ok(ack) => {
            println!("← ACK de la bóveda:");
            println!("{}", serde_json::to_string_pretty(&ack).unwrap_or_default());
            0
        }
        Err(e) => {
            eprintln!("✗ envío rechazado: {e}");
            1
        }
    }
}

fn cmd_discover(args: &[String]) -> i32 {
    let timeout_ms: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(3000);
    println!("buscando bóvedas en la LAN ({} ms)…", timeout_ms);
    let found = vault_sync::mdns::discover(timeout_ms);
    if found.is_empty() {
        println!("(ninguna bóveda visible; verifique que vaultd corre con enable_sync)");
        return 1;
    }
    for f in &found {
        println!("  ✓ bóveda en {f}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_numeric_and_host() {
        assert_eq!(parse_addr("127.0.0.1:8642").to_string(), "127.0.0.1:8642");
        // localhost resuelve
        assert!(parse_addr("localhost:8642").port() == 8642);
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Prueba el parseo REAL (no una copia): extrae el valor y deja solo los
    /// argumentos posicionales, en sus dos formas.
    #[test]
    fn strip_flag_extracts_value_and_leaves_positionals() {
        let a = args(&["1.2.3.4:9000", "file.pdf", "--categoria", "Tesis"]);
        let (rest, val) = strip_flag(&a, "--categoria");
        assert_eq!(rest, args(&["1.2.3.4:9000", "file.pdf"]));
        assert_eq!(val.as_deref(), Some("Tesis"));

        // forma --flag=valor
        let a = args(&["addr", "file.pdf", "--categoria=Acta de Grado"]);
        let (rest, val) = strip_flag(&a, "--categoria");
        assert_eq!(rest, args(&["addr", "file.pdf"]));
        assert_eq!(val.as_deref(), Some("Acta de Grado"));

        // sin el flag no se toca nada
        let a = args(&["addr", "file.pdf"]);
        let (rest, val) = strip_flag(&a, "--categoria");
        assert_eq!(rest, args(&["addr", "file.pdf"]));
        assert!(val.is_none());

        // flag al final sin valor: se descarta sin romper
        let a = args(&["addr", "--categoria"]);
        let (rest, val) = strip_flag(&a, "--categoria");
        assert_eq!(rest, args(&["addr"]));
        assert!(val.is_none());

        // un flag con valor no se confunde con el nombre de un archivo
        let a = args(&[
            "--ca",
            "~/.boveda/data/ca.pem",
            "1.2.3.4:9000",
            "código",
            "AND_1",
        ]);
        let (rest, val) = strip_flag(&a, "--ca");
        assert_eq!(rest, args(&["1.2.3.4:9000", "código", "AND_1"]));
        assert_eq!(val.as_deref(), Some("~/.boveda/data/ca.pem"));
    }
}
