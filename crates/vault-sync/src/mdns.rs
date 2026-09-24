//! Descubrimiento mDNS: anuncia la bóveda como `_vaultsync._tcp.local.`
//! para que los móviles la detecten sin configurar IPs.

/// Handle del anuncio mDNS; se retira al soltarlo.
pub struct MdnsGuard {
    _service: mdns_sd::ServiceDaemon,
}

/// Registra el anuncio `_vaultsync._tcp.local.` en todas las interfaces.
pub fn announce(port: u16, instance: &str) -> Result<MdnsGuard, String> {
    let service = mdns_sd::ServiceDaemon::new().map_err(|e| e.to_string())?;
    let props = [
        ("proto".to_string(), "1".to_string()),
        ("tls".to_string(), "mtls".to_string()),
    ];
    let service_info = mdns_sd::ServiceInfo::new(
        "_vaultsync._tcp.local.",
        instance,
        &format!("{instance}.local."),
        "",
        port,
        &props[..],
    )
    .map_err(|e| e.to_string())?
    .enable_addr_auto();
    service.register(service_info).map_err(|e| e.to_string())?;
    tracing::info!("mDNS: anunciando _vaultsync._tcp.local. en puerto {port}");
    Ok(MdnsGuard { _service: service })
}

/// Descubre bóvedas en la red (para vaultctl/simulador de móvil).
pub fn discover(timeout_ms: u64) -> Vec<String> {
    let service = match mdns_sd::ServiceDaemon::new() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let receiver = match service.browse("_vaultsync._tcp.local.") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut found = Vec::new();
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(std::time::Duration::from_millis(300)) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                let host = info.get_hostname().trim_end_matches('.').to_string();
                let ip = info
                    .get_addresses_v4()
                    .iter()
                    .next()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| host.clone());
                found.push(format!("{ip}:{}", info.get_port()));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = service.stop_browse("_vaultsync._tcp.local.");
    found
}

#[cfg(test)]
mod tests {
    #[test]
    fn discover_returns_without_crash() {
        // en entornos sin mDNS disponible devuelve lista vacía, no pánico
        let _ = super::discover(200);
    }
}
