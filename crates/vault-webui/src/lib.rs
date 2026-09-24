//! vault-webui: panel de administración local de la bóveda.
//!
//! Servidor HTTP ligero (std::net + hilos, sin dependencias de red extra) que
//! escucha SOLO en 127.0.0.1 y expone:
//!
//! - `GET  /`                  → interfaz HTML autocontenida (sin JS externo).
//! - `POST /api/login`         → {pin} → {token} (sesión con TTL).
//! - `POST /api/logout`        → cierra la sesión.
//! - `GET  /api/state`         → resumen: pendientes, documentos, dispositivos, settings.
//! - `GET  /api/documents?q=`  → búsqueda compuesta (vault-index).
//! - `POST /api/admit`         → {submission_id} → ACK de sellado.
//! - `POST /api/reject`        → {submission_id, reason}.
//! - `POST /api/destroy`       → {vault_id, admin_pin, destruction_pin, justification}.
//! - `POST /api/pairing-code`  → genera código de un solo uso para móviles.
//! - `POST /api/sweep`         → barrido de integridad inmediato.
//! - `GET  /api/audit`         → cadena de auditoría (verificada).
//!
//! Todas las rutas `/api/*` salvo `login` exigen cabecera `Authorization: Bearer <token>`.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex as StdMutex};

use serde_json::{json, Value};
use vault_admin::AdminService;
use vault_index::SearchQuery;

/// Cuánto vive una sesión del panel (segundos).
const SESSION_TTL_SECS: u64 = 15 * 60;

/// Estado compartido del panel. El `AdminService` llega compartido con el
/// resto del daemon (`Arc<Mutex<…>>`): una sola vista de la BD cifrada.
pub struct WebUiState {
    pub admin: Arc<StdMutex<AdminService>>,
    sessions: StdMutex<HashMap<String, u64>>,
}

impl WebUiState {
    pub fn new(admin: Arc<StdMutex<AdminService>>) -> Arc<Self> {
        Arc::new(WebUiState {
            admin,
            sessions: StdMutex::new(HashMap::new()),
        })
    }

    fn create_session(&self) -> String {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("os randomness");
        let token: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let now = now_epoch();
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), now + SESSION_TTL_SECS);
        token
    }

    fn check_session(&self, token: &str) -> bool {
        let now = now_epoch();
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(&exp) if exp > now => {
                sessions.insert(token.to_string(), now + SESSION_TTL_SECS);
                true
            }
            _ => {
                sessions.remove(token);
                false
            }
        }
    }

    fn drop_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Error de la capa web (ya listo para serializar como JSON).
fn err_json(code: u16, msg: &str) -> (u16, Value) {
    (code, json!({ "error": msg }))
}

/// Maneja una petición ya parseada y devuelve (status, JSON).
fn route(
    state: &WebUiState,
    method: &str,
    path: &str,
    query: &str,
    token: Option<&str>,
    body: &Value,
) -> (u16, Value) {
    // ---- públicos ----
    if method == "POST" && path == "/api/login" {
        let pin = body["pin"].as_str().unwrap_or_default();
        let mut admin = state.admin.lock().unwrap();
        match admin.login(pin) {
            Ok(_) => {
                let t = state.create_session();
                (200, json!({ "token": t }))
            }
            Err(e) => err_json(403, &e.to_string()),
        }
    }
    // ---- con sesión ----
    else {
        let Some(tok) = token else {
            return err_json(401, "sesión requerida");
        };
        if !state.check_session(tok) {
            return err_json(401, "sesión expirada o inválida");
        }
        match (method, path) {
            ("POST", "/api/logout") => {
                state.drop_session(tok);
                (200, json!({ "ok": true }))
            }
            ("GET", "/api/state") => handle_state(state),
            ("GET", "/api/documents") => handle_documents(state, query),
            ("POST", "/api/admit") => {
                let Some(id) = body["submission_id"].as_str() else {
                    return err_json(400, "submission_id requerido");
                };
                let mut admin = state.admin.lock().unwrap();
                match admin.admit(id, "panel") {
                    Ok(ack) => (200, serde_json::to_value(&ack).unwrap_or_default()),
                    Err(e) => err_json(422, &e.to_string()),
                }
            }
            ("POST", "/api/reject") => {
                let Some(id) = body["submission_id"].as_str() else {
                    return err_json(400, "submission_id requerido");
                };
                let reason = body["reason"].as_str().unwrap_or("sin motivo");
                let mut admin = state.admin.lock().unwrap();
                match admin.reject(id, reason, "panel") {
                    Ok(()) => (200, json!({ "ok": true })),
                    Err(e) => err_json(422, &e.to_string()),
                }
            }
            ("POST", "/api/destroy") => {
                let vault_id = body["vault_id"].as_str().unwrap_or_default();
                let admin_pin = body["admin_pin"].as_str().unwrap_or_default();
                let d_pin = body["destruction_pin"].as_str().unwrap_or_default();
                let justification = body["justification"].as_str().unwrap_or_default();
                if justification.is_empty() {
                    return err_json(400, "justification requerida");
                }
                let mut admin = state.admin.lock().unwrap();
                match admin.destroy(vault_id, admin_pin, d_pin, justification, "panel") {
                    Ok(()) => (
                        200,
                        json!({ "ok": true, "message": "destrucción ejecutada" }),
                    ),
                    Err(e) => err_json(422, &e.to_string()),
                }
            }
            ("POST", "/api/pairing-code") => {
                let mut admin = state.admin.lock().unwrap();
                match admin.new_pairing_code() {
                    Ok(code) => (200, json!({ "code": code, "ttl_secs": 600 })),
                    Err(e) => err_json(403, &e.to_string()),
                }
            }
            ("POST", "/api/destruction-pin") => {
                let new_pin = body["destruction_pin"].as_str().unwrap_or_default();
                let mut admin = state.admin.lock().unwrap();
                match admin.set_destruction_pin(tok, new_pin) {
                    Ok(()) => (200, json!({ "ok": true })),
                    Err(e) => err_json(422, &e.to_string()),
                }
            }
            ("POST", "/api/sweep") => {
                let mut admin = state.admin.lock().unwrap();
                let layout = vault_fs::VaultLayout::new(admin.vault_root());
                match vault_audit::sweep(admin.db_mut(), &layout) {
                    Ok(r) => (200, serde_json::to_value(&r).unwrap_or_default()),
                    Err(e) => err_json(500, &e.to_string()),
                }
            }
            ("GET", "/api/audit") => {
                let admin = state.admin.lock().unwrap();
                let entries: Vec<Value> = admin
                    .db()
                    .audit()
                    .iter()
                    .map(|a| {
                        json!({
                            "seq": a.seq,
                            "timestamp": a.timestamp,
                            "actor": a.actor,
                            "action": a.action,
                            "subject": a.subject,
                            "detail": a.detail,
                        })
                    })
                    .collect();
                let chain_ok = admin.db().verify_audit_chain().is_ok();
                (200, json!({ "chain_ok": chain_ok, "entries": entries }))
            }
            _ => err_json(404, "ruta no encontrada"),
        }
    }
}

fn handle_state(state: &WebUiState) -> (u16, Value) {
    let admin = state.admin.lock().unwrap();
    let db = admin.db();
    let settings = db.settings();
    let documents: Vec<Value> = db.documents().iter().map(doc_json).collect();
    let pending: Vec<Value> = admin
        .pending_submissions()
        .iter()
        .map(|s| {
            json!({
                "submission_id": s.submission_id,
                "device_id": s.device_id,
                "received_at": s.received_at,
                "sha256": s.sha256,
                "size_bytes": s.size_bytes,
                "meta": {
                    "title": s.meta.title,
                    "category": s.meta.category.dir_name(),
                    "author": s.meta.author,
                    "department": s.meta.department,
                    "file_name": s.meta.file_name,
                    "academic_year": s.meta.academic_year,
                },
            })
        })
        .collect();
    let devices: Vec<Value> = db
        .devices()
        .iter()
        .map(|d| {
            json!({
                "device_id": d.device_id,
                "cert_fingerprint": d.cert_fingerprint,
                "paired_at": d.paired_at,
                "enabled": d.enabled,
            })
        })
        .collect();
    (
        200,
        json!({
            "has_pin": db.admin_pin_hash().is_some(),
            "has_destruction_pin": admin.has_destruction_pin(),
            "admin_lockout_secs": admin.admin_lockout_secs(),
            "destruction_lockout_secs": admin.destruction_lockout_secs(),
            "pending": pending,
            "documents": documents,
            "devices": devices,
            "audit_len": db.audit().len(),
            "audit_chain_ok": db.verify_audit_chain().is_ok(),
            "settings": {
                "tsa_url": settings.tsa_url,
                "admission_required_categories": settings.admission_required_categories,
                "destruction_grace_secs": settings.destruction_grace_secs,
                "sweep_interval_secs": settings.sweep_interval_secs,
            },
        }),
    )
}

fn doc_json(d: &vault_core::Document) -> Value {
    json!({
        "vault_id": d.vault_id,
        "title": d.meta.title,
        "category": d.meta.category.dir_name(),
        "author": d.meta.author,
        "department": d.meta.department,
        "academic_year": d.meta.academic_year,
        "file_name": d.meta.file_name,
        "extension": d.meta.extension,
        "size_bytes": d.size_bytes,
        "sha256": d.sha256,
        "rel_path": d.rel_path,
        "integrity": format!("{:?}", d.integrity).to_lowercase(),
        "rfc3161_time": d.rfc3161_time,
        "origin_device": d.origin_device,
        "registered_at": d.meta.registered_at,
    })
}

fn handle_documents(state: &WebUiState, query: &str) -> (u16, Value) {
    // extraer y decodificar el parámetro `q`
    let raw = query
        .split('&')
        .find_map(|kv| {
            kv.split_once('=')
                .filter(|(k, _)| *k == "q")
                .map(|(_, v)| v)
        })
        .unwrap_or("");
    let decoded = percent_decode(raw);
    let admin = state.admin.lock().unwrap();
    let q = SearchQuery::parse(&decoded);
    let found: Vec<Value> = vault_index::search(admin.db(), &q)
        .iter()
        .map(doc_json)
        .collect();
    (200, json!({ "count": found.len(), "documents": found }))
}

/// Decodifica percent-encoding mínimo (+ y %XX) para parámetros de consulta.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Servidor HTTP mínimo (una conexión por petición, keep-alive innecesario)
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: String,
    token: Option<String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = p;
            break;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_uppercase();
    let target = parts.next().unwrap_or("/");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };
    let mut token = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("authorization") {
                let v = v.trim();
                token = v
                    .strip_prefix("Bearer ")
                    .map(|t| t.to_string())
                    .or(Some(v.to_string()));
            }
        }
    }
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    if content_length > 1024 * 1024 {
        return None;
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Some(Request {
        method,
        path,
        query,
        token,
        body,
    })
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, payload: &[u8]) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        422 => "Unprocessable Entity",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(payload);
    let _ = stream.flush();
}

fn handle_conn(mut stream: TcpStream, state: Arc<WebUiState>) {
    let Some(req) = read_request(&mut stream) else {
        return;
    };
    // Ruta raíz: la interfaz HTML.
    if req.method == "GET" && (req.path == "/" || req.path == "/index.html") {
        write_response(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
        );
        return;
    }
    let body: Value = if req.body.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(&req.body).unwrap_or(Value::Null)
    };
    let (status, json) = route(
        &state,
        &req.method,
        &req.path,
        &req.query,
        req.token.as_deref(),
        &body,
    );
    write_response(
        &mut stream,
        status,
        "application/json; charset=utf-8",
        json.to_string().as_bytes(),
    );
}

/// Sirve el panel en `addr` (se recomienda 127.0.0.1:puerto). Devuelve la
/// dirección real de escucha y deja un hilo por conexión. El proceso termina
/// al soltar el listener (el hilo principal conserva el handle).
pub fn serve(addr: SocketAddr, state: Arc<WebUiState>) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let real = listener.local_addr()?;
    std::thread::Builder::new()
        .name("vault-webui".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let st = state.clone();
                        let _ = std::thread::Builder::new()
                            .name("vault-webui-conn".into())
                            .spawn(move || handle_conn(s, st));
                    }
                    Err(e) => tracing::warn!("webui: aceptar conexión: {e}"),
                }
            }
        })?;
    tracing::info!("Panel de administración en http://{real}/");
    Ok(real)
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bóveda — Panel de administración</title>
<style>
  :root { --bg:#0f1420; --card:#1a2233; --ok:#2fbf71; --bad:#e05252; --warn:#e0a52f; --tx:#e8ecf4; --mut:#8a94a8; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--tx); }
  header { display:flex; align-items:center; gap:12px; padding:14px 22px; background:var(--card); border-bottom:1px solid #2a3450; }
  header h1 { font-size:18px; margin:0; }
  header .status { margin-left:auto; font-size:13px; color:var(--mut); }
  main { max-width:1100px; margin:0 auto; padding:18px; display:grid; gap:18px; }
  section { background:var(--card); border:1px solid #2a3450; border-radius:10px; padding:16px; }
  h2 { margin:0 0 10px; font-size:15px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #26304a; }
  th { color:var(--mut); font-weight:600; }
  input, button, select { font:inherit; border-radius:6px; border:1px solid #33405f; background:#0d1320; color:var(--tx); padding:7px 10px; }
  button { background:#24304d; cursor:pointer; }
  button:hover { background:#2d3b5e; }
  button.primary { background:var(--ok); border-color:var(--ok); color:#06130b; font-weight:700; }
  button.danger { background:var(--bad); border-color:var(--bad); color:#1a0505; font-weight:700; }
  .mono { font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--mut); }
  .pill { padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; }
  .pill.ok { background:#10331f; color:var(--ok); }
  .pill.bad { background:#3a1414; color:var(--bad); }
  .pill.pending { background:#3a2e10; color:var(--warn); }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .muted { color:var(--mut); font-size:12px; }
  #login { max-width:360px; margin:8vh auto; }
  .hidden { display:none; }
  pre { white-space:pre-wrap; font-size:12px; color:var(--mut); }
</style>
</head>
<body>
<div id="login">
  <section>
    <h2>Acceso al panel</h2>
    <div class="row">
      <input id="pin" type="password" placeholder="PIN de administrador" style="flex:1">
      <button class="primary" onclick="login()">Entrar</button>
    </div>
    <p class="muted" id="login-msg"></p>
  </section>
</div>

<div id="app" class="hidden">
<header>
  <h1>🗂 Bóveda académica</h1>
  <span class="status" id="status">conectado</span>
  <button onclick="logout()">Salir</button>
</header>
<main>
  <section>
    <h2>Cola de admisión</h2>
    <div id="pending"></div>
  </section>

  <section>
    <h2>Documentos custodiados</h2>
    <div class="row" style="margin-bottom:8px">
      <input id="q" placeholder="categoria:Tesis AND departamento:&quot;Ingeniería&quot;" style="flex:1" onkeydown="if(event.key==='Enter')search()">
      <button onclick="search()">Buscar</button>
      <button onclick="document.getElementById('q').value='';search()">Todo</button>
      <button onclick="sweep()">Verificar integridad</button>
    </div>
    <div id="docs"></div>
  </section>

  <section>
    <h2>Dispositivos y emparejamiento</h2>
    <div class="row" style="margin-bottom:8px">
      <button onclick="pairingCode()">Generar código de emparejamiento</button>
      <span class="mono" id="pairing-code"></span>
    </div>
    <div id="devices"></div>
  </section>

  <section>
    <h2>Destrucción supervisada</h2>
    <p class="muted">Requiere PIN de administrador y PIN de destrucción (doble control). El documento se borra con sobreescritura y queda tombstone + auditoría.</p>
    <div class="row">
      <input id="d-vault" placeholder="vault_id" style="flex:2">
      <input id="d-admin" type="password" placeholder="PIN admin" style="flex:1">
      <input id="d-dest" type="password" placeholder="PIN destrucción" style="flex:1">
      <input id="d-just" placeholder="Justificación" style="flex:2">
      <button class="danger" onclick="destroy()">Destruir</button>
    </div>
  </section>

  <section>
    <h2>Auditoría</h2>
    <p class="muted" id="audit-status"></p>
    <div id="audit" style="max-height:260px;overflow:auto"></div>
  </section>
</main>
</div>

<script>
let TOKEN = sessionStorage.getItem('token') || '';
async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || (opts.body ? 'POST' : 'GET'),
    headers: Object.assign(
      { 'Content-Type': 'application/json' },
      TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}
    ),
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}
function esc(s) { const d = document.createElement('div'); d.textContent = s ?? ''; return d.innerHTML; }

async function login() {
  const pin = document.getElementById('pin').value;
  try {
    const r = await api('/api/login', { body: { pin } });
    TOKEN = r.token; sessionStorage.setItem('token', TOKEN);
    showApp();
  } catch (e) {
    document.getElementById('login-msg').textContent = 'Error: ' + e.message;
  }
}
async function logout() { try { await api('/api/logout', { body: {} }); } catch {} TOKEN=''; sessionStorage.removeItem('token'); location.reload(); }

function showApp() {
  document.getElementById('login').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  refresh();
}

async function refresh() {
  try {
    const s = await api('/api/state');
    renderPending(s.pending); renderDocs(s.documents); renderDevices(s.devices); renderAudit();
    document.getElementById('status').textContent =
      s.documents.length + ' docs · ' + s.pending.length + ' pendientes · auditoría ' +
      (s.audit_chain_ok ? 'íntegra' : '¡COMPROMETIDA!');
  } catch (e) {
    if (String(e.message).includes('sesión')) { TOKEN=''; location.reload(); }
  }
}

function renderPending(list) {
  const el = document.getElementById('pending');
  if (!list.length) { el.innerHTML = '<p class="muted">Sin entregas pendientes.</p>'; return; }
  el.innerHTML = '<table><tr><th>Archivo</th><th>Categoría</th><th>Autor</th><th>Tamaño</th><th></th></tr>' +
    list.map(p =>
      '<tr><td>' + esc(p.meta.file_name) + '</td><td>' + esc(p.meta.category) + '</td><td>' +
      esc(p.meta.author) + '</td><td>' + (p.size_bytes/1048576).toFixed(1) + ' MB</td>' +
      '<td class="row"><button class="primary" onclick="admit(\'' + p.submission_id + '\')">Admitir</button>' +
      '<button onclick="reject(\'' + p.submission_id + '\')">Rechazar</button></td></tr>'
    ).join('') + '</table>';
}
async function admit(id) { try { const r = await api('/api/admit', { body: { submission_id: id } }); alert(r.message || 'Sellado'); refresh(); } catch (e) { alert(e.message); } }
async function reject(id) { const reason = prompt('Motivo del rechazo:') || 'sin motivo'; try { await api('/api/reject', { body: { submission_id: id, reason } }); refresh(); } catch (e) { alert(e.message); } }

function integrityPill(i) {
  const cls = i === 'ok' ? 'ok' : (i === 'pending' ? 'pending' : 'bad');
  return '<span class="pill ' + cls + '">' + esc(i) + '</span>';
}
function renderDocs(list) {
  const el = document.getElementById('docs');
  if (!list.length) { el.innerHTML = '<p class="muted">Sin documentos.</p>'; return; }
  el.innerHTML = '<table><tr><th>Título</th><th>Categoría</th><th>Autor</th><th>Integridad</th><th>vault_id</th></tr>' +
    list.map(d =>
      '<tr><td>' + esc(d.title) + '<br><span class="mono">' + esc(d.file_name) + '</span></td>' +
      '<td>' + esc(d.category) + (d.academic_year ? ' · ' + d.academic_year : '') + '</td>' +
      '<td>' + esc(d.author) + '</td><td>' + integrityPill(d.integrity) + '</td>' +
      '<td class="mono">' + esc(d.vault_id.slice(0, 16)) + '…</td></tr>'
    ).join('') + '</table>';
}
async function search() {
  const q = document.getElementById('q').value;
  const r = await api('/api/documents' + (q ? '?q=' + encodeURIComponent(q) : ''));
  renderDocs(r.documents);
}
function renderDevices(list) {
  const el = document.getElementById('devices');
  if (!list.length) { el.innerHTML = '<p class="muted">Ningún dispositivo emparejado.</p>'; return; }
  el.innerHTML = '<table><tr><th>Dispositivo</th><th>Huella SHA-256</th><th>Emparejado</th></tr>' +
    list.map(d => '<tr><td>' + esc(d.device_id) + '</td><td class="mono">' + esc(d.cert_fingerprint.slice(0, 32)) + '…</td><td>' + esc(d.paired_at) + '</td></tr>').join('') + '</table>';
}
async function pairingCode() {
  try { const r = await api('/api/pairing-code', { body: {} }); document.getElementById('pairing-code').textContent = r.code + ' (10 min)'; }
  catch (e) { alert(e.message); }
}
async function destroy() {
  const vault_id = document.getElementById('d-vault').value.trim();
  const admin_pin = document.getElementById('d-admin').value;
  const destruction_pin = document.getElementById('d-dest').value;
  const justification = document.getElementById('d-just').value.trim();
  if (!confirm('¿DESTRUIR ' + vault_id + ' de forma irreversible?')) return;
  try { const r = await api('/api/destroy', { body: { vault_id, admin_pin, destruction_pin, justification } }); alert(r.message); refresh(); }
  catch (e) { alert(e.message); }
}
async function sweep() {
  try { const r = await api('/api/sweep', { body: {} }); alert('Verificados: ' + r.checked + ' · OK: ' + r.ok + ' · manipulados: ' + r.tampered + ' · perdidos: ' + r.missing); refresh(); }
  catch (e) { alert(e.message); }
}
async function renderAudit() {
  try {
    const r = await api('/api/audit');
    document.getElementById('audit-status').textContent =
      r.chain_ok ? 'Cadena de auditoría íntegra (' + r.entries.length + ' entradas).' : '¡CADENA COMPROMETIDA!';
    document.getElementById('audit').innerHTML = '<table><tr><th>#</th><th>Cuándo</th><th>Actor</th><th>Acción</th><th>Detalle</th></tr>' +
      r.entries.slice().reverse().map(a =>
        '<tr><td>' + a.seq + '</td><td class="mono">' + esc(a.timestamp) + '</td><td>' + esc(a.actor) + '</td><td>' + esc(a.action) + '</td><td class="muted">' + esc(a.detail) + '</td></tr>'
      ).join('') + '</table>';
  } catch {}
}
if (TOKEN) { showApp(); }
document.getElementById('pin').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Category, DocumentMeta};
    use vault_crypto::dbcrypto::generate_keyfile;
    use vault_crypto::LocalTsa;
    use vault_fs::VaultLayout;
    use vault_store::VaultDb;

    fn setup(dir: &std::path::Path) -> Arc<WebUiState> {
        let kf = generate_keyfile();
        let db = VaultDb::open(&dir.join("db"), &kf).unwrap();
        let layout = VaultLayout::new(dir.join("vault"));
        layout.init(&["Profesor".to_string()]).unwrap();
        let tsa = LocalTsa::new().unwrap();
        WebUiState::new(Arc::new(StdMutex::new(AdminService::new(db, layout, tsa))))
    }

    fn post(state: &Arc<WebUiState>, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
        let (m, target) = path.split_once(' ').unwrap_or(("POST", path));
        let (p, q) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target, ""),
        };
        route(state, m, p, q, token, &body)
    }

    fn make_submission(dir: &std::path::Path) -> vault_core::Submission {
        let content = b"PDF-FAKE contenido de tesis para el panel";
        let hp = vault_crypto::HashPair::from_bytes(content);
        let staging = dir.join("vault/.staging");
        std::fs::create_dir_all(&staging).unwrap();
        let rel = format!("{}.bin", &hp.sha256[..12]);
        std::fs::write(staging.join(&rel), content).unwrap();
        vault_core::Submission {
            submission_id: vault_core::new_id(),
            device_id: "AND_UI_1".into(),
            meta: DocumentMeta {
                title: "Tesis Panel".into(),
                category: Category::Tesis,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "Ingeniería".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: Some(2026),
                file_name: "tesis-panel.pdf".into(),
                extension: "pdf".into(),
            },
            sha256: hp.sha256,
            blake3: hp.blake3,
            size_bytes: content.len() as u64,
            staging_path: rel,
            received_at: vault_core::now_rfc3339(),
            state: vault_core::AdmissionState::Pending,
        }
    }

    #[test]
    fn login_state_admit_flow() {
        let dir = tempfile::tempdir().unwrap();
        let state = setup(dir.path());

        // sin sesión no se puede leer estado
        let (code, _) = post(&state, "GET /api/state", None, json!({}));
        assert_eq!(code, 401);

        // sin PIN configurado no hay login
        let (code, _r) = post(&state, "POST /api/login", None, json!({ "pin": "123456" }));
        assert_eq!(code, 403);

        state
            .admin
            .lock()
            .unwrap()
            .set_admin_pin(None, "123456")
            .unwrap();
        let (code, r) = post(&state, "POST /api/login", None, json!({ "pin": "123456" }));
        assert_eq!(code, 200);
        let token = r["token"].as_str().unwrap().to_string();

        // estado con sesión
        let (code, st) = post(&state, "GET /api/state", Some(&token), json!({}));
        assert_eq!(code, 200);
        assert!(st["has_pin"].as_bool().unwrap());
        assert!(st["pending"].as_array().unwrap().is_empty());

        // PIN incorrecto → 403 (y el bloqueo progresivo entra en juego)
        let (code, _) = post(&state, "POST /api/login", None, json!({ "pin": "000000" }));
        assert_eq!(code, 403);

        // admitir una entrega desde el panel
        let sub = make_submission(dir.path());
        state
            .admin
            .lock()
            .unwrap()
            .db_mut()
            .add_submission(sub.clone());
        let (code, ack) = post(
            &state,
            "POST /api/admit",
            Some(&token),
            json!({ "submission_id": sub.submission_id }),
        );
        assert_eq!(code, 200);
        assert_eq!(ack["status"], "sealed");
        assert!(ack["vault_id"].is_string());

        // búsqueda por categoría
        {
            let admin = state.admin.lock().unwrap();
            let q = SearchQuery::parse("categoria:Tesis");
            let found = vault_index::search(admin.db(), &q);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].meta.file_name, "tesis-panel.pdf");
        }
        // y por la ruta HTTP
        let (code, docs) = post(
            &state,
            "GET /api/documents?q=categoria%3ATesis",
            Some(&token),
            json!({}),
        );
        assert_eq!(code, 200);
        assert_eq!(docs["count"], 1);

        // logout invalida la sesión
        let (code, _) = {
            post(&state, "POST /api/logout", Some(&token), json!({}));
            post(&state, "GET /api/state", Some(&token), json!({}))
        };
        assert_eq!(code, 401);
    }

    #[test]
    fn pairing_code_and_audit() {
        let dir = tempfile::tempdir().unwrap();
        let state = setup(dir.path());
        state
            .admin
            .lock()
            .unwrap()
            .set_admin_pin(None, "123456")
            .unwrap();
        let (_, r) = post(&state, "POST /api/login", None, json!({ "pin": "123456" }));
        let token = r["token"].as_str().unwrap().to_string();

        let (code, r) = post(&state, "POST /api/pairing-code", Some(&token), json!({}));
        assert_eq!(code, 200);
        assert_eq!(r["code"].as_str().unwrap().len(), 8);

        let (code, audit) = post(&state, "GET /api/audit", Some(&token), json!({}));
        assert_eq!(code, 200);
        assert!(audit["chain_ok"].as_bool().unwrap());
        assert!(!audit["entries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn http_server_serves_html_and_api() {
        let dir = tempfile::tempdir().unwrap();
        let state = setup(dir.path());
        state
            .admin
            .lock()
            .unwrap()
            .set_admin_pin(None, "123456")
            .unwrap();
        let addr = serve("127.0.0.1:0".parse().unwrap(), state).unwrap();

        // GET / devuelve la UI
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200"));
        assert!(raw.contains("Panel de administración") || raw.contains("Bóveda"));

        // login vía HTTP real
        let body = br#"{"pin":"123456"}"#;
        let mut s = TcpStream::connect(addr).unwrap();
        let req = format!(
            "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.starts_with("HTTP/1.1 200"), "login HTTP falló: {text}");
        assert!(text.contains("\"token\""));
    }
}
