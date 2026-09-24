//! vault-gui: aplicación de escritorio (egui/eframe) de la bóveda académica.
//!
//! 100 % gráfica: no requiere terminal. Tema ultra-minimalista OLED (#000000),
//! tipografía limpia, diseño modular y modales/toasts para toda interacción.
//!
//! Flujo:
//!   1. Bootstrap (solo la primera vez): carpeta de la bóveda + PIN de
//!      Coordinación/administrador de la bóveda.
//!   2. Login con usuario+contraseña institucional (roles PoLP).
//!   3. Vistas según rol: Documentos, Papelera (Administrativo), Versiones,
//!      Auditoría (Coordinación/Director), Usuarios (modo IT, aparte).

use std::path::PathBuf;

use eframe::egui;
use vault_core::{Document, Role};
use vault_roles::{RoleService, Session};
use vault_store::VaultDb;

// ----------------------------------------------------------------------
// Datos de aplicación (todo lo mutables vive aquí; la BD solo se toca desde
// estos handles para evitar bloqueos del hilo de UI)
// ----------------------------------------------------------------------

/// Toast de notificación gráfica (nada por consola).
#[derive(Debug, Clone, PartialEq)]
pub struct Toast {
    pub kind: ToastKind,
    pub text: String,
    pub born: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Ok,
    Warn,
    Error,
}

impl Toast {
    fn new(kind: ToastKind, text: impl Into<String>) -> Self {
        Toast {
            kind,
            text: text.into(),
            born: std::time::Instant::now(),
        }
    }

    fn alive(&self) -> bool {
        self.born.elapsed() < std::time::Duration::from_secs(4)
    }
}

/// Pantalla activa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Bootstrap,
    Login,
    Documents,
    Trash,
    Audit,
    /// Usuarios y roles: solo aparece con una sesión de administración
    /// vigente (la sesión se abre siempre fuera de la aplicación).
    Users,
    /// Administración del sistema (almacenamiento y reportes); también
    /// requiere la sesión de administración.
    System,
}

/// Modal activo (uno a la vez).
#[derive(Debug, Clone, PartialEq)]
pub enum Modal {
    None,
    /// Confirmación destructiva genérica (título, texto, acción id).
    Confirm {
        title: String,
        body: String,
        action: PendingAction,
    },
    /// Edición de metadatos (solo Administrativo/Coordinación).
    EditMeta {
        vault_id: String,
        title: String,
        department: String,
        year: String,
        note: String,
    },
    /// Renombrar.
    Rename {
        vault_id: String,
        name: String,
    },
    /// Soft-delete (motivo obligatorio).
    SoftDelete {
        vault_id: String,
        reason: String,
    },
    /// Alta de usuario (solo con la sesión de administración activa).
    NewUser {
        username: String,
        display: String,
        role: Role,
        pin: String,
        pin2: String,
    },
    /// Definición del PIN de un usuario existente (solo administración).
    SetPin {
        username: String,
        pin: String,
        pin2: String,
    },
    /// Selector de archivos propio (sin depender de zenity/kdialog).
    FilePicker {
        dir: PathBuf,
        filter: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PendingAction {
    QuitApp,
    Logout,
}

/// App de escritorio.
pub struct BovedaApp {
    /// Ruta de datos de la bóveda (~/.boveda por defecto).
    pub data_dir: PathBuf,
    pub vault_root: PathBuf,

    /// Servicio de roles (dueño de la BD: se re-crea al abrir la bóveda).
    pub roles: Option<RoleService>,
    /// Sesión activa.
    pub session: Option<Session>,
    /// Sello de tiempo local para sellar documentos importados (misma TSA que
    /// el servicio: `data/tsa`). No se crea en modo consulta.
    pub tsa: Option<vault_crypto::LocalTsa>,
    /// Bóveda en modo consulta: el servicio tiene la escritura y la app no
    /// puede modificar nada (solo leer y autenticar).
    pub read_only: bool,

    pub screen: Screen,
    pub modal: Modal,

    // formularios
    pub boot_pin: String,
    pub boot_pin2: String,
    pub login_user: String,
    pub login_pass: String,
    pub search: String,

    /// Fila seleccionada en la tabla de documentos.
    pub selected: Option<String>,
    /// Toasts en pantalla.
    pub toasts: Vec<Toast>,
    /// Clave pública de IT para reportes de crash (hex), si está configurada.
    pub it_pubkey: Option<String>,
    /// Emisor de reportes cifrados (pánico y errores lógicos).
    pub reporter: Option<vault_crash::CrashReporter>,
    /// Última ruta de error lógico reportada (para el toast/pantalla).
    pub last_report: Option<String>,
}

/// Asegura el par de claves de reportes de fallo: la clave PÚBLICA vive en
/// `config/it.pub` (la app la usa para cifrar); la PRIVADA solo existe en
/// `door/` (0600, la consola de administración es la única que la lee).
/// Devuelve la clave pública en hex comprimido si está disponible.
///
/// Layout de datos en una sola máquina (debe coincidir con vaultd y la
/// consola de administración): `<datos>/ = ~/.boveda/data/` con
/// `vault.key`, `db/`, `door/`, `config/`, `crash/` dentro.
pub fn ensure_crash_keys(data_dir: &std::path::Path) -> Option<String> {
    let cfg = data_dir.join("config/it.pub");
    if let Ok(hex) = std::fs::read_to_string(&cfg) {
        let hex = hex.trim().to_string();
        if hex.len() == 66 {
            return Some(hex);
        }
    }
    let door = data_dir.join("door/it.pub");
    if let Ok(hex) = std::fs::read_to_string(&door) {
        let hex = hex.trim().to_string();
        if hex.len() == 66 {
            let _ = std::fs::create_dir_all(cfg.parent()?);
            let _ = std::fs::copy(&door, &cfg);
            return Some(hex);
        }
    }
    // primera vez: genera el par; la privada queda en door/ (solo la consola)
    let kp = vault_crash::ItKeyPair::generate();
    let door_dir = data_dir.join("door");
    std::fs::create_dir_all(&door_dir).ok()?;
    std::fs::write(door_dir.join("door.key.pem"), kp.private_pem()).ok()?;
    std::fs::write(door_dir.join("it.pub"), format!("{}\n", kp.public_hex())).ok()?;
    std::fs::create_dir_all(cfg.parent()?).ok()?;
    std::fs::write(&cfg, format!("{}\n", kp.public_hex())).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            door_dir.join("door.key.pem"),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Some(kp.public_hex())
}

impl BovedaApp {
    /// Directorio base por defecto (~/.boveda).
    pub fn default_data_dir() -> PathBuf {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".boveda")
    }

    /// Carpeta de datos internos `<datos>/` (~/.boveda/data), misma que usa
    /// vaultd: keyfile, BD cifrada, door/, config/ y crash/ viven aquí.
    fn vault_data_dir(&self) -> PathBuf {
        self.data_dir.join("data")
    }

    /// Crea el estado inicial de la app (aún sin bóveda abierta).
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_oled_theme(&cc.egui_ctx);
        let data_dir = Self::default_data_dir();
        let vault_root = data_dir.join("vault");
        let it_pubkey = std::fs::read_to_string(data_dir.join("data/config/it.pub"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|h| !h.is_empty());
        // Emisor de reportes: cifra para la administración de sistemas y firma
        // con la identidad de esta instalación (clave propia, 0600).
        let reporter = it_pubkey.as_ref().map(|pk| {
            let inner = data_dir.join("data");
            let signing = vault_crash::load_or_create_app_key(&inner).ok();
            vault_crash::CrashReporter::new(pk.clone(), inner.join("crash"), signing)
        });
        // ¿existe ya la bóveda? → login directo (la BD vive en data/db/)
        let exists = data_dir.join("data/db/vault.db.enc").exists();
        BovedaApp {
            data_dir,
            vault_root,
            roles: None,
            session: None,
            tsa: None,
            read_only: false,
            screen: if exists {
                Screen::Login
            } else {
                Screen::Bootstrap
            },
            modal: Modal::None,
            boot_pin: String::new(),
            boot_pin2: String::new(),
            login_user: String::new(),
            login_pass: String::new(),
            search: String::new(),
            selected: None,
            toasts: Vec::new(),
            it_pubkey,
            reporter,
            last_report: None,
        }
    }

    /// Registra un error lógico (no fatal) como reporte cifrado. La aplicación
    /// sigue funcionando; el reporte queda para la administración de sistemas.
    fn report_error(&mut self, module: &str, message: &str) {
        if let Some(rep) = self.reporter.as_ref() {
            if let Ok(path) = rep.report_logic_error(module, message) {
                self.last_report = Some(path.display().to_string());
            }
        }
    }

    fn toast(&mut self, kind: ToastKind, text: impl Into<String>) {
        self.toasts.push(Toast::new(kind, text));
    }

    fn open_vault(&mut self) -> Result<(), String> {
        let keyfile_path = self.vault_data_dir().join("vault.key");
        let kf: [u8; 64] = std::fs::read(&keyfile_path)
            .map_err(|e| format!("keyfile: {e}"))?
            .try_into()
            .map_err(|_| "keyfile corrupto".to_string())?;
        let db = VaultDb::open(&self.vault_data_dir().join("db"), &kf)
            .map_err(|e| format!("BD: {e}"))?;
        // Si otro proceso (el servicio) tiene la escritura, esta instancia
        // queda en modo consulta: avisa en pantalla y no permite modificar.
        self.read_only = db.is_read_only();
        let layout = vault_fs::VaultLayout::new(&self.vault_root);
        self.roles = Some(RoleService::new(db, layout));
        self.tsa = if self.read_only {
            None
        } else {
            vault_crypto::LocalTsa::new_persisted(&self.vault_data_dir().join("tsa")).ok()
        };
        Ok(())
    }

    /// ¿Se pueden ejecutar acciones que escriban en la bóveda?
    fn can_write(&self) -> bool {
        !self.read_only
    }

    /// Bootstrap: crea keyfile + BD + carpetas + PIN del administrador de la bóveda.
    fn bootstrap(&mut self) {
        if self.boot_pin.len() < 6 {
            self.toast(ToastKind::Warn, "El PIN debe tener al menos 6 caracteres");
            return;
        }
        if self.boot_pin != self.boot_pin2 {
            self.toast(ToastKind::Warn, "Los PIN no coinciden");
            return;
        }
        if !self.can_write() {
            self.toast(
                ToastKind::Warn,
                "La bóveda ya existe y está en uso; no se puede crear otra.",
            );
            return;
        }
        if let Err(e) = std::fs::create_dir_all(self.vault_data_dir().join("db")) {
            self.toast(ToastKind::Error, format!("no se pudo crear {e}"));
            return;
        }
        if let Err(e) = std::fs::create_dir_all(&self.vault_root) {
            self.toast(ToastKind::Error, format!("no se pudo crear {e}"));
            return;
        }
        // keyfile solo si no existe
        let keyfile_path = self.vault_data_dir().join("vault.key");
        if !keyfile_path.exists() {
            let kf = vault_crypto::dbcrypto::generate_keyfile();
            if let Err(e) = std::fs::write(&keyfile_path, kf) {
                self.toast(ToastKind::Error, format!("keyfile: {e}"));
                return;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&keyfile_path, std::fs::Permissions::from_mode(0o600));
            }
        }
        if let Err(e) = self.open_vault() {
            self.toast(ToastKind::Error, e);
            return;
        }
        // claves de reportes de fallo (pública en config/, privada en door/)
        let _ = ensure_crash_keys(&self.vault_data_dir());
        // usuarios iniciales del entorno educativo
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        for (u, d, r, pin) in [
            (
                "director",
                "Dirección",
                Role::Director,
                self.boot_pin.clone(),
            ),
            (
                "coordinacion",
                "Coordinación",
                Role::Coordinacion,
                self.boot_pin.clone(),
            ),
            (
                "administrativo",
                "Administración",
                Role::Administrativo,
                self.boot_pin.clone(),
            ),
            ("docente", "Docentes", Role::Docente, self.boot_pin.clone()),
        ] {
            let _ = vault_roles::upsert_user_with_pin(svc.db_mut(), u, d, r, &pin);
        }
        svc.db_mut().append_audit(
            "sistema",
            "bootstrap",
            "vault",
            "bóveda inicializada con roles estándar",
        );
        let _ = svc.db_mut().flush();
        self.boot_pin.clear();
        self.boot_pin2.clear();
        self.screen = Screen::Login;
        self.toast(
            ToastKind::Ok,
            "Bóveda creada. Inicie sesión con los usuarios estándar.",
        );
    }

    fn do_login(&mut self) {
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        match svc.login(&self.login_user.trim().to_lowercase(), &self.login_pass) {
            Ok(session) => {
                // toda entrada genera registro (trazabilidad por rol)
                svc.db_mut().append_audit(
                    &session.username,
                    "login",
                    &session.username,
                    &format!("rol={}", session.role.label()),
                );
                let _ = svc.db_mut().flush();
                self.screen = Screen::Documents;
                self.toast(
                    ToastKind::Ok,
                    format!(
                        "Bienvenido, {} ({})",
                        session.display_name,
                        session.role.label()
                    ),
                );
                self.login_pass.clear();
                self.session = Some(session);
            }
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    fn logout(&mut self) {
        if let (Some(session), Some(svc)) = (&self.session, self.roles.as_mut()) {
            svc.db_mut().append_audit(
                &session.username,
                "logout",
                &session.username,
                "sesión cerrada",
            );
            let _ = svc.db_mut().flush();
        }
        self.session = None;
        self.screen = Screen::Login;
        self.selected = None;
    }

    fn refresh_row_visibility(&self) -> bool {
        self.session.is_some()
    }
}

// ----------------------------------------------------------------------
// Tema OLED #000000
// ----------------------------------------------------------------------

/// Aplica el tema ultra-minimalista: fondo negro puro, bordes sutiles,
/// acentos fríos, tipografía limpia.
pub fn apply_oled_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;
    v.dark_mode = true;
    v.override_text_color = Some(egui::Color32::from_rgb(0xE8, 0xEC, 0xF4));
    v.panel_fill = egui::Color32::BLACK; // #000000
    v.window_fill = egui::Color32::from_rgb(0x0A, 0x0D, 0x14);
    v.extreme_bg_color = egui::Color32::BLACK;
    v.faint_bg_color = egui::Color32::from_rgb(0x0D, 0x11, 0x1A);

    v.widgets.noninteractive.bg_fill = egui::Color32::BLACK;
    v.widgets.noninteractive.fg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0xC8, 0xD0, 0xE0));
    v.widgets.noninteractive.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x24, 0x2C, 0x40));

    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x10, 0x16, 0x24);
    v.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(0x10, 0x16, 0x24);
    v.widgets.inactive.fg_stroke =
        egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(0xE8, 0xEC, 0xF4));
    v.widgets.inactive.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x2A, 0x34, 0x4E));

    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x18, 0x22, 0x38);
    v.widgets.hovered.weak_bg_fill = egui::Color32::from_rgb(0x18, 0x22, 0x38);
    v.widgets.hovered.bg_stroke =
        egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(0x4C, 0x62, 0x96));

    v.widgets.active.bg_fill = egui::Color32::from_rgb(0x22, 0x30, 0x52);
    v.widgets.active.weak_bg_fill = egui::Color32::from_rgb(0x22, 0x30, 0x52);
    v.widgets.active.bg_stroke =
        egui::Stroke::new(1.4_f32, egui::Color32::from_rgb(0x6E, 0x8E, 0xD8));

    v.selection.bg_fill = egui::Color32::from_rgb(0x1C, 0x2A, 0x4A);
    v.selection.stroke = egui::Stroke::new(1.2_f32, egui::Color32::from_rgb(0x5A, 0x78, 0xB8));

    v.window_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x2A, 0x34, 0x4E));
    v.window_shadow = egui::epaint::Shadow::NONE;
    v.popup_shadow = egui::epaint::Shadow::NONE;

    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 5.0);
    style.spacing.interact_size = egui::vec2(40.0, 26.0);
    ctx.set_style(style);

    let mut fonts = egui::FontDefinitions::default();
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .and_modify(|f| {
            // orden: la primera fuente disponible gana; mantengo las embebidas
            f.truncate(2);
        });
    ctx.set_fonts(fonts);
}

// ----------------------------------------------------------------------
// Render principal (eframe::App)
// ----------------------------------------------------------------------

impl eframe::App for BovedaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // toasts (arriba al centro)
        self.draw_toasts(ctx);

        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("🗂 Bóveda académica");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(s) = &self.session {
                        ui.label(format!("{} · {}", s.display_name, s.role.label()));
                        if ui.button("Salir").clicked() {
                            self.modal = Modal::Confirm {
                                title: "Cerrar sesión".into(),
                                body: "¿Cerrar la sesión actual?".into(),
                                action: PendingAction::Logout,
                            };
                        }
                    }
                    if ui.button("✕").clicked() {
                        self.modal = Modal::Confirm {
                            title: "Salir de la aplicación".into(),
                            body: "¿Cerrar la Bóveda académica?".into(),
                            action: PendingAction::QuitApp,
                        };
                    }
                });
            });
            ui.add_space(6.0);
        });

        // modo consulta: el servicio tiene la escritura (aviso permanente)
        if self.read_only {
            self.draw_read_only_banner(ctx);
        }

        // sesión privilegiada transitoria: banner + navegación extra mientras dure
        let privileged = self.privileged_active();
        if privileged {
            self.draw_privileged_banner(ctx);
        }
        // si la sesión privilegiada caducó, no se puede seguir en sus pantallas
        if !privileged && matches!(self.screen, Screen::Users | Screen::System) {
            self.screen = Screen::Documents;
        }

        // navegación por rol
        if self.refresh_row_visibility() {
            egui::SidePanel::left("nav").show(ctx, |ui| {
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    nav_item(ui, &mut self.screen, Screen::Documents, "📄", "Documentos");
                    let can_trash = self
                        .session
                        .as_ref()
                        .map(|s| s.role.can_restore())
                        .unwrap_or(false);
                    if can_trash {
                        nav_item(ui, &mut self.screen, Screen::Trash, "🗑", "Papelera");
                    }
                    let can_audit = self
                        .session
                        .as_ref()
                        .map(|s| s.role.can_audit())
                        .unwrap_or(false);
                    if can_audit {
                        nav_item(ui, &mut self.screen, Screen::Audit, "🧾", "Auditoría");
                    }
                    if privileged {
                        ui.add_space(8.0);
                        nav_item(ui, &mut self.screen, Screen::Users, "👤", "Usuarios");
                        nav_item(ui, &mut self.screen, Screen::System, "⚙", "Sistema");
                    }
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Bootstrap => self.draw_bootstrap(ui),
            Screen::Login => self.draw_login(ui),
            Screen::Documents => self.draw_documents(ctx, ui),
            Screen::Trash => self.draw_trash(ui),
            Screen::Audit => self.draw_audit(ui),
            Screen::Users => self.draw_users(ui),
            Screen::System => self.draw_system(ctx, ui),
        });

        self.draw_modal(ctx);
    }
}

impl BovedaApp {
    /// ¿Hay sesión privilegiada transitoria vigente?
    ///
    /// La marca la escribe la consola de administración al abrir la sesión;
    /// la aplicación solo la detecta (nunca la crea).
    pub fn privileged_active(&self) -> bool {
        matches!(self.privileged_remaining(), Some(rest) if rest > 0)
    }

    /// Aviso de modo consulta: la app puede leer, pero no modificar la bóveda.
    fn draw_read_only_banner(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("read_only_banner")
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x1B, 0x2A, 0x4A))
                    .inner_margin(egui::Margin::symmetric(14.0, 5.0)),
            )
            .show(ctx, |ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(0xBF, 0xD4, 0xFF),
                    "MODO CONSULTA · el servicio está activo: puede consultar y buscar, \
                     pero no modificar la bóveda. Las acciones de escritura están desactivadas.",
                );
            });
    }

    /// Segundos que le quedan a la sesión de administración (0 = ninguna).
    pub fn privileged_remaining(&self) -> Option<u64> {
        let exp = std::fs::read_to_string(self.vault_data_dir().join("door/session"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())?;
        let now = now_epoch();
        exp.checked_sub(now)
    }

    /// Carpeta inicial del selector de archivos.
    fn default_picker_dir(&self) -> PathBuf {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Banner de alto contraste mientras la sesión privilegiada esté activa.
    fn draw_privileged_banner(&self, ctx: &egui::Context) {
        let remaining = self.privileged_remaining().unwrap_or(0);
        egui::TopBottomPanel::top("privileged_banner")
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x8B, 0x1A, 0x1A))
                    .inner_margin(egui::Margin::symmetric(14.0, 5.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0xE0, 0x82),
                        format!(
                            "SESIÓN PRIVILEGIADA TRANSITORIA · expira en {:02}:{:02}",
                            remaining / 60,
                            remaining % 60
                        ),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Cerrar sesión privilegiada").clicked() {
                            let _ =
                                std::fs::remove_file(self.vault_data_dir().join("door/session"));
                        }
                    });
                });
            });
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }

    /// Panel de administración local del sistema (solo con sesión vigente).
    fn draw_system(&mut self, _ctx: &egui::Context, ui: &mut egui::Ui) {
        if !self.privileged_active() {
            ui.heading("Sistema");
            ui.weak("La administración local requiere una sesión de administración vigente.");
            return;
        }
        let can_write = self.can_write();
        ui.heading("Sistema");
        ui.separator();

        ui.label(egui::RichText::new("Almacenamiento").strong());
        if let Some(svc) = self.roles.as_ref() {
            ui.weak(format!(
                "{} documentos · {} en papelera · {} versiones",
                svc.db().documents().len(),
                svc.db().trashed().len(),
                svc.db().versions().len()
            ));
        }
        ui.horizontal(|ui| {
            ui.add_enabled_ui(can_write, |ui| {
                if ui.button("Limpiar temporales de staging").clicked() {
                    let n = clean_staging(&self.vault_root);
                    self.toast(ToastKind::Ok, format!("{n} temporales eliminados"));
                }
            });
            if ui.button("Recargar estado de la bóveda").clicked() {
                if let Err(e) = self.open_vault() {
                    self.report_error("vault-gui::open_vault", &e);
                    self.toast(ToastKind::Error, e);
                } else {
                    let modo = if self.read_only {
                        " (modo consulta)"
                    } else {
                        ""
                    };
                    self.toast(ToastKind::Ok, format!("Estado recargado{modo}"));
                }
            }
        });
        ui.add_space(10.0);

        ui.label(egui::RichText::new("Reportes de fallo").strong());
        let crash_dir = self.vault_data_dir().join("crash");
        let n = std::fs::read_dir(&crash_dir)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.path().extension().map(|x| x == "crpt").unwrap_or(false))
                    .count()
            })
            .unwrap_or(0);
        ui.weak(format!(
            "{n} reportes cifrados en {} (solo se pueden leer con la clave privada de administración).",
            crash_dir.display()
        ));
        if let Some(last) = &self.last_report {
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Último error lógico reportado").strong());
            ui.monospace(last);
        }
        ui.add_space(10.0);
        if ui.button("Cerrar sesión privilegiada").clicked() {
            self.it_close_session();
        }
    }
}

impl BovedaApp {
    fn draw_toasts(&mut self, ctx: &egui::Context) {
        self.toasts.retain(|t| t.alive());
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(egui::Align2::CENTER_TOP, [0.0, 42.0])
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                for t in &self.toasts {
                    let (icon, color) = match t.kind {
                        ToastKind::Ok => ("✔", egui::Color32::from_rgb(0x2F, 0xBF, 0x71)),
                        ToastKind::Warn => ("⚠", egui::Color32::from_rgb(0xE0, 0xA5, 0x2F)),
                        ToastKind::Error => ("✖", egui::Color32::from_rgb(0xE0, 0x52, 0x52)),
                    };
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(0x0A, 0x0D, 0x14))
                        .stroke(egui::Stroke::new(1.0_f32, color))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.colored_label(color, icon);
                                ui.label(&t.text);
                            });
                        });
                    ui.add_space(4.0);
                }
            });
    }

    fn draw_bootstrap(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(60.0);
            ui.heading("Primera configuración");
            ui.label("Se creará la bóveda cifrada y los usuarios estándar (Docente, Administrativo, Coordinación, Director) con este PIN.");
            ui.add_space(16.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(0x0A, 0x0D, 0x14))
                .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x2A, 0x34, 0x4E)))
                .rounding(10.0)
                .inner_margin(20.0)
                .show(ui, |ui| {
                    ui.set_max_width(420.0);
                    ui.add_space(4.0);
                    ui.label("Ruta de la bóveda");
                    ui.monospace(self.vault_root.display().to_string());
                    ui.add_space(8.0);
                    ui.label("PIN (mínimo 6 caracteres)");
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.boot_pin)
                            .password(true)
                            .hint_text("••••••"),
                    );
                    ui.add_space(6.0);
                    ui.label("Repita el PIN");
                    let resp2 = ui.add(
                        egui::TextEdit::singleline(&mut self.boot_pin2)
                            .password(true)
                            .hint_text("••••••"),
                    );
                    ui.add_space(12.0);
                    let create = ui.add_sized(
                        [ui.available_width(), 32.0],
                        egui::Button::new(egui::RichText::new("Crear bóveda").strong()),
                    );
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter))
                        && (resp.lost_focus() || resp2.lost_focus());
                    if create.clicked() || enter {
                        self.bootstrap();
                    }
                });
        });
    }

    fn draw_login(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(70.0);
            ui.heading("Acceso institucional");
            ui.label("Autentíquese con su usuario y contraseña asignados.");
            ui.add_space(16.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(0x0A, 0x0D, 0x14))
                .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x2A, 0x34, 0x4E)))
                .rounding(10.0)
                .inner_margin(20.0)
                .show(ui, |ui| {
                    ui.set_max_width(380.0);
                    ui.label("Usuario");
                    let user_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.login_user)
                            .hint_text("p. ej. docente, coordinacion…"),
                    );
                    ui.add_space(6.0);
                    ui.label("Contraseña");
                    let pass_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.login_pass)
                            .password(true)
                            .hint_text("••••••"),
                    );
                    ui.add_space(12.0);
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let btn = ui.add_sized(
                        [ui.available_width(), 32.0],
                        egui::Button::new(egui::RichText::new("Iniciar sesión").strong()),
                    );
                    if btn.clicked() || (enter && (user_resp.lost_focus() || pass_resp.lost_focus())) {
                        self.do_login();
                    }
                    ui.add_space(6.0);
                    ui.small("Roles: Docente (lectura) · Administrativo (gestión) · Coordinación (auditoría) · Director (supervisión)");
                });
        });
    }

    fn draw_documents(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let Some(session) = self.session.clone() else {
            return;
        };
        let can_write = self.can_write();
        ui.horizontal(|ui| {
            // La búsqueda se ejecuta en vivo al escribir (y con el botón, que
            // además devuelve el foco al campo).
            let search_resp = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Buscar: categoria:Tesis AND departamento:\"Ingeniería\"")
                    .desired_width(ui.available_width() - 90.0),
            );
            if search_resp.changed() {
                ui.ctx().request_repaint();
            }
            if ui.button("Buscar").clicked() {
                search_resp.request_focus();
            }
            if session.role.can_import() {
                ui.add_enabled_ui(can_write, |ui| {
                    let importar = ui.button("＋ Importar…");
                    if importar.clicked() {
                        match rfd_pick_file() {
                            Some(path) => self.import_document(&session, path),
                            // sin diálogo del sistema: navegador propio, igualmente gráfico
                            None => {
                                self.modal = Modal::FilePicker {
                                    dir: self.default_picker_dir(),
                                    filter: String::new(),
                                }
                            }
                        }
                    }
                    if !can_write {
                        importar.on_hover_text("No disponible en modo consulta");
                    }
                });
            }
        });
        ui.add_space(6.0);

        let Some(svc) = self.roles.as_ref() else {
            return;
        };
        let rows: Vec<Document> = if self.search.trim().is_empty() {
            svc.documents(&session)
        } else {
            svc.search(&session, &self.search).unwrap_or_default()
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("docs_grid")
                .num_columns(6)
                .spacing([16.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Título");
                    ui.strong("Categoría");
                    ui.strong("Autor");
                    ui.strong("Año");
                    ui.strong("Integridad");
                    ui.strong("Acciones");
                    ui.end_row();

                    for doc in &rows {
                        let is_sel = self.selected.as_deref() == Some(doc.vault_id.as_str());
                        if ui.selectable_label(is_sel, &doc.meta.title).clicked() {
                            self.selected = Some(doc.vault_id.clone());
                        }
                        ui.label(doc.meta.category.dir_name());
                        ui.label(&doc.meta.author);
                        ui.label(
                            doc.meta
                                .academic_year
                                .map(|y| y.to_string())
                                .unwrap_or_default(),
                        );
                        let (color, txt) = match doc.integrity {
                            vault_core::IntegrityStatus::Ok => {
                                (egui::Color32::from_rgb(0x2F, 0xBF, 0x71), "ok")
                            }
                            vault_core::IntegrityStatus::Pending => {
                                (egui::Color32::from_rgb(0xE0, 0xA5, 0x2F), "pendiente")
                            }
                            vault_core::IntegrityStatus::Tampered => {
                                (egui::Color32::from_rgb(0xE0, 0x52, 0x52), "¡manipulado!")
                            }
                        };
                        ui.colored_label(color, txt);

                        ui.horizontal(|ui| {
                            let role = session.role;
                            if role.can_rename_or_move()
                                && ui
                                    .add_enabled(can_write, egui::Button::new("✏️").small())
                                    .on_hover_text("Renombrar")
                                    .clicked()
                            {
                                self.modal = Modal::Rename {
                                    vault_id: doc.vault_id.clone(),
                                    name: doc.meta.file_name.clone(),
                                };
                            }
                            if role.can_edit_meta()
                                && ui
                                    .add_enabled(can_write, egui::Button::new("🛠").small())
                                    .on_hover_text("Editar metadatos")
                                    .clicked()
                            {
                                self.modal = Modal::EditMeta {
                                    vault_id: doc.vault_id.clone(),
                                    title: doc.meta.title.clone(),
                                    department: doc.meta.department.clone(),
                                    year: doc
                                        .meta
                                        .academic_year
                                        .map(|y| y.to_string())
                                        .unwrap_or_default(),
                                    note: String::new(),
                                };
                            }
                            if role.can_soft_delete()
                                && ui
                                    .add_enabled(can_write, egui::Button::new("🗑").small())
                                    .on_hover_text("A papelera")
                                    .clicked()
                            {
                                self.modal = Modal::SoftDelete {
                                    vault_id: doc.vault_id.clone(),
                                    reason: String::new(),
                                };
                            }
                            if role.can_audit()
                                && ui.small_button("🕘").on_hover_text("Versiones").clicked()
                            {
                                self.show_versions(&doc.vault_id);
                            }
                            if role == Role::Director
                                && ui
                                    .small_button("👁")
                                    .on_hover_text("Ver (auditado)")
                                    .clicked()
                            {
                                self.director_view(&doc.vault_id);
                            }
                        });
                        ui.end_row();
                    }
                });
            if rows.is_empty() {
                ui.add_space(20.0);
                ui.weak("Sin documentos. Use «＋ Importar…» o sincronice desde el canal móvil.");
            }
        });
        let _ = ctx;
    }

    fn draw_trash(&mut self, ui: &mut egui::Ui) {
        let Some(session) = self.session.clone() else {
            return;
        };
        let can_write = self.can_write();
        let items = match self.roles.as_ref().map(|svc| svc.trashed(&session)) {
            Some(Ok(t)) => t,
            Some(Err(e)) => {
                self.toast(ToastKind::Error, e.to_string());
                Vec::new()
            }
            None => Vec::new(),
        };
        ui.heading("Papelera (soft-delete)");
        ui.label("Los documentos aquí conservan el archivo físico intacto. Solo el modo IT puede purgar definitivamente.");
        ui.add_space(8.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("trash_grid")
                .num_columns(5)
                .spacing([16.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Título");
                    ui.strong("Motivo");
                    ui.strong("Por");
                    ui.strong("Cuándo");
                    ui.strong("Acción");
                    ui.end_row();
                    for t in &items {
                        ui.label(&t.document.meta.title);
                        ui.label(&t.reason);
                        ui.label(&t.trashed_by);
                        ui.label(&t.trashed_at);
                        if ui
                            .add_enabled(can_write, egui::Button::new("↩ Restaurar").small())
                            .on_hover_text(if can_write {
                                "Restaurar al índice activo"
                            } else {
                                "No disponible en modo consulta"
                            })
                            .clicked()
                        {
                            let mut svc_mut_guard = self.roles.take();
                            if let Some(svc) = svc_mut_guard.as_mut() {
                                match svc.restore(&session, &t.document.vault_id) {
                                    Ok(_) => self.toast(ToastKind::Ok, "Documento restaurado"),
                                    Err(e) => self.toast(ToastKind::Error, e.to_string()),
                                }
                            }
                            self.roles = svc_mut_guard;
                        }
                        ui.end_row();
                    }
                });
            if items.is_empty() {
                ui.add_space(12.0);
                ui.weak("La papelera está vacía.");
            }
        });
    }

    fn draw_audit(&mut self, ui: &mut egui::Ui) {
        let Some(session) = self.session.clone() else {
            return;
        };
        let (entries, chain_ok) = match self.roles.as_ref() {
            Some(svc) => (
                svc.audit(&session).unwrap_or_default(),
                svc.db().verify_audit_chain().is_ok(),
            ),
            None => (Vec::new(), false),
        };
        ui.heading("Auditoría");
        if chain_ok {
            ui.colored_label(
                egui::Color32::from_rgb(0x2F, 0xBF, 0x71),
                format!("Cadena íntegra · {} entradas", entries.len()),
            );
        } else {
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x52, 0x52),
                "¡CADENA DE AUDITORÍA COMPROMETIDA!",
            );
        }
        ui.add_space(6.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("audit_grid")
                .num_columns(5)
                .spacing([16.0, 3.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("#");
                    ui.strong("Cuándo");
                    ui.strong("Actor");
                    ui.strong("Acción");
                    ui.strong("Detalle");
                    ui.end_row();
                    for e in entries.iter().rev().take(300) {
                        ui.label(e.seq.to_string());
                        ui.monospace(&e.timestamp);
                        ui.label(&e.actor);
                        ui.label(&e.action);
                        ui.weak(&e.detail);
                        ui.end_row();
                    }
                });
        });
    }

    /// Pantalla de administración de usuarios.
    ///
    /// Solo se muestra con una sesión de administración vigente, que SIEMPRE
    /// se abre fuera de la aplicación: aquí únicamente se detecta. Nada de lo
    /// que se haga en esta pantalla se escribe en la cadena de auditoría
    /// institucional (visible para Coordinación y Dirección).
    fn draw_users(&mut self, ui: &mut egui::Ui) {
        if !self.privileged_active() {
            ui.heading("Usuarios");
            ui.weak("Se requiere una sesión de administración vigente.");
            return;
        }
        let can_write = self.can_write();

        ui.heading("Usuarios y roles");
        ui.horizontal(|ui| {
            ui.label("Sesión de administración activa.");
            if ui.button("Cerrar sesión privilegiada").clicked() {
                self.it_close_session();
            }
        });
        if !can_write {
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0xA5, 0x2F),
                "Modo consulta: detenga el servicio para administrar usuarios.",
            );
        }
        if let Some(rest) = self.privileged_remaining() {
            ui.weak(format!(
                "La sesión caduca sola en {:02}:{:02}.",
                rest / 60,
                rest % 60
            ));
        }
        ui.add_space(8.0);

        let mut action: Option<(String, ItAction)> = None;
        {
            let Some(svc) = self.roles.as_ref() else {
                return;
            };
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("it_users")
                    .num_columns(6)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Usuario");
                        ui.strong("Nombre");
                        ui.strong("PIN");
                        ui.strong("Rol");
                        ui.strong("Estado");
                        ui.strong("Acción");
                        ui.end_row();

                        for u in svc.users() {
                            ui.label(&u.username);
                            ui.label(&u.display_name);
                            // El PIN nunca se guarda en claro: solo se informa
                            // de si está definido.
                            ui.label(if u.pin_hash.is_empty() {
                                "sin definir"
                            } else {
                                "definido"
                            });
                            ui.label(u.role.label());
                            if u.enabled {
                                ui.colored_label(
                                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                                    "activo",
                                );
                            } else {
                                ui.colored_label(egui::Color32::GRAY, "inhabilitado");
                            }
                            ui.horizontal(|ui| {
                                let accion = if u.enabled {
                                    "deshabilitar"
                                } else {
                                    "habilitar"
                                };
                                if ui
                                    .add_enabled(can_write, egui::Button::new(accion).small())
                                    .clicked()
                                {
                                    action = Some((u.username.clone(), ItAction::Toggle));
                                }
                                if ui
                                    .add_enabled(
                                        can_write,
                                        egui::Button::new("definir PIN").small(),
                                    )
                                    .clicked()
                                {
                                    action = Some((u.username.clone(), ItAction::SetPin));
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
        }

        ui.add_space(10.0);
        ui.add_enabled_ui(can_write, |ui| {
            if ui.button("＋ Nuevo usuario…").clicked() {
                self.modal = Modal::NewUser {
                    username: String::new(),
                    display: String::new(),
                    role: Role::Docente,
                    pin: String::new(),
                    pin2: String::new(),
                };
            }
        });

        match action {
            Some((username, ItAction::Toggle)) => self.it_toggle_user(&username),
            Some((username, ItAction::SetPin)) => {
                self.modal = Modal::SetPin {
                    username,
                    pin: String::new(),
                    pin2: String::new(),
                }
            }
            None => {}
        }
    }

    // ------------------------------------------------------------------
    // Acciones de la pantalla de administración (no auditan)
    // ------------------------------------------------------------------

    /// Habilita o deshabilita un usuario. No escribe en la auditoría.
    fn it_toggle_user(&mut self, username: &str) {
        let Some(enabled) = self
            .roles
            .as_ref()
            .and_then(|svc| svc.db().find_user(username).map(|u| u.enabled))
        else {
            return;
        };
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        match svc.set_user_enabled(username, !enabled) {
            Ok(()) => self.toast(
                ToastKind::Ok,
                format!(
                    "{username}: {}",
                    if enabled {
                        "deshabilitado"
                    } else {
                        "habilitado"
                    }
                ),
            ),
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    /// Define el PIN de un usuario. No escribe en la auditoría.
    fn it_set_pin(&mut self, username: &str, pin: &str) {
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        match svc.set_user_pin(username, pin) {
            Ok(()) => self.toast(ToastKind::Ok, format!("PIN de {username} actualizado")),
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    /// Da de alta un usuario. No escribe en la auditoría.
    fn it_add_user(&mut self, username: &str, display: &str, role: Role, pin: &str) {
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        match svc.upsert_user(username, display, role, pin) {
            Ok(()) => self.toast(
                ToastKind::Ok,
                format!("Usuario {} creado ({})", username, role.label()),
            ),
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    /// Cierra la sesión de administración (borra la marca de vigencia).
    fn it_close_session(&mut self) {
        let path = self.vault_data_dir().join("door/session");
        match std::fs::remove_file(&path) {
            Ok(()) => {
                self.screen = Screen::Documents;
                self.toast(ToastKind::Ok, "Sesión de administración finalizada");
            }
            Err(_) => self.toast(ToastKind::Warn, "No había sesión activa"),
        }
    }

    // ------------------------------------------------------------------
    // acciones
    // ------------------------------------------------------------------

    /// Importa un documento local usando el MISMO sellado que la admisión de
    /// entregas (sello de tiempo RFC 3161, deduplicación por contenido e
    /// índice de texto), de modo que el resultado es idéntico al del canal
    /// móvil.
    fn import_document(&mut self, session: &Session, path: PathBuf) {
        if !self.can_write() {
            self.toast(
                ToastKind::Warn,
                "Modo consulta: el servicio está activo y no se puede importar.",
            );
            return;
        }
        if !session.role.can_import() {
            self.toast(
                ToastKind::Error,
                format!(
                    "El rol {} no puede incorporar documentos",
                    session.role.label()
                ),
            );
            return;
        }
        let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
            self.toast(ToastKind::Error, "Ruta sin nombre de archivo");
            return;
        };
        let Ok(content) = std::fs::read(&path) else {
            self.toast(ToastKind::Error, "No se pudo leer el archivo");
            return;
        };
        if content.is_empty() {
            self.toast(ToastKind::Warn, "El archivo está vacío");
            return;
        }

        // Clasificación por nombre/extensión: la institución puede ajustar las
        // reglas sin recompilar en <datos>/config/rules.toml; si no existe se
        // usan las embebidas.
        let ruleset = vault_index::Ruleset::load(&self.vault_data_dir().join("config/rules.toml"))
            .unwrap_or_else(|_| vault_index::Ruleset::default_ruleset());
        let category = ruleset
            .classify(&file_name)
            .unwrap_or(vault_core::Category::MaterialGrafico);
        let meta = vault_core::DocumentMeta {
            title: title_from_file_name(&file_name),
            category,
            author: session.display_name.clone(),
            id_number: None,
            department: String::new(),
            registered_at: vault_core::now_rfc3339(),
            academic_year: None,
            file_name: file_name.clone(),
            extension: extension_of(&file_name),
        };

        // El layout es el mismo del servicio (raíz de la bóveda) y se pasa por
        // valor para no mezclar préstamos mutables e inmutables del servicio.
        let layout = vault_fs::VaultLayout::new(self.vault_root.clone());
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        let outcome = vault_admin::seal_document(
            svc.db_mut(),
            &layout,
            self.tsa.as_ref(),
            vault_admin::SealRequest {
                source: vault_admin::SealSource::Bytes(&content),
                meta,
                origin_device: None, // origen local: no viene de un dispositivo emparejado
                actor: session.actor(),
                audit_action: "import",
            },
        );
        match outcome {
            Ok(vault_admin::SealOutcome::Sealed(doc)) => {
                let stamp = if doc.rfc3161_time.is_some() {
                    " · sello de tiempo RFC 3161"
                } else {
                    ""
                };
                let warn = svc.db_mut().flush().err();
                if let Some(e) = warn {
                    self.toast(ToastKind::Error, format!("BD: {e}"));
                } else {
                    self.toast(
                        ToastKind::Ok,
                        format!("«{file_name}» importado y sellado{stamp}"),
                    );
                }
            }
            Ok(vault_admin::SealOutcome::Duplicate { .. }) => self.toast(
                ToastKind::Warn,
                "Ese documento ya está en la bóveda (mismo contenido).",
            ),
            Err(e) => {
                // fallo de sellado: es un error del sistema, no del usuario →
                // queda reportado de forma cifrada para la administración.
                self.report_error("vault-gui::import", &e.to_string());
                self.toast(ToastKind::Error, e.to_string());
            }
        }
    }

    fn show_versions(&mut self, vault_id: &str) {
        let (Some(svc), Some(session)) = (self.roles.as_ref(), self.session.clone()) else {
            self.toast(ToastKind::Warn, "No hay sesión activa".to_string());
            return;
        };
        match svc.versions_of(&session, vault_id) {
            Ok(vs) if vs.is_empty() => {
                self.toast(ToastKind::Warn, "Este documento no tiene versiones aún.")
            }
            Ok(vs) => {
                let lines: Vec<String> = vs
                    .iter()
                    .map(|v| {
                        format!(
                            "v{} · {} · {} · {}",
                            v.version, v.created_at, v.created_by, v.note
                        )
                    })
                    .collect();
                self.toast(ToastKind::Ok, format!("Versiones: {}", lines.join(" | ")));
            }
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    fn director_view(&mut self, vault_id: &str) {
        let (Some(svc), Some(session)) = (self.roles.as_mut(), self.session.clone()) else {
            self.toast(ToastKind::Warn, "No hay sesión activa".to_string());
            return;
        };
        match svc.view(&session, vault_id) {
            Ok(doc) => self.toast(
                ToastKind::Ok,
                format!("Visualización auditada: {}", doc.meta.title),
            ),
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    fn draw_modal(&mut self, ctx: &egui::Context) {
        let modal = std::mem::replace(&mut self.modal, Modal::None);
        match modal {
            Modal::None => {}
            Modal::Confirm {
                title,
                body,
                action,
            } => {
                let mut open = true;
                egui::Window::new(&title)
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(&body);
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                            }
                            if ui
                                .button(egui::RichText::new("Confirmar").strong())
                                .clicked()
                            {
                                match action {
                                    PendingAction::Logout => self.logout(),
                                    PendingAction::QuitApp => std::process::exit(0),
                                }
                                self.modal = Modal::None;
                            }
                        });
                    });
                if !open {
                    self.modal = Modal::None;
                }
            }
            Modal::Rename { vault_id, name } => {
                let mut open = true;
                let mut name = name;
                egui::Window::new("Renombrar documento")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("Nuevo nombre de archivo:");
                        let resp =
                            ui.add(egui::TextEdit::singleline(&mut name).desired_width(320.0));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                            }
                            let enter =
                                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            if ui
                                .button(egui::RichText::new("Renombrar").strong())
                                .clicked()
                                || enter
                            {
                                self.apply_rename(&vault_id, &name);
                                self.modal = Modal::None;
                            }
                        });
                    });
                if !open {
                    self.modal = Modal::None;
                }
            }
            Modal::EditMeta {
                vault_id,
                title,
                department,
                year,
                note,
            } => {
                let mut open = true;
                let mut st = (title, department, year, note);
                egui::Window::new("Editar metadatos")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("Nota: si es Coordinación, se creará una copia de seguridad inmutable del estado previo.");
                        ui.add_space(6.0);
                        egui::Grid::new("edit_meta_grid").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            ui.label("Título"); ui.add(egui::TextEdit::singleline(&mut st.0).desired_width(280.0)); ui.end_row();
                            ui.label("Departamento"); ui.add(egui::TextEdit::singleline(&mut st.1).desired_width(280.0)); ui.end_row();
                            ui.label("Año"); ui.add(egui::TextEdit::singleline(&mut st.2).desired_width(280.0)); ui.end_row();
                            ui.label("Nota"); ui.add(egui::TextEdit::singleline(&mut st.3).desired_width(280.0)); ui.end_row();
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                            }
                            if ui.button(egui::RichText::new("Guardar").strong()).clicked() {
                                self.apply_edit_meta(&vault_id, &st.0, &st.1, &st.2, &st.3);
                                self.modal = Modal::None;
                            }
                        });
                    });
                if !open {
                    self.modal = Modal::None;
                }
            }
            Modal::SoftDelete { vault_id, reason } => {
                let mut open = true;
                let mut reason = reason;
                egui::Window::new("Enviar a papelera")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("El archivo NO se destruye; quedará en la papelera y podrá restaurarse.");
                        ui.label("Motivo (obligatorio):");
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut reason)
                                .desired_width(320.0)
                                .hint_text("p. ej. duplicado detectado"),
                        );
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                            }
                            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            if (ui.button(egui::RichText::new("A papelera").strong()).clicked() || enter)
                                && !reason.trim().is_empty()
                            {
                                self.apply_soft_delete(&vault_id, &reason);
                                self.modal = Modal::None;
                            }
                        });
                    });
                if !open {
                    self.modal = Modal::None;
                }
            }
            Modal::NewUser {
                username,
                display,
                role,
                pin,
                pin2,
            } => {
                // Solo tiene sentido con la sesión de administración vigente.
                if !self.privileged_active() {
                    self.modal = Modal::None;
                    return;
                }
                let mut open = true;
                let mut st = (username, display, role, pin, pin2);
                egui::Window::new("Nuevo usuario")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        egui::Grid::new("new_user_grid")
                            .num_columns(2)
                            .spacing([10.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Usuario");
                                ui.add(egui::TextEdit::singleline(&mut st.0).desired_width(240.0));
                                ui.end_row();
                                ui.label("Nombre");
                                ui.add(egui::TextEdit::singleline(&mut st.1).desired_width(240.0));
                                ui.end_row();
                                ui.label("Rol");
                                egui::ComboBox::from_id_salt("new_user_role")
                                    .selected_text(st.2.label())
                                    .show_ui(ui, |ui| {
                                        for r in Role::ALL {
                                            ui.selectable_value(&mut st.2, r, r.label());
                                        }
                                    });
                                ui.end_row();
                                ui.label("PIN (mín. 6)");
                                ui.add(
                                    egui::TextEdit::singleline(&mut st.3)
                                        .password(true)
                                        .desired_width(240.0),
                                );
                                ui.end_row();
                                ui.label("Repita el PIN");
                                ui.add(
                                    egui::TextEdit::singleline(&mut st.4)
                                        .password(true)
                                        .desired_width(240.0),
                                );
                                ui.end_row();
                            });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                            }
                            if ui.button(egui::RichText::new("Crear").strong()).clicked() {
                                if st.0.trim().is_empty() {
                                    self.toast(ToastKind::Warn, "Indique el usuario");
                                } else if st.3.len() < 6 || st.3 != st.4 {
                                    self.toast(
                                        ToastKind::Warn,
                                        "El PIN debe tener 6 caracteres o más y coincidir",
                                    );
                                } else {
                                    let (u, d, r, p) =
                                        (st.0.clone(), st.1.clone(), st.2, st.3.clone());
                                    self.it_add_user(&u, &d, r, &p);
                                    self.modal = Modal::None;
                                }
                            }
                        });
                    });
                if !open {
                    self.modal = Modal::None;
                }
            }
            Modal::SetPin {
                username,
                pin,
                pin2,
            } => {
                if !self.privileged_active() {
                    self.modal = Modal::None;
                    return;
                }
                let mut open = true;
                let mut st = (pin, pin2);
                egui::Window::new(format!("PIN de {username}"))
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("Nuevo PIN (mínimo 6 caracteres):");
                        ui.add(
                            egui::TextEdit::singleline(&mut st.0)
                                .password(true)
                                .desired_width(260.0),
                        );
                        ui.label("Repita el PIN:");
                        ui.add(
                            egui::TextEdit::singleline(&mut st.1)
                                .password(true)
                                .desired_width(260.0),
                        );
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                            }
                            if ui.button(egui::RichText::new("Guardar").strong()).clicked() {
                                if st.0.len() < 6 || st.0 != st.1 {
                                    self.toast(
                                        ToastKind::Warn,
                                        "El PIN debe tener 6 caracteres o más y coincidir",
                                    );
                                } else {
                                    let (u, p) = (username.clone(), st.0.clone());
                                    self.it_set_pin(&u, &p);
                                    self.modal = Modal::None;
                                }
                            }
                        });
                    });
                if !open {
                    self.modal = Modal::None;
                }
            }
            Modal::FilePicker { dir, mut filter } => {
                let mut open = true;
                let mut goto: Option<PathBuf> = None;
                let mut pick: Option<PathBuf> = None;
                egui::Window::new("Importar documento")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(true)
                    .default_size([560.0, 420.0])
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            if ui.button("⬆ Subir").clicked() {
                                if let Some(parent) = dir.parent() {
                                    goto = Some(parent.to_path_buf());
                                }
                            }
                            if ui.button("🏠 Inicio").clicked() {
                                goto = Some(BovedaApp::default_data_dir());
                            }
                            ui.add(
                                egui::TextEdit::singleline(&mut filter)
                                    .hint_text("filtrar por nombre o extensión")
                                    .desired_width(220.0),
                            );
                        });
                        ui.monospace(dir.display().to_string());
                        ui.separator();

                        let entries = picker_entries(&dir, &filter);
                        egui::ScrollArea::vertical()
                            .max_height(300.0)
                            .show(ui, |ui| {
                                if entries.is_empty() {
                                    ui.weak("Sin coincidencias en esta carpeta.");
                                }
                                for e in entries {
                                    let label = if e.is_dir {
                                        format!("📁 {}", e.name)
                                    } else {
                                        format!("📄 {}", e.name)
                                    };
                                    if ui.selectable_label(false, label).clicked() {
                                        if e.is_dir {
                                            goto = Some(e.path.clone());
                                        } else {
                                            pick = Some(e.path.clone());
                                        }
                                    }
                                }
                            });
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancelar").clicked() {
                                self.modal = Modal::None;
                                return;
                            }
                            ui.weak("Seleccione un archivo para importarlo y sellarlo.");
                        });
                    });
                if let Some(d) = goto {
                    self.modal = Modal::FilePicker { dir: d, filter };
                } else if !open {
                    self.modal = Modal::None;
                } else if let Some(path) = pick {
                    let session = self.session.clone();
                    if let Some(s) = session {
                        self.import_document(&s, path);
                    }
                    self.modal = Modal::None;
                } else {
                    // mantener el estado del selector entre fotogramas
                    self.modal = Modal::FilePicker { dir, filter };
                }
            }
        }
    }

    fn apply_rename(&mut self, vault_id: &str, new_name: &str) {
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        let Some(session) = self.session.clone() else {
            return;
        };
        match svc.rename(&session, vault_id, new_name) {
            Ok(doc) => self.toast(
                ToastKind::Ok,
                format!("Renombrado a «{}»", doc.meta.file_name),
            ),
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    fn apply_edit_meta(
        &mut self,
        vault_id: &str,
        title: &str,
        department: &str,
        year: &str,
        note: &str,
    ) {
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        let Some(session) = self.session.clone() else {
            return;
        };
        let year_opt = year.trim().parse::<u16>().ok();
        match svc.edit_meta(
            &session,
            vault_id,
            (!title.trim().is_empty()).then(|| title.trim().to_string()),
            (!department.trim().is_empty()).then(|| department.trim().to_string()),
            year_opt,
            note,
        ) {
            Ok(doc) => {
                let v = if session.role.versions_on_edit() {
                    " · versión inmutable creada"
                } else {
                    ""
                };
                self.toast(
                    ToastKind::Ok,
                    format!("Metadatos actualizados: {}{v}", doc.meta.title),
                );
            }
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }

    fn apply_soft_delete(&mut self, vault_id: &str, reason: &str) {
        let Some(svc) = self.roles.as_mut() else {
            return;
        };
        let Some(session) = self.session.clone() else {
            return;
        };
        match svc.soft_delete(&session, vault_id, reason) {
            Ok(()) => self.toast(
                ToastKind::Ok,
                "Documento enviado a la papelera (restaurable)",
            ),
            Err(e) => self.toast(ToastKind::Error, e.to_string()),
        }
    }
}

fn nav_item(ui: &mut egui::Ui, screen: &mut Screen, target: Screen, icon: &str, label: &str) {
    let selected = *screen == target;
    let txt = format!("{icon}  {label}");
    if ui
        .selectable_label(selected, egui::RichText::new(txt).size(15.0))
        .clicked()
    {
        *screen = target;
    }
}

/// Selector gráfico de archivo (diálogo nativo del sistema). Sin consola.
fn rfd_pick_file() -> Option<PathBuf> {
    // eframe no trae diálogos nativos; usamos el diálogo del SO via zenity/kdialog
    // solo si existen; si no, entrada manual modal (sigue siendo 100 % gráfica).
    for (bin, args) in [
        (
            "zenity",
            vec!["--file-selection", "--title=Importar documento"],
        ),
        (
            "kdialog",
            vec!["--getopenfilename", ".", "--title", "Importar documento"],
        ),
    ] {
        if which(bin) {
            if let Ok(out) = std::process::Command::new(bin).args(args).output() {
                if out.status.success() {
                    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !p.is_empty() {
                        return Some(PathBuf::from(p));
                    }
                }
            }
        }
    }
    None
}

/// Acción disponible en la pantalla de administración de usuarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItAction {
    Toggle,
    SetPin,
}

/// Entrada del selector de archivos propio.
#[derive(Debug, Clone, PartialEq)]
struct PickerEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
}

/// Lista carpetas y archivos de `dir` (carpetas primero), filtrando por
/// subcadena del nombre cuando hay filtro. `..` no se lista: se navega con el
/// botón «Subir».
fn picker_entries(dir: &std::path::Path, filter: &str) -> Vec<PickerEntry> {
    let needle = filter.trim().to_lowercase();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue; // nada oculto: la bóveda y sus datos no se exponen aquí
        }
        if !needle.is_empty() && !name.to_lowercase().contains(&needle) {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        let entry = PickerEntry {
            name,
            path: e.path(),
            is_dir: ft.is_dir(),
        };
        if entry.is_dir {
            dirs.push(entry);
        } else {
            files.push(entry);
        }
    }
    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    files.sort_by(|a, b| a.name.cmp(&b.name));
    dirs.extend(files);
    dirs
}

/// Elimina los temporales de staging y devuelve cuántos se borraron.
fn clean_staging(vault_root: &std::path::Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(vault_root.join(".staging")) {
        for e in rd.flatten() {
            if e.path().is_file() {
                let _ = std::fs::remove_file(e.path());
                n += 1;
            }
        }
    }
    n
}

/// Título legible a partir del nombre de archivo (sin la última extensión).
fn title_from_file_name(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((stem, _ext)) if !stem.is_empty() => stem.to_string(),
        _ => file_name.to_string(),
    }
}

/// Extensión en minúsculas de un nombre de archivo ("" si no tiene).
fn extension_of(file_name: &str) -> String {
    file_name
        .rsplit_once('.')
        .map(|(stem, ext)| if stem.is_empty() { "" } else { ext })
        .unwrap_or("")
        .to_lowercase()
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|dir| {
                let candidate = dir.join(bin);
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}
/// Arranca la aplicación gráfica (punto de entrada para bins).
pub fn run_gui() -> Result<(), eframe::Error> {
    // 1) reportes de fallo: claves + hook de pánico ANTES de cualquier otra cosa
    //    (mismo layout que vaultd: ~/.boveda/data/{door,config,crash})
    let data_dir = BovedaApp::default_data_dir().join("data");
    let _ = std::fs::create_dir_all(&data_dir);
    if let Some(pub_hex) = ensure_crash_keys(&data_dir) {
        let signing = vault_crash::load_or_create_app_key(&data_dir).ok();
        vault_crash::CrashReporter::new(pub_hex, data_dir.join("crash"), signing)
            .install_panic_hook();
    }
    // 2) ventana
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 680.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("Bóveda académica"),
        ..Default::default()
    };
    eframe::run_native(
        "Bóveda académica",
        options,
        Box::new(|cc| Ok(Box::new(BovedaApp::new(cc)))),
    )
}

// reexport para que bins usen tipos clave
pub use BovedaApp as App;

#[cfg(test)]
mod tests {
    use super::*;

    /// App con bóveda en blanco dentro de un directorio temporal propio.
    fn test_app() -> (BovedaApp, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join(".boveda");
        let app = BovedaApp {
            vault_root: data_dir.join("vault"),
            data_dir,
            roles: None,
            session: None,
            tsa: None,
            read_only: false,
            screen: Screen::Login,
            modal: Modal::None,
            boot_pin: String::new(),
            boot_pin2: String::new(),
            login_user: String::new(),
            login_pass: String::new(),
            search: String::new(),
            selected: None,
            toasts: Vec::new(),
            it_pubkey: None,
            reporter: None,
            last_report: None,
        };
        (app, dir)
    }

    /// App ya configurada (bootstrap hecho) con cuatro usuarios estándar.
    fn bootstrapped_app() -> (BovedaApp, tempfile::TempDir) {
        let (mut app, dir) = test_app();
        app.boot_pin = "123456".into();
        app.boot_pin2 = "123456".into();
        app.bootstrap();
        (app, dir)
    }

    fn write_temp_file(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    impl BovedaApp {
        /// Inicia sesión en la bóveda de prueba y devuelve la sesión.
        fn login_as(&mut self, username: &str) -> Session {
            self.login_user = username.to_string();
            self.login_pass = "123456".to_string();
            self.do_login();
            self.session
                .clone()
                .unwrap_or_else(|| panic!("no se pudo iniciar sesión como {username}"))
        }
    }

    #[test]
    fn role_matrix_helpers() {
        assert!(Role::Docente.can_view());
        assert!(!Role::Docente.can_rename_or_move());
        assert!(Role::Administrativo.can_soft_delete());
        assert!(Role::Administrativo.can_edit_meta());
        assert!(Role::Coordinacion.versions_on_edit());
        assert!(!Role::Administrativo.versions_on_edit());
        assert!(Role::Director.can_audit());
        assert!(!Role::Docente.can_audit());
        // importar: Administrativo y Coordinación sí; Docente y Dirección no
        assert!(Role::Administrativo.can_import());
        assert!(Role::Coordinacion.can_import());
        assert!(!Role::Docente.can_import());
        assert!(!Role::Director.can_import());
    }

    #[test]
    fn default_data_dir_under_home() {
        let d = BovedaApp::default_data_dir();
        assert!(d.ends_with(".boveda"));
    }

    #[test]
    fn toasts_expire() {
        let (mut app, _dir) = test_app();
        app.toast(ToastKind::Ok, "hola");
        assert_eq!(app.toasts.len(), 1);
        // forzar expiración
        app.toasts[0].born = std::time::Instant::now() - std::time::Duration::from_secs(10);
        app.toasts.retain(|t| t.alive());
        assert!(app.toasts.is_empty());
    }

    #[test]
    fn title_and_extension_helpers() {
        assert_eq!(title_from_file_name("informe.pdf"), "informe");
        // no debe comerse extensiones repetidas del nombre
        assert_eq!(title_from_file_name("acta.doc.doc"), "acta.doc");
        assert_eq!(title_from_file_name("sin_extension"), "sin_extension");
        assert_eq!(title_from_file_name(".oculto"), ".oculto");
        assert_eq!(extension_of("Tesis.PDF"), "pdf");
        assert_eq!(extension_of("sin_extension"), "");
    }

    /// Flujo completo sin ventana: bootstrap → login de los cuatro roles →
    /// matriz de permisos aplicada por el servicio.
    #[test]
    fn bootstrap_login_and_permission_matrix() {
        let (mut app, _dir) = bootstrapped_app();
        assert_eq!(app.screen, Screen::Login, "tras crear, debe pedir login");

        // la bóveda existe en el layout canónico <datos>/data/db/
        assert!(app.data_dir.join("data/db/vault.db.enc").exists());
        let kf = std::fs::read(app.data_dir.join("data/vault.key")).unwrap();
        assert_eq!(kf.len(), 64, "keyfile de 64 bytes");

        // cuatro usuarios estándar con su rol
        let users = app.roles.as_ref().unwrap().users();
        assert_eq!(users.len(), 4);
        for (u, r) in [
            ("director", Role::Director),
            ("coordinacion", Role::Coordinacion),
            ("administrativo", Role::Administrativo),
            ("docente", Role::Docente),
        ] {
            let found = users.iter().find(|x| x.username == u).expect("usuario");
            assert_eq!(found.role, r);
            assert!(found.enabled);
        }
        // y el bootstrap queda auditado
        assert!(app
            .roles
            .as_ref()
            .unwrap()
            .db()
            .audit()
            .iter()
            .any(|a| a.action == "bootstrap"));

        // login real de cada rol con el PIN del bootstrap
        for (u, r) in [
            ("director", Role::Director),
            ("coordinacion", Role::Coordinacion),
            ("administrativo", Role::Administrativo),
            ("docente", Role::Docente),
        ] {
            app.login_user = u.into();
            app.login_pass = "123456".into();
            app.do_login();
            let session = app.session.clone().expect("sesión iniciada");
            assert_eq!(session.role, r);
            assert!(app.login_pass.is_empty(), "la contraseña no se conserva");
            app.logout();
        }

        // credenciales incorrectas no abren sesión
        app.login_user = "docente".into();
        app.login_pass = "mala".into();
        app.do_login();
        assert!(app.session.is_none());
        assert!(app.toasts.iter().any(|t| t.kind == ToastKind::Error));

        // matriz de permisos por rol sobre un documento real
        let (mut app, dir) = bootstrapped_app();
        let docente = app.login_as("docente");
        let administrativo = app.login_as("administrativo");
        let coordinacion = app.login_as("coordinacion");
        let director = app.login_as("director");

        let src = write_temp_file(dir.path(), "acta.txt", b"acta de la sesion ordinaria");
        app.session = Some(administrativo.clone());
        app.import_document(&administrativo, src);
        let svc = app.roles.as_ref().unwrap();
        assert_eq!(svc.db().documents().len(), 1, "el administrativo importa");
        let doc = svc.db().documents()[0].clone();

        // Docente: solo lectura
        assert!(!docente.role.can_import());
        assert!(matches!(
            app.roles
                .as_mut()
                .unwrap()
                .soft_delete(&docente, &doc.vault_id, "x"),
            Err(vault_roles::RoleError::Denied(_))
        ));
        // Administrativo: papelera sí, auditoría no
        assert!(matches!(
            app.roles.as_ref().unwrap().audit(&administrativo),
            Err(vault_roles::RoleError::Denied(_))
        ));
        app.roles
            .as_mut()
            .unwrap()
            .soft_delete(&administrativo, &doc.vault_id, "duplicado")
            .unwrap();
        assert_eq!(app.roles.as_ref().unwrap().db().trashed().len(), 1);
        app.roles
            .as_mut()
            .unwrap()
            .restore(&administrativo, &doc.vault_id)
            .unwrap();
        // Coordinación: auditoría sí y versionado al editar
        assert!(app.roles.as_ref().unwrap().audit(&coordinacion).is_ok());
        app.roles
            .as_mut()
            .unwrap()
            .edit_meta(
                &coordinacion,
                &doc.vault_id,
                Some("Acta corregida".into()),
                None,
                None,
                "corrección",
            )
            .unwrap();
        assert_eq!(
            app.roles
                .as_ref()
                .unwrap()
                .db()
                .versions_of(&doc.vault_id)
                .len(),
            1
        );
        // Dirección: visualización auditada
        app.roles
            .as_mut()
            .unwrap()
            .view(&director, &doc.vault_id)
            .unwrap();
        assert!(app
            .roles
            .as_ref()
            .unwrap()
            .db()
            .verify_audit_chain()
            .is_ok());
    }

    /// La importación sella con el mismo camino que la admisión: dedup por
    /// contenido y texto indexado (la búsqueda por contenido lo encuentra).
    #[test]
    fn import_seals_dedups_and_indexes() {
        let (mut app, dir) = bootstrapped_app();
        let adm = app.login_as("administrativo");

        let a = write_temp_file(dir.path(), "tesis.txt", b"estudio sobre penicilina 2026");
        app.import_document(&adm, a.clone());
        let svc = app.roles.as_ref().unwrap();
        assert_eq!(svc.db().documents().len(), 1);
        let doc = svc.db().documents()[0].clone();
        // metadatos derivados del nombre
        assert_eq!(doc.meta.title, "tesis");
        assert_eq!(doc.meta.extension, "txt");
        assert_eq!(doc.meta.author, adm.display_name);
        // el archivo está en la bóveda y sellado
        let sealed = svc.layout().abs_path(&doc.rel_path);
        assert!(sealed.exists());
        assert!(std::fs::write(&sealed, b"hack").is_err(), "sellado");
        // índice de texto: búsqueda por contenido
        let found = svc.search(&adm, "texto:penicilina").unwrap();
        assert_eq!(found.len(), 1, "la búsqueda por contenido debe encontrarlo");

        // el mismo contenido con otro nombre: duplicado, no se suma otra vez
        let b = write_temp_file(dir.path(), "copia.txt", b"estudio sobre penicilina 2026");
        app.import_document(&adm, b);
        assert_eq!(app.roles.as_ref().unwrap().db().documents().len(), 1);
        assert!(app
            .toasts
            .iter()
            .any(|t| t.kind == ToastKind::Warn && t.text.contains("ya está")));
    }

    /// Con el servicio activo la app abre en modo consulta y no modifica nada.
    #[test]
    fn read_only_mode_blocks_writes() {
        let (mut app, _dir) = bootstrapped_app();
        let kf: [u8; 64] = std::fs::read(app.data_dir.join("data/vault.key"))
            .unwrap()
            .try_into()
            .unwrap();

        // la app cierra su handle y el «servicio» toma la escritura
        app.roles = None;
        let _service = VaultDb::open(&app.data_dir.join("data/db"), &kf).unwrap();
        assert!(!_service.is_read_only(), "el servicio es el escritor");

        app.open_vault().unwrap();
        assert!(app.read_only, "debe detectar el modo consulta");
        assert!(!app.can_write());
        assert!(app.tsa.is_none(), "en modo consulta no se crea la TSA");

        // leer y autenticar sí
        let adm = app.login_as("administrativo");
        assert_eq!(app.roles.as_ref().unwrap().documents(&adm).len(), 0);

        // importar avisa y no añade nada
        let incoming = tempfile::tempdir().unwrap();
        let src = write_temp_file(incoming.path(), "x.txt", b"contenido");
        app.import_document(&adm, src);
        assert_eq!(app.roles.as_ref().unwrap().db().documents().len(), 0);
        assert!(app
            .toasts
            .iter()
            .any(|t| t.kind == ToastKind::Warn && t.text.contains("Modo consulta")));
    }

    /// La pantalla de usuarios solo vive con la sesión de administración
    /// vigente y NUNCA escribe en la cadena de auditoría.
    #[test]
    fn administration_screen_requires_session_and_leaves_no_audit_trace() {
        let (mut app, _dir) = bootstrapped_app();
        let session_path = app.data_dir.join("data/door/session");

        // sin sesión no hay administración
        assert!(!app.privileged_active());
        let before = app.roles.as_ref().unwrap().db().audit().len();
        app.it_toggle_user("docente");
        app.it_set_pin("docente", "999999");
        // (aunque se invoque sin sesión, no audita: el invariante es de la
        // cadena, y las acciones de la pantalla se bloquean en la interfaz)
        assert_eq!(app.roles.as_ref().unwrap().db().audit().len(), before); // la marca de sesión la escribe la consola, no la app
        std::fs::create_dir_all(session_path.parent().unwrap()).unwrap();
        std::fs::write(&session_path, now_epoch().saturating_sub(5).to_string()).unwrap();
        assert!(
            !app.privileged_active(),
            "una marca caducada no abre sesión"
        );
        std::fs::write(&session_path, (now_epoch() + 900).to_string()).unwrap();
        assert!(app.privileged_active());
        assert!(app.privileged_remaining().unwrap() > 800);

        // alta, cambio de PIN y deshabilitado: sin rastro en la auditoría
        app.it_add_user("nuevo", "Nuevo Docente", Role::Docente, "abcdef");
        app.it_set_pin("nuevo", "654321");
        app.it_toggle_user("nuevo");
        assert_eq!(
            app.roles.as_ref().unwrap().db().audit().len(),
            before,
            "la administración interna no debe auditarse"
        );
        // pero surte efecto
        let svc = app.roles.as_ref().unwrap();
        assert!(svc.db().find_user("nuevo").is_some());
        assert!(!svc.db().find_user("nuevo").unwrap().enabled);

        // cerrar la sesión la deja sin efecto de inmediato
        app.it_close_session();
        assert!(!app.privileged_active());
        assert!(!session_path.exists());
    }

    /// El selector propio lista carpetas y archivos, ignora lo oculto y filtra.
    #[test]
    fn file_picker_lists_and_filters() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subcarpeta")).unwrap();
        std::fs::create_dir(dir.path().join(".oculta")).unwrap();
        std::fs::write(dir.path().join("tesis.pdf"), b"x").unwrap();
        std::fs::write(dir.path().join("notas.txt"), b"y").unwrap();

        let all = picker_entries(dir.path(), "");
        let names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["subcarpeta", "notas.txt", "tesis.pdf"]);
        assert!(all[0].is_dir, "las carpetas van primero");

        let pdf = picker_entries(dir.path(), ".pdf");
        assert_eq!(pdf.len(), 1);
        assert_eq!(pdf[0].name, "tesis.pdf");
        assert!(!pdf[0].is_dir);
    }

    /// La limpieza de staging borra temporales y no toca los documentos.
    #[test]
    fn clean_staging_removes_only_temporaries() {
        let (mut app, window) = bootstrapped_app();
        let adm = app.login_as("administrativo");
        let src = write_temp_file(window.path(), "nota.txt", b"contenido indice");
        app.import_document(&adm, src);

        let staging = app.vault_root.join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("tmp-1.incoming"), b"sobra").unwrap();
        std::fs::write(staging.join("tmp-2.incoming"), b"sobra").unwrap();

        assert_eq!(clean_staging(&app.vault_root), 2);
        assert!(std::fs::read_dir(&staging).unwrap().next().is_none());
        // el documento sellado sigue donde estaba
        assert_eq!(app.roles.as_ref().unwrap().db().documents().len(), 1);
    }
}
