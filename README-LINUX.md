# Bóveda Académica — Linux, una sola máquina

Sistema Integral de Bóveda: custodia documental académica con sellado criptográfico
(SHA-256 + BLAKE3 + RFC 3161), inmutabilidad física, cola de admisión, auditoría
encadenada y panel de administración web.

**Escenario soportado:** TODO funciona en **un solo computador Linux**, sin root y
sin servidores externos. La misma máquina levanta el servidor (`vaultd`) y actúa
como dispositivo cliente (`vaultctl`).

---

## Arranque rápido (3 comandos)

```bash
cd Linux/vault
./scripts/quickstart.sh MiPinSeguro2026
```

Eso compila (solo la primera vez), crea la bóveda en `~/.boveda/`, levanta el
servidor y abre el panel:

| Componente          | Dónde                          |
|---------------------|--------------------------------|
| Panel de administración | http://localhost:8443/     |
| Canal mTLS          | `127.0.0.1:8642`               |
| Bóveda (documentos) | `~/.boveda/vault/`             |
| Datos internos      | `~/.boveda/data/`              |
| CA para emparejar   | `~/.boveda/data/ca.pem`        |

Dentro de `~/.boveda/data/`:

| Archivo / carpeta | Contenido |
|---|---|
| `vault.key` | Clave maestra de 64 bytes (0600): **sin ella la bóveda es irrecuperable** |
| `db/vault.db.enc` | Base de datos cifrada (un solo escritor a la vez, ver «Modo consulta») |
| `pki/`, `tsa/`, `ca.pem` | Autoridad del canal mTLS y sellador de tiempo RFC 3161 |
| `config/it.pub` | Clave pública a la que se cifran los reportes de fallo |
| `config/rules.toml` | *(opcional)* reglas de clasificación de documentos por nombre/extensión |
| `crash/` | Reportes de fallo cifrados (`.crpt`) |
| `app.key.pem`, `app.pub` | Identidad de la instalación que firma cada reporte |

## Flujo completo en la misma máquina

1. **Levantar la bóveda** (terminal 1):
   ```bash
   ./scripts/quickstart.sh MiPinSeguro2026
   ```
   El PIN de administrador queda configurado con lo que ponga aquí.

2. **Abrir el panel** — http://localhost:8443/ — e iniciar sesión con el PIN.

3. **Generar código de emparejamiento**: botón «Generar código» (válido 10 min).

4. **Emparejar esta máquina como dispositivo** (terminal 2):
   ```bash
   ./target/release/vaultctl pair 127.0.0.1:8642 <CÓDIGO> AND_LOCAL \
       --ca ~/.boveda/data/ca.pem
   ```
   La identidad queda en `./vaultctl-identity/` (solo se hace una vez).

5. **Enviar un documento**:
   ```bash
   ./target/release/vaultctl upload 127.0.0.1:8642 Tesis_Ingenieria_2026.pdf
   ```
   El archivo llega a la cola de admisión del panel (verificado por hash).

6. **Admitir en el panel** → el documento se sella (solo lectura + bit inmutable),
   recibe sello de tiempo RFC 3161 y queda registrado en la auditoría encadenada.

7. **Buscar / auditar / destruir** desde el panel:
   - Búsqueda compuesta: `categoria:Tesis AND departamento:"Ingeniería" AND año:2026`
   - «Verificar integridad»: barrido anti bit-rot inmediato.
   - Destrucción supervisada: exige PIN de administrador **y** PIN de destrucción
     (configurable en el panel), con tombstone + auditoría.

## Comandos

### vaultd (servidor)
```
vaultd --quickstart [PIN]   crea bóveda + PIN y arranca todo (recomendado)
vaultd --init PIN           solo configura el PIN y sale
vaultd --no-landlock        desactiva el confinamiento del proceso (Linux)
vaultd                      arranca con la config existente (~/.boveda/vaultd.toml)
```

Por defecto el servicio se **confina con Landlock** (Linux): sólo puede leer y
escribir dentro de `~/.boveda/`; del resto del sistema únicamente alcanza los
directorios imprescindibles (`/usr`, `/etc`, `/proc`, `/dev`, `/tmp`…), nunca el
HOME del usuario. Si el kernel no lo soporta se avisa y el servicio arranca sin
confinamiento (`--no-landlock` evita el intento explícitamente).

Si el servicio ya está en marcha y se intenta arrancar otro escritor, **falla con
un mensaje claro**: la base de datos admite un único escritor para que nadie
pierda cambios.

### vaultctl (cliente de esta máquina)
```
vaultctl discover                        busca bóvedas en la LAN (mDNS)
vaultctl pair <addr> <código> <id> --ca <ca.pem>
vaultctl ping <addr>
vaultctl manifest <addr>                 hashes presentes en la bóveda
vaultctl upload <addr> <archivo> [--categoria C]
```

## App gráfica (100 % ventanas, sin consola)

`target/release/vault-gui` (o `/opt/intranet-suite/bin/vault-gui`) abre una
aplicación de escritorio con tema negro puro: nunca requiere terminal.

```
vault-gui                 uso normal: gestión documental según el rol
vault-gui --ITA           habilita las pantallas de administración de esta ejecución
vault-gui --no-landlock   no confina la escritura del proceso (Linux)
vault-gui --help          ayuda
```

La aplicación **no se confina en lectura** (necesita poder importar de cualquier
carpeta), pero en Linux sí confina su **escritura** a `~/.boveda/` mediante
Landlock. Las pantallas de **Usuarios** y **Sistema** existen únicamente con
`--ITA` y, además, requieren una sesión de administración vigente abierta por la
consola de administración. Nada de lo que se haga en ellas se escribe en la
cadena de auditoría institucional.

- **Primera ejecución**: pide un PIN y crea la bóveda con cuatro usuarios
  estándar (mismo PIN para todos, cámbielos después desde la gestión de
  usuarios de su instalación):

  | Usuario         | Rol           | Permisos sobre documentos                          |
  |-----------------|---------------|-----------------------------------------------------|
  | `director`      | Dirección     | visión global + consultar auditoría + logs          |
  | `coordinacion`  | Coordinación  | editar metadatos (versionado inmutable) + auditoría |
  | `administrativo`| Administración| renombrar/mover + papelera (restaurable)            |
  | `docente`       | Docentes      | solo lectura y búsqueda                             |

- **Pantallas**: Documentos (búsqueda compuesta, *importar*, renombrar, mover),
  Papelera (restaurar) y Auditoría (cadena verificada).
- **Importar** sella con el mismo camino que el canal móvil: deduplicación por
  contenido, sello de tiempo RFC 3161, archivo inmutable y **texto indexado**
  (la búsqueda `texto:penicilina` encuentra el contenido del documento).
- La **búsqueda por contenido** cubre PDF, **Word (`docx`)**, **Excel (`xlsx`)**,
  **PowerPoint (`pptx`)**, **OpenDocument (`odt`/`ods`/`odp`)**, RTF, texto plano
  y OCR de imágenes si `tesseract` está instalado. El Office binario antiguo
  (`.doc`/`.xls`/`.ppt`) se indexa si hay `antiword` o `catdoc` disponibles.
- El **selector de archivos** es propio de la aplicación: no necesita ningún
  diálogo externo instalado ni lanza procesos del sistema (nada de `zenity` ni
  `kdialog`).
- Usa la **misma bóveda** que `vaultd`: keyfile y BD en `~/.boveda/data/`.
  Si no existe, el asistente la crea; si existe, arranca en el login.
- Ante un fallo inesperado (o un error lógico registrado) la app genera un
  reporte cifrado y **firmado con la identidad de la instalación**, lo deja en
  `~/.boveda/data/crash/` y continúa de forma controlada.

### Modo consulta (servicio y aplicación a la vez)

La base de datos admite **un solo escritor**. Si el servicio (`vaultd`) está en
marcha y se abre la aplicación gráfica, ésta detecta la situación y se abre en
**modo consulta**: un aviso permanente en la parte superior, todas las acciones
de escritura desactivadas y ninguna posibilidad de pisar los cambios del
servicio. Para administrar desde la ventana, detenga el servicio (Ctrl-C) y
vuelva a abrir la aplicación.

## Seguridad

- **Keyfile** de 64 bytes en `~/.boveda/data/vault.key` (0600): sin él, la BD
  cifrada es irrecuperable. Haga copia de seguridad de ese archivo.
- Toda la BD de metadatos viaja cifrada (XChaCha20-Poly1305, bloques autenticados).
- La auditoría es una **cadena hash-linked**: alterar cualquier entrada rompe toda
  la cadena y el panel lo muestra en rojo.
- Los documentos admitidos se sellan con `chattr +i` (bit inmutable): ni root
  puede modificarlos sin retirarlo primero (solo la destrucción supervisada lo hace).
- El canal móvil exige mTLS con certificado de cliente emitido por la CA de la
  bóveda tras el emparejamiento de un solo uso.

## Desarrollo / CI

```bash
cargo fmt --all -- --check          # formato
cargo clippy --workspace --all-targets -- -D warnings   # lint estricto
cargo test --workspace              # todos los tests (incluye E2E mTLS)
cargo build --release               # binarios en target/release/{vaultd,vaultctl,vault-gui}
```

GitHub Actions (`.github/workflows/ci.yml`) ejecuta exactamente eso en
`ubuntu-latest` y publica los binarios como artefacto.
