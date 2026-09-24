# ITConstructedDoor.md — DOCUMENTO INTERNO DE ADMINISTRACIÓN DE SISTEMAS

> **RESTRICCIÓN DE CIRCULACIÓN:** Este documento es de circulación exclusiva
> para el administrador de sistemas de TI de la institución. No debe copiarse,
> distribuirse ni citarse en ningún otro material del proyecto. Ninguna otra
> pieza de documentación, código fuente, pantalla del software o material de
> capacitación debe mencionar o revelar la existencia, el nombre, la ubicación
> o el funcionamiento de este protocolo.

---

## 1. Propósito

Mecanismo de acceso de emergencia ("Break-Glass") que otorga a la
administración de sistemas un control operativo total del ecosistema
(usuarios, base de datos, configuración y almacenamiento) sin comprometer las
certificaciones de seguridad del resto del sistema. No existen accesos
ocultos en la aplicación: el modo es una herramienta de administración
explicita, separada del producto de usuario final.

## 2. Superficie técnica

| Componente | Ubicación | Función |
|---|---|---|
| Consola de administración | `bin/vault-it` (en `/opt/intranet-suite/bin/`) | Única interfaz del modo |
| Estado del modo | `<datos>/door/door.state` | Usuario IT + hash Argon2id de la contraseña |
| Clave privada IT | `<datos>/door/door.key.pem` | Factor criptográfico de apertura + lectura de reportes |
| Clave pública | `<datos>/door/it.pub` y `<datos>/config/it.pub` | La app la usa SOLO para cifrar reportes de fallo |
| Sesión transitoria | `<datos>/door/session` | Marca de caducidad (15 min) de la sesión de administración |
| Identidad de la instalación | `<datos>/app.key.pem` (0600) y `<datos>/app.pub` | Firmar cada reporte para que no se pueda suplantar su origen |

Directorio de datos por defecto: `~/.boveda/data/` (despliegue de una sola
máquina). En despliegue portable: `/opt/intranet-suite/data/`.

## 3. Protocolo de activación (MFA, dos factores)

`vault-it door setup` (una sola vez):
1. Define el usuario IT y la contraseña (mínimo 8 caracteres). La contraseña
   se almacena solo como hash Argon2id.
2. Genera el par de claves ECC (P-256). La clave privada queda en
   `door.key.pem` (0600). **Cópiala a un medio fuera de la máquina y bórrala
   de aquí si la política lo exige** — sin ella no hay apertura ni lectura de
   reportes.

`vault-it door open` (cada vez que se necesite):
1. Factor 1 — conocimiento: usuario + contraseña IT (verificadas contra el
   hash Argon2id).
2. Factor 2 — posesión: contenido íntegro de la clave privada PEM, validado
   contra la clave pública registrada.
3. Si ambos factores pasan, se escribe una sesión con caducidad de 15
   minutos. Las operaciones administrativas requieren esa sesión activa.

`vault-it door revoke` cierra la sesión inmediatamente.
`vault-it door status` consulta el estado.

## 4. Capacidades con la sesión abierta

- `users list | add | disable | enable | reset-pin` — CRUD de usuarios y
  roles de la plataforma (Docente, Administrativo, Coordinación, Director).
- `trash list | purge <vault_id>` — borrado definitivo con sobrescritura
  física del archivo (único camino; los roles estándar solo tienen
  papelera/restauración).
- `storage stats | clean-staging` — métricas internas y limpieza de
  temporales.
- `report list | read <archivo.crpt>` — descifrado de los reportes de fallo
  con la clave privada de IT (ver §5). La lectura informa además de si la
  firma de la instalación es válida.

Mientras el servicio esté en marcha, la base de datos tiene un **escritor
único**: las operaciones de modificación (usuarios y purga) se niegan con un
mensaje explícito. Detenga el servicio (Ctrl-C) para administrar; la
consulta (`users list`, `trash list`, `storage stats`, `report …`) funciona
sin interrupciones. Del mismo modo, la sesión de administración es visible
para la aplicación gráfica, que entonces solo permite consultar.

## 5. Reportes de fallo cifrados (subsistema de diagnóstico)

- Ante cualquier pánico o error lógico registrado, la aplicación genera un
  reporte de estado con volcado parcial (backtrace truncado, hilo, versión,
  plataforma) y lo cifra **localmente** con ECIES sobre P-256 (clave efímera
  por reporte + derivación SHA-256 + ChaCha20-Poly1305 autenticado).
- Los archivos `.crpt` en `<datos>/crash/` son opacos si se interceptan: no
  contienen ningún byte legible del reporte.
- Cada reporte va además **firmado** con la clave de la instalación
  (`<datos>/app.key.pem`); su pública (`app.pub`) permite comprobar la
  procedencia. Cualquiera puede cifrar contra la clave pública de IT, así que
  la firma es lo que distingue un reporte legítimo de un archivo plantado.
- Solo `vault-it report read <archivo.crpt>` puede descifrarlos, y exige la
  clave privada de IT (§3). Ni el Director ni ningún rol estándar dispone de
  camino de lectura.

## 6. Trazabilidad aislada

- Las operaciones ejecutadas bajo este modo **no** se escriben en la cadena
  de auditoría institucional: esa cadena es visible para Coordinación y
  Dirección y no debe exponer métricas ni configuraciones internas del
  servidor.
- La trazabilidad del modo IT reside exclusivamente en este archivo de
  documentación y en el control físico de la clave privada por parte del
  administrador de sistemas.
- La sesión caduca sola a los 15 minutos y `door revoke` la corta de
  inmediato; el estado del modo (`door status`) permite verificar en todo
  momento que no quede abierta.

## 7. Despliegue portable (una máquina, sin servidor externo)

```
/opt/intranet-suite/
├── bin/        vault-gui · vaultd · vaultctl · vault-it
├── lib/        (nativo: nada que instalar en el sistema anfitrión)
├── config/     it.pub · vaultd.toml (opcional)
└── data/       keyfile, BD cifrada, door/, crash/   (o ~/.boveda/)
```

- Los binarios son autocontenidos (Rust puro, sin dependencias dinámicas del
  sistema más allá de OpenGL/X11/Wayland del escritorio).
- `config/it.pub` es la copia de la clave pública que la app gráfica usa
  para cifrar reportes; puede regenerarse con `vault-it door setup`.
- La jerarquía completa se traslada copiando el directorio; no hay registro
  ni servicios del sistema que modificar.

## 8. Revocación y compromiso

- **Sospecha de compromiso de la clave privada:** ejecutar `vault-it door
  setup` tras eliminar el directorio `door/` (rota el par de claves; los
  reportes anteriores quedan ilegibles por diseño) y **regenerar también
  `<datos>/config/it.pub`**: la aplicación lee esa copia para cifrar, y si se
  queda la clave antigua los reportes nuevos ya no se podrán descifrar.
- **Rotación completa:** además de `door/` y `config/it.pub`, borre
  `<datos>/app.key.pem` + `<datos>/app.pub` si quiere invalidar la firma de la
  instalación (los reportes antiguos seguirán descifrándose, pero dejarán de
  verificar como propios).
- **Salida del personal de TI:** `door revoke` + borrado del `door/` +
  rotación (§7). Los usuarios estándar nunca tuvieron acceso al modo.
- **Si el servicio está en marcha:** deténgalo antes de las operaciones de
  modificación; el escritor único de la base de datos impide operar a la vez
  desde el servicio y desde la consola.
