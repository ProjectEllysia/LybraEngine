# LybraEngine

Motor de detección de vulnerabilidades de red y auditoría de seguridad. Descubre qué escucha en un objetivo, identifica cada servicio y su versión con precisión, confirma vulnerabilidades con checks activos y cruza los hallazgos con NVD, CISA KEV, EPSS y avisos OVAL/CSAF de distribuciones.

Nació dentro de [EllysiaServer](https://github.com/ProjectEllysia/EllysiaServer) y se separó para tener entidad propia: un servicio de Linux (`lybrad`) que cualquier aplicación puede integrar de forma segura mediante un socket Unix.

---

## 🚀 ¿Qué diferencia a LybraEngine?

- **Sin privilegios root**: Realiza un barrido de puertos TCP mediante conexiones `connect()` concurrentes no privilegiadas, apto para cualquier operador y distribución moderna.
- **Fingerprinting propio de 26 protocolos** (19 TCP y 7 UDP) calibrado rigurosamente contra Nmap para extraer versiones exactas, metadatos TLS, huellas HASSH y parámetros binarios.
- **146 checks activos** con confirmadores y refutadores reales (como SSH Terrapin) para confirmar vulnerabilidades en lugar de basarse en meras conjeturas de banner.
- **Cruce masivo de inteligencia de amenazas**: NVD, CISA KEV, EPSS y avisos de seguridad OVAL (Debian, Ubuntu) y CSAF (Red Hat), con **detección de *backports*** para descartar falsos positivos cuando una distribución parchea un paquete sin cambiar su versión principal.
- **Superficie web y de APIs**: Crawler HTTP de solo lectura, análisis de especificaciones OpenAPI/Swagger y descubrimiento automatizado de *virtual hosts* por SAN TLS y registros PTR.
- **Reconocimiento pasivo OSINT / DNS / Cloud**: Descubrimiento de subdominios, higiene DNS (DKIM, SPF, DMARC) y sondeo de exposición Cloud (AWS S3, Google Cloud Storage, Azure Blob, Firebase).
- **Exportadores estándar nativos**: Generación de reportes normalizados en **SARIF 2.1.0**, **STIX 2.1** y **OCSF**.

---

## ⚡ Instalación y Quickstart (60 segundos)

Para evitar el error PEP 668 (`externally-managed-environment`) en distribuciones actuales (Kali Linux, Debian 12+, Ubuntu 24.04+, Arch), puedes utilizar el instalador automatizado o realizarlo de forma manual.

### Opción A: Instalador automatizado (Recomendado)
```bash
./scripts/install.sh --venv
# O si prefieres dejar los comandos 'lybra' y 'lybrad' accesibles globalmente en ~/.local/bin:
./scripts/install.sh --venv --link-bin
```

### Opción B: Instalación manual
```bash
python3 -m venv .venv
.venv/bin/pip install ./client .
```

### Primer arranque local para pentesting
Por defecto, como medida de seguridad anti-SSRF, `lybrad` bloquea objetivos en redes privadas. Para laboratorios de pruebas (como Hack The Box), VPNs o redes internas (`10.x`, `192.168.x`), activa `--allow-private-targets`:

```bash
# Terminal 1: Iniciar el demonio
.venv/bin/lybrad --kb ./kb.sqlite --socket ./lybra.sock --allow-private-targets

# Terminal 2: Interactuar con la CLI de lybra
export LYBRA_SOCKET=./lybra.sock
.venv/bin/lybra info
.venv/bin/lybra scan 10.10.11.23 --profile standard
```

---

## 📚 Base de Conocimiento y Llenado (`lybra kb backfill`)

Al arrancar por primera vez, `lybrad` sincroniza automáticamente los datos recientes (KEV, EPSS, OVAL y los últimos 8 días de NVD). Para realizar el **llenado histórico completo de NVD (~350 000 CVE)**, tienes dos métodos:

### 1. Desde NVD con la CLI (Recomendado)
Es altamente recomendable configurar una clave de API gratuita de NVD para acelerar el proceso (pasa de ~6s a ~0.65s por página):
```bash
export LYBRA_NVD_API_KEY="tu-clave-nvd"
.venv/bin/lybra kb backfill --kb ./kb.sqlite --since 2020-01-01
```
También se puede invocar contra un demonio en marcha:
```bash
.venv/bin/lybra kb backfill --since 2015-01-01
```

### 2. Importación desde EllysiaServer (En pocos minutos)
Si dispones de una base PostgreSQL de EllysiaServer, puedes poblar la base SQLite local ejecutando:
```bash
.venv/bin/pip install -e '.[ellysia-import]'
PGPASSWORD=secreto .venv/bin/python scripts/import_ellysia_kb.py \
    --dsn postgresql://usuario@127.0.0.1:15432/Ellysia --output kb.sqlite
```

---

## 🎛️ Perfiles de Escaneo y Modo `--aggressive`

| Perfil | Puertos TCP | Puertos UDP | Fases y Comportamiento |
|---|---|---|---|
| **`fast`** | 100 puertos comunes | 7 UDP | Barrido rápido, fingerprinting y cruce con KB. Sin crawler, sin checks activos e ignora `--aggressive`. |
| **`standard`** (Por defecto) | 74 puertos curados | 7 UDP | Barrido estándar y **todas** las fases activas (crawler, checks, OpenAPI, virtual hosts). |
| **`thorough`** | 65 535 puertos | 7 UDP | Barrido exhaustivo de todo el rango TCP, sin reutilizar caché del planificador. |

### ¿Qué añade el modo `--aggressive`?
Al activar `--aggressive`, el motor habilita comprobaciones avanzadas de protocolo e interacción con autenticaciones:
- Checks con sesión/RPC como `ssh-none-authentication-accepted` y `windows-shares-unauthenticated`.
- Análisis de superficie RPC en Domain Controllers.
- Pruebas de *Mass Assignment* (`PUT`/`PATCH`) en endpoints OpenAPI.
- Ataque de credenciales HTTP Basic por defecto (con ritmo atenuado a un máximo de 3 intentos por usuario).

---

## 🛠️ Flujos Habituales de Pentesting (Ejemplos CLI)

```bash
# Escaneo de red asíncrono
.venv/bin/lybra scan 192.168.1.50 --profile standard --timeout 120 --no-wait
.venv/bin/lybra status <scanId>
.venv/bin/lybra result <scanId> --json

# Reconocimiento pasivo de dominios, IPs y nube
.venv/bin/lybra osint domain example.com
.venv/bin/lybra osint hostnames 192.168.1.50
.venv/bin/lybra cloud probe --resource s3:mi-bucket --subdomain app.example.com

# Auditoría estática de software / CPE sin tocar la red
.venv/bin/lybra analyze --cpe cpe:2.3:a:openssl:openssl --version 3.0.1
.venv/bin/lybra kb cve CVE-2024-6387
.venv/bin/lybra kb version nginx 1.18.0
.venv/bin/lybra kb status
```

---

## 🚢 Despliegue en Producción

### Como servicio de systemd (Respetando PEP 668)
El instalador automatizado soporta la configuración completa e idempotente del servicio systemd (respetando `/etc/lybra/lybrad.toml` existente, admitiendo `--dry-run` para auditoría previa y soportando actualización tras `git pull`):

```bash
sudo ./scripts/install.sh --systemd
# O si el servicio debe auditar redes internas / laboratorios:
sudo ./scripts/install.sh --systemd --allow-private-targets
```

Para desinstalar o depurar (añadiendo `--purge` para borrar también la base de conocimiento):
```bash
sudo ./scripts/install.sh --uninstall --systemd
# sudo ./scripts/install.sh --uninstall --systemd --purge
```

<details>
<summary>Pasos manuales equivalentes (systemd)</summary>

```bash
sudo useradd --system --home-dir /var/lib/lybra --shell /usr/sbin/nologin lybra
sudo python3 -m venv /opt/lybra/venv
sudo /opt/lybra/venv/bin/pip install ./client .
sudo ln -sf /opt/lybra/venv/bin/lybrad /usr/bin/lybrad
sudo ln -sf /opt/lybra/venv/bin/lybra /usr/local/bin/lybra
sudo install -Dm644 packaging/lybrad.service /etc/systemd/system/lybrad.service
sudo install -Dm644 packaging/lybrad.toml /etc/lybra/lybrad.toml
sudo systemctl enable --now lybrad
sudo usermod -aG lybra "$USER"    # recargar sesión o 'newgrp lybra' para usar el socket
```
</details>

### Con Docker
Puedes desplegar fácilmente usando el nuevo `docker-compose.yml` de la raíz o mediante el instalador y comandos directos:

```bash
# Con docker-compose.yml en la raíz
docker compose up -d

# O usando el instalador con wrapper local `--link-bin` (evita tener que escribir docker exec lybra ...)
./scripts/install.sh --docker --link-bin

# Comandos directos de Docker
docker build -t lybra-engine .
docker run -d --name lybra -v lybra_kb:/var/lib/lybra -v lybra_run:/run/lybra lybra-engine
docker exec lybra lybra info
```

---

## 🗂️ Arquitectura por Subpaquetes

| Subpaquete | Propósito Principal |
|---|---|
| `core/` | Motor central (`engine`, `scanner` asíncrono, `planner`, `vulndata` para NVD/KEV/EPSS/OVAL/CSAF). |
| `net/` | Transporte TCP concurrente sin privilegios (`transport`) y payloads UDP. |
| `fingerprinting/` | Analizadores específicos para los 26 protocolos calibrados contra Nmap. |
| `checks/` | Framework de checks activos, scripts y credenciales. |
| `web/` | Crawler HTTP, análisis de APIs OpenAPI y descubrimiento de *virtual hosts*. |
| `analysis/` | Correlación, aplicabilidad, *backports*, fin de vida, cumplimiento normativo y movimiento lateral. |
| `recon/` | Inteligencia pasiva (OSINT, DNS, Cloud) y red de fuentes externas. |
| `kb/` | Almacenamiento local SQLite (`store`), sincronización (`sync`) y consultas (`queries`). |
| `reporting/` | Exportadores normalizados (SARIF, STIX, OCSF) y gestión de evidencias. |
| `ingest/` | Adaptadores de entrada para ingesta desde otras herramientas. |
| `app/` | Servicio demonio `lybrad`, protocolo JSON sobre socket y CLI `lybra`. |
| `client/` | Cliente Python independiente (`lybra-client`). |
| `feeds/` | Checks, firmas, alias de productos y catálogos estáticos. |

---

## 📖 Documentación Detallada

- [`docs/guia-pentesting.md`](docs/guia-pentesting.md) — Guía operativa completa de fases, protocolos y recetas en Python.
- [`docs/configuracion.md`](docs/configuracion.md) — Referencia exhaustiva de variables de entorno, perfiles y los 30 parámetros de `ScanSettings`.
- [`docs/protocolo.md`](docs/protocolo.md) — Contrato técnico v1 del socket Unix y operaciones del demonio.

---

## 🧪 Desarrollo y Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -e ./client -e '.[dev]'

.venv/bin/pytest -n auto                  # Suite rápida (red sellada en loopback)
.venv/bin/pytest -m oracle tests/oracle   # Pruebas contra contenedores reales (requiere Docker)
.venv/bin/pytest client/tests             # Tests del cliente Python
```

---

## 📜 Licencia

- **Motor (`lybrad` y librerías internas)**: [GPL-3.0](LICENSE).
- **Cliente (`client/`)**: [Apache-2.0](client/LICENSE). Dado que el cliente se comunica exclusivamente a través de un socket Unix, las aplicaciones que lo integran no quedan sujetas a la GPL.
