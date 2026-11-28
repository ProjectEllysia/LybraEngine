# Configuración Exhaustiva de LybraEngine (`lybrad`)

Esta referencia detalla todas las opciones de configuración, variables de entorno y perfiles de rendimiento para ajustar **LybraEngine** y su demonio `lybrad`.

---

## 1. Orden de Precedencia

Los parámetros de configuración de `lybrad` se resuelven aplicando la siguiente jerarquía de precedencia (de mayor a menor prioridad):

1. **Flags de Línea de Órdenes (CLI)**: Argumentos explícitos al invocar `lybra` o `lybrad` (p. ej., `--allow-private-targets`, `--kb ./kb.sqlite`).
2. **Variables de Entorno (`LYBRA_*`)**: Opciones inyectadas en el entorno del proceso (p. ej., `LYBRA_SOCKET`, `LYBRA_NVD_API_KEY`).
3. **Fichero de Configuración (TOML)**: Ubicado por defecto en `/etc/lybra/lybrad.toml` o especificado mediante `--config <ruta>`.
4. **Valores por Defecto del Motor**: Definidos internamente en `src/lybra/core/scanner.py` y `src/lybra/app/service.py`.

---

## 2. Referencia de Variables de Entorno

| Variable | Tipo | Descripción |
|---|---|---|
| `LYBRA_SOCKET` | Cadena (Ruta) | Ruta absoluta o relativa al socket Unix de comunicación (por defecto `/run/lybra/lybra.sock`). |
| `LYBRA_KB` | Cadena (Ruta) | Ruta al fichero de base de conocimiento SQLite (por defecto `/var/lib/lybra/kb.sqlite`). |
| `LYBRA_NVD_API_KEY` | Cadena | Clave de API de NVD (National Vulnerability Database). **Muy recomendada**: reduce el tiempo de sincronización de páginas de 6s a 0.65s. |
| `LYBRA_SHODAN_API_KEY` | Cadena | Clave de API de Shodan para el enriquecimiento pasivo y OSINT de red. |
| `LYBRA_CENSYS_API_KEY` | Cadena | Clave de Censys con formato estricto `<API ID>:<secreto>`. |
| `LYBRA_SECURITYTRAILS_API_KEY` | Cadena | Clave de API de SecurityTrails para recolección pasiva de subdominios. |
| `NO_COLOR` | Bandera | Si está presente, desactiva la salida colorizada en la CLI. |
| `FORCE_COLOR` | Bandera | Fuerza la salida colorizada incluso si la salida no es un TTY. |

---

## 3. Secciones del Fichero TOML (`lybrad.toml`)

### `[daemon]`
Controla el comportamiento general del demonio:
- `socket`: Ruta del socket Unix (por defecto `/run/lybra/lybra.sock`).
- `socket_group`: Grupo del sistema con permisos de acceso al socket (por defecto `lybra`).
- `max_concurrent_scans`: Número máximo de escaneos simultáneos en ejecución (por defecto `4`).
- `max_queued_scans`: Capacidad de la cola de espera para escaneos concurrentes (por defecto `32`).
- `allow_private_targets`: Booleano (`true`/`false`). Permite escanear rangos privados (`10.x`, `192.168.x`, `172.16/12`, loopback). Por defecto `false` como medida anti-SSRF.

### `[kb]`
Gestiona la base de conocimiento local:
- `path`: Ruta al archivo SQLite de la base de conocimiento (por defecto `/var/lib/lybra/kb.sqlite`).
- `sync_interval_hours`: Frecuencia horaria de sincronización automática de fuentes (por defecto `24`; `0` la desactiva).
- `nvd_window_days`: Ventana temporal en días consultada en las sincronizaciones rutinarias (por defecto `8`).

### `[osint]`
Controla la inteligencia pasiva:
- `ttl_hours`: Tiempo de vida de la caché para consultas de terceros (por defecto `24`).
- `request_timeout_seconds`: Timeout de peticiones HTTP externas (por defecto `30`).
- `enabled_sources`: Lista de fuentes habilitadas (por defecto `["crtsh", "shodan", "censys", "securitytrails"]`).

---

## 4. Tabla Completa de Parámetros de Escaneo (`ScanSettings`)

Los siguientes **30 parámetros** corresponden a la clase `ScanSettings` en `src/lybra/core/scanner.py` (líneas 169-198) y se pueden sobrescribir dentro de la sección `[scan]` en `lybrad.toml`:

| Parámetro | Tipo | Valor por Defecto | Descripción Operativa |
|---|---|---|---|
| `tcp_concurrency` | Entero | `200` | Número de sockets TCP concurrentes durante el barrido de puertos. |
| `tcp_timeout` | Flotante | `2.0` | Timeout en segundos para establecer conexiones TCP de sondeo. |
| `udp_timeout` | Flotante | `2.0` | Timeout en segundos para esperar respuestas de paquetes UDP. |
| `udp_retries` | Entero | `1` | Número de reintentos para sondas UDP sin respuesta. |
| `udp_budget_seconds` | Flotante | `20.0` | Presupuesto máximo de tiempo dedicado al análisis de puertos UDP. |
| `rate_limit_interval` | Flotante | `0.2` | Intervalo base en segundos entre sondeos consecutivos (ritmo de envío). |
| `rate_limit_max_backoff_factor` | Flotante | `8.0` | Factor máximo de *backoff* exponencial ante congestión o limitación de tasa. |
| `host_pool_size` | Entero | `8` | Tamaño del pool para procesamiento multihost. |
| `http_timeout` | Flotante | `8.0` | Timeout para solicitudes HTTP del crawler y comprobaciones web. |
| `http_max_body_bytes` | Entero | `131072` (128 KiB) | Tamaño máximo en bytes procesado de cuerpos de respuestas HTTP. |
| `http_user_agent` | Cadena | `"Lybra/1.0"` | Cabecera User-Agent utilizada en los sondeos y crawler web. |
| `network_timeout` | Flotante | `5.0` | Timeout general de operaciones de red a nivel de socket. |
| `banner_timeout` | Flotante | `2.0` | Tiempo máximo de espera para la recepción pasiva de banners iniciales. |
| `max_blind_probes` | Entero | `2` | Número máximo de sondas ciegas enviadas ante servicios no reconocidos. |
| `max_payload_expansions` | Entero | `25` | Límite de expansiones de payloads en checks activos complejos. |
| `implausible_open_ratio` | Flotante | `0.5` | Ratio máximo de puertos abiertos para considerar un barrido verosímil. |
| `implausible_min_probed` | Entero | `100` | Mínimo de puertos probados antes de evaluar la implausibilidad del barrido. |
| `blocking_recheck_ports` | Entero | `3` | Número de puertos reexaminados para detectar bloqueos de cortafuegos a mitad de escaneo. |
| `max_virtual_hosts` | Entero | `10` | Límite de *virtual hosts* descubiertos analizados por certificado TLS/PTR. |
| `capture_evidence` | Booleano | `True` | Si se adjunta evidencia técnica en bruto (fragmentos de banner, payloads) en los hallazgos. |
| `crawler_max_pages` | Entero | `50` | Número máximo de páginas rastreadas por servicio web. |
| `crawler_max_depth` | Entero | `3` | Profundidad máxima de enlaces seguidos por el crawler web. |
| `crawler_time_budget_seconds` | Flotante | `20.0` | Presupuesto temporal dedicado al crawler por servicio web. |
| `crawler_max_scan_directories` | Entero | `10` | Directorios descubiertos sobre los que se ejecutan los checks de rutas sensibles. |
| `api_max_endpoints` | Entero | `25` | Límite de endpoints analizados derivados de especificaciones OpenAPI/Swagger. |
| `api_max_specification_bytes` | Entero | `1048576` (1 MiB) | Tamaño máximo aceptado para ficheros de especificación de API. |
| `credential_max_attempts` | Entero | `3` | Intentos máximos por cuenta en el motor de autenticación por defecto (`--aggressive`). |
| `reachability_check` | Booleano | `True` | Si se realiza verificación previa de alcanzabilidad del host objetivo. |
| `reachability_port` | Entero | `80` | Puerto empleado para la comprobación previa de alcanzabilidad. |
| `reachability_timeout` | Flotante | `3.0` | Timeout en segundos para la comprobación de alcanzabilidad. |

---

## 5. Perfiles de Configuración Listos para Copiar (`lybrad.toml`)

### Perfil A: Auditoría Sigilosa y Enlaces Lentos (Low-and-Slow)
Ideal para entornos con restricciones estrictas de caudal, IDS sensibles o enlaces de red lentos:
```toml
[daemon]
socket = "/run/lybra/lybra.sock"
max_concurrent_scans = 1
max_queued_scans = 8
allow_private_targets = false

[kb]
path = "/var/lib/lybra/kb.sqlite"
sync_interval_hours = 24

[scan]
tcp_concurrency = 30
tcp_timeout = 5.0
rate_limit_interval = 1.0
rate_limit_max_backoff_factor = 16.0
http_timeout = 15.0
crawler_max_pages = 10
crawler_time_budget_seconds = 40.0
reachability_timeout = 5.0
```

### Perfil B: Auditoría Interna LAN / Laboratorios HTB (Rápido y Permisivo)
Diseñado para redes internas de confianza o laboratorios de pentesting donde se requiere velocidad y cobertura de rangos privados:
```toml
[daemon]
socket = "/run/lybra/lybra.sock"
max_concurrent_scans = 8
max_queued_scans = 64
allow_private_targets = true

[kb]
path = "/var/lib/lybra/kb.sqlite"
sync_interval_hours = 12

[scan]
tcp_concurrency = 500
tcp_timeout = 1.0
rate_limit_interval = 0.05
http_timeout = 5.0
crawler_max_pages = 100
max_virtual_hosts = 20
reachability_check = false
```
