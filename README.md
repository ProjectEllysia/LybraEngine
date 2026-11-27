# LybraEngine

Motor de detección de vulnerabilidades de red. Descubre qué escucha en un
objetivo, identifica cada servicio y su versión, confirma vulnerabilidades con
checks activos y cruza lo encontrado con NVD, CISA KEV y EPSS.

Nació dentro de [EllysiaServer](https://github.com/ProjectEllysia/EllysiaServer)
y se separó para tener entidad propia: un servicio de Linux que cualquier
aplicación puede integrar.

## Estado

Funciona como servicio de Linux (`lybrad`) con su línea de órdenes (`lybra`) y
su base de conocimiento propia. Las aplicaciones lo integran con el cliente de
Python [`lybra-client`](client/), un paquete aparte con licencia Apache-2.0 y
sin dependencias.

| Subpaquete | Módulos y qué hacen |
|---|---|
| `core/` | El motor: `engine` convierte servicios en hallazgos, incluidas las CVE por versión; `scanner` orquesta un escaneo (plazo, cancelación, permisos y fases en orden) y devuelve lo que vio sin guardar nada; `planner`; `vulndata` (comparación de versiones y CPE, y lectura de los feeds de NVD, KEV, EPSS y OVAL); `_shared` (utilidades comunes y la ruta de `feeds/`). |
| `net/` | `transport` (barrido de puertos TCP concurrente y sin privilegios) y `udp_payloads`. |
| `fingerprinting/` | Un analizador por protocolo (HTTP, TLS, SSH, SMB, LDAP, bases de datos…), calibrado contra Nmap. |
| `checks/` | `framework` (checks activos declarativos que confirman una vulnerabilidad en vez de inferirla), `script_checks` y `credentials`. |
| `web/` | `crawler`, `api_surface` y `virtual_hosts`: superficie web de un servicio. |
| `analysis/` | `correlation` (deduplicación y puntuación contextual), `applicability`, `backports`, `distro`, `end_of_life`, `compliance`, `lateral` y `grouping`. |
| `recon/` | `osint`, `dns_hygiene` y `cloud` (inteligencia pasiva de un dominio, su higiene DNS y la exposición cloud) y `osint_network` (lo que toca la red en esas operaciones: fuentes de terceros con su caché, DNS y las sondas cloud). |
| `kb/` | La capa superior: `store` (la base de conocimiento local en SQLite: CVE con sus reglas de aplicabilidad, KEV, EPSS y avisos de distribución), `sync` (sincronización con las fuentes públicas, fuente a fuente y con su estado) y `queries` (consultas desde fuera del escaneo y las fases de escaneo que usan la base). Usa `core`; `core` no la usa. |
| `reporting/` | `exporters` y `evidence`. |
| `ingest/` | `adapters` más `classifier`, `selector` y `translator`: entrada de datos de otras herramientas. |
| `app/` | El servicio `lybrad` y su CLI: `protocol` (formato de los mensajes), `service` (las operaciones), `daemon` (el socket) y `cli` (la línea de órdenes `lybra`). |
| `client/` | El cliente de Python, `lybra-client`: un paquete aparte que no depende del motor. |
| `feeds/` | Checks, firmas, alias de productos y catálogos de fin de vida. |

El contrato entre el servicio y sus clientes está en
[`docs/protocolo.md`](docs/protocolo.md).

## Uso

```bash
lybrad --kb ./kb.sqlite --socket ./lybra.sock        # el servicio
export LYBRA_SOCKET=./lybra.sock

lybra info
lybra scan 198.51.100.10 --profile fast              # espera y muestra los hallazgos
lybra scan 198.51.100.10 --no-wait                   # sólo encola
lybra result <scanId> --json
lybra analyze --cpe cpe:2.3:a:openssl:openssl --version 3.0.1
lybra kb status
lybra kb sync --source kev
lybra osint domain example.com                       # subdominios, servicios vistos, higiene DNS
lybra osint hostnames 198.51.100.10
lybra cloud probe --resource s3:mi-bucket --subdomain app.example.com
```

Por defecto el motor **rechaza objetivos en redes privadas**; para escanear la
propia red, `lybrad --allow-private-targets`. Con la base vacía, `lybrad`
sincroniza al arrancar (sin el histórico de NVD; ver más abajo) y después cada
24 horas. La configuración de ejemplo está en
[`packaging/lybrad.toml`](packaging/lybrad.toml).

### Como servicio de systemd

```bash
sudo useradd --system --home-dir /var/lib/lybra --shell /usr/sbin/nologin lybra
sudo pip install ./client .                           # instala lybrad y lybra
sudo install -Dm644 packaging/lybrad.service /etc/systemd/system/lybrad.service
sudo install -Dm644 packaging/lybrad.toml /etc/lybra/lybrad.toml
sudo systemctl enable --now lybrad
sudo usermod -aG lybra "$USER"                        # para usar el socket
```

### Con Docker

```bash
docker build -t lybra-engine .
docker run -d --name lybra -v lybra_kb:/var/lib/lybra -v lybra_run:/run/lybra lybra-engine
docker exec lybra lybra info
```

Otro contenedor usa el motor montando el volumen `lybra_run` y entrando en el
grupo del socket (`group_add: ["990"]` en compose).

## Base de conocimiento

La sincronización diaria sólo trae los últimos días de NVD. El primer llenado
(unas 350 000 CVE) se hace una vez, de una de dos formas:

- desde NVD, con `KnowledgeBaseSync.sync_nvd_backfill` (más de una hora sin
  clave de API de NVD);
- copiando la base de una instalación de EllysiaServer, en minutos:

  ```bash
  .venv/bin/pip install -e '.[ellysia-import]'
  PGPASSWORD=… .venv/bin/python scripts/import_ellysia_kb.py \
      --dsn postgresql://usuario@127.0.0.1:15432/Ellysia --output kb.sqlite
  ```

  El script sólo lee de PostgreSQL y al terminar comprueba que cada tabla
  tiene las mismas filas y que el motor responde igual en las dos bases.

## Desarrollo

```bash
python -m venv .venv
.venv/bin/pip install -e ./client -e '.[dev]'     # el motor depende del cliente: va primero

.venv/bin/pytest -n auto                  # suite rápida, con la red sellada
.venv/bin/pytest -m oracle tests/oracle   # bancos contra contenedores reales (necesita Docker)
.venv/bin/pytest client/tests             # el cliente, sin el motor
```

La suite no sale nunca de loopback: `tests/conftest.py` corta cualquier otra
conexión al instante, y el limitador de ritmo del motor no duerme.

## Licencia

El motor, [GPL-3.0](LICENSE). El cliente, [Apache-2.0](client/LICENSE): como
sólo habla con el motor por un socket, una aplicación que lo use no queda sujeta
a la GPL.
