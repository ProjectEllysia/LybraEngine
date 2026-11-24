# LybraEngine

Motor de detección de vulnerabilidades de red. Descubre qué escucha en un
objetivo, identifica cada servicio y su versión, confirma vulnerabilidades con
checks activos y cruza lo encontrado con NVD, CISA KEV y EPSS.

Nació dentro de [EllysiaServer](https://github.com/ProjectEllysia/EllysiaServer)
y se separó para tener entidad propia: un servicio de Linux que cualquier
aplicación puede integrar.

## Estado

Funciona como servicio de Linux (`lybrad`) con su línea de órdenes (`lybra`) y
su base de conocimiento propia. Falta publicar el cliente de Python como
paquete aparte (`lybra-client`); hoy vive en `lybra.client`.

| Módulo | Qué hace |
|---|---|
| `transport` | Barrido de puertos TCP concurrente y sin privilegios. |
| `fingerprinting/` | Un analizador por protocolo (HTTP, TLS, SSH, SMB, LDAP, bases de datos…), calibrado contra Nmap. |
| `engine` | Convierte servicios en hallazgos, incluidas las CVE por versión. |
| `checks`, `script_checks` | Checks activos declarativos que confirman una vulnerabilidad en vez de inferirla. |
| `kb` | Comparación de versiones y CPE, y lectura de los feeds de NVD, KEV, EPSS y OVAL. |
| `knowledge_base` | La base de conocimiento local en SQLite: CVE con sus reglas de aplicabilidad, KEV, EPSS y avisos de distribución. |
| `kb_sync` | La sincronización con las fuentes públicas, fuente a fuente y con su estado. |
| `kb_queries` | Las consultas desde fuera del escaneo (ficha de una CVE, ¿es vulnerable esta versión?, avisos recientes) y las fases de escaneo que usan la base. |
| `scanner` | La orquestación de un escaneo: plazo, cancelación, permisos y fases en orden. Devuelve lo que vio sin guardar nada. |
| `correlation` | Deduplicación y puntuación contextual. |
| `osint`, `dns_hygiene` | Inteligencia pasiva de un dominio. |
| `protocol`, `service`, `daemon` | El servicio `lybrad`: el formato de los mensajes, las operaciones y el socket. |
| `client`, `cli` | El cliente de Python y la línea de órdenes `lybra`. |
| `feeds/` | Checks, firmas, alias de productos y catálogos de fin de vida. |

Lo que falta, en orden:

1. El servicio `lybrad` y la CLI `lybra`, con su imagen de Docker.
2. La librería cliente `lybra-client`.

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

El contrato entre el servicio y sus clientes está en
[`docs/protocolo.md`](docs/protocolo.md).

## Desarrollo

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'

.venv/bin/pytest -n auto                  # suite rápida, con la red sellada
.venv/bin/pytest -m oracle tests/oracle   # bancos contra contenedores reales (necesita Docker)
```

La suite no sale nunca de loopback: `tests/conftest.py` corta cualquier otra
conexión al instante, y el limitador de ritmo del motor no duerme.

## Licencia

[GPL-3.0](LICENSE).
