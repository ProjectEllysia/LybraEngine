# LybraEngine

Motor de detección de vulnerabilidades de red. Descubre qué escucha en un
objetivo, identifica cada servicio y su versión, confirma vulnerabilidades con
checks activos y cruza lo encontrado con NVD, CISA KEV y EPSS.

Nació dentro de [EllysiaServer](https://github.com/ProjectEllysia/EllysiaServer)
y se separó para tener entidad propia: un servicio de Linux que cualquier
aplicación puede integrar.

## Estado

En construcción. Hoy el repositorio contiene el motor completo como librería:
cada capa de detección y el orquestador que las encadena en un escaneo.

| Módulo | Qué hace |
|---|---|
| `transport` | Barrido de puertos TCP concurrente y sin privilegios. |
| `fingerprinting/` | Un analizador por protocolo (HTTP, TLS, SSH, SMB, LDAP, bases de datos…), calibrado contra Nmap. |
| `engine` | Convierte servicios en hallazgos, incluidas las CVE por versión. |
| `checks`, `script_checks` | Checks activos declarativos que confirman una vulnerabilidad en vez de inferirla. |
| `kb` | Comparación de versiones y CPE, y lectura de los feeds de NVD, KEV, EPSS y OVAL. |
| `scanner` | La orquestación de un escaneo: plazo, cancelación, permisos y fases en orden. Devuelve lo que vio sin guardar nada. |
| `correlation` | Deduplicación y puntuación contextual. |
| `osint`, `dns_hygiene` | Inteligencia pasiva de un dominio. |
| `feeds/` | Checks, firmas, alias de productos y catálogos de fin de vida. |

Lo que falta, en orden:

1. La base de conocimiento propia (SQLite) y su sincronización. Hasta entonces,
   la detección por versión necesita que quien integra el motor le pase sus
   consultas (`ScanPhases.analyze`).
2. El servicio `lybrad` y la CLI `lybra`, con su imagen de Docker.
3. La librería cliente `lybra-client`.

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
