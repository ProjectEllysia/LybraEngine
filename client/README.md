# lybra-client

Cliente de Python del motor de escaneo [Lybra](https://github.com/ProjectEllysia/LybraEngine).
Habla con el servicio `lybrad` por su socket Unix y sólo usa la biblioteca
estándar.

## Instalación

```bash
pip install "lybra-client @ git+https://github.com/ProjectEllysia/LybraEngine@client-v0.2.1#subdirectory=client"
```

Hace falta pertenecer al grupo del socket (`lybra`) o, en contenedores, montar
el volumen del socket y entrar en su grupo.

## Uso

```python
from lybra_client import LybraClient, LybraError

client = LybraClient()          # LYBRA_SOCKET o /run/lybra/lybra.sock

# Un escaneo de red: encolar, seguir el progreso y recoger el resultado.
result = client.scan("198.51.100.10", profile="fast", on_progress=print)
for finding in result["findings"]:
    print(finding["title"], finding.get("cveIds"))

# Llenado histórico de la base de conocimiento (backfill de NVD con progreso)
backfill_res = client.kb_backfill(since="2020-01-01", on_progress=print)
print("CVEs importadas:", backfill_res["cves"])

# Software instalado, sin tocar la red: un CPE (o un nombre) y su versión.
analysis = client.analyze([
    {"cpe": "cpe:2.3:a:openssl:openssl", "version": "3.0.1", "origin": "inventory"},
])

# Inteligencia pasiva y exposición cloud (síncronas, con plazo; ver el protocolo §3.5).
client.osint_domain("example.com", dkim_selectors=["selector1"])
client.osint_hostnames("93.184.216.34")
client.cloud_probe(["s3:mi-bucket"], ["app.example.com"])

# La base de conocimiento.
client.kb_cve("CVE-2024-6387")
client.kb_version("nginx", "1.18.0")

try:
    client.scan_start("10.0.0.5")
except LybraError as error:
    print(error.code)           # target_not_allowed
```

Los resultados son los del protocolo tal cual, en diccionarios con claves en
camelCase; el contrato completo está en
[`docs/protocolo.md`](https://github.com/ProjectEllysia/LybraEngine/blob/main/docs/protocolo.md).

| Excepción | Cuándo |
|---|---|
| `LybraError` | El motor contestó con un error; `code` dice cuál (`invalid_params`, `target_not_allowed`, `not_found`, `busy`…). |
| `LybraConnectionError` | No se pudo hablar con `lybrad`: el socket no existe, no hay permiso o se cortó la conexión. Es un `ConnectionError`. |

## Licencia

[Apache-2.0](LICENSE). El motor es GPL-3.0; como el cliente sólo habla con él
por un socket, una aplicación que use este cliente no queda sujeta a la GPL.
