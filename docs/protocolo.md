# Protocolo de LybraEngine — v1

Este documento es el contrato entre el servicio `lybrad` y quien lo usa: la CLI
`lybra`, la librería `lybra-client` y, a través de ella, cualquier aplicación
(EllysiaServer es la primera). Lo que no esté aquí no es contrato.

El motor es **autónomo**: guarda su propia base de conocimiento de
vulnerabilidades (NVD, CISA KEV y EPSS) y no depende de ninguna aplicación. Lo
que **no** guarda es la historia de los activos: un escaneo devuelve los
hallazgos de ese escaneo, y seguir un hallazgo en el tiempo (si es nuevo, si
sigue abierto, si se corrigió) es trabajo de la aplicación que lo integra.

## 1. Transporte

- **Socket Unix de tipo stream.** Ruta por defecto: `/run/lybra/lybra.sock`;
  se cambia con la variable `LYBRA_SOCKET` en los dos extremos.
- **Permisos:** el socket se crea con modo `0660` y grupo `lybra`. Quien
  pertenece al grupo puede lanzar escaneos; nadie más llega al socket. No hay
  autenticación adicional: el control de acceso es el del sistema de ficheros.
- **Sin red a propósito.** El motor sólo escucha en local. Exponerlo a otra
  máquina es decisión del operador (un túnel SSH, un proxy) y queda fuera de
  este contrato.

## 2. Formato de los mensajes

Cada mensaje es **un objeto JSON en una sola línea**, en UTF-8, terminado en
`\n` (JSON delimitado por saltos de línea). Una línea no puede superar 16 MiB;
el servicio cierra la conexión ante una más larga.

### Petición

```json
{"v": 1, "id": "c-17", "op": "scan.start", "params": {"target": "203.0.113.10"}}
```

| Campo | Qué es |
|---|---|
| `v` | Versión mayor del protocolo. Hoy, `1`. |
| `id` | Identificador que elige el cliente; la respuesta lo devuelve tal cual para poder emparejarlas. Cadena de hasta 64 caracteres. |
| `op` | La operación (ver §3). |
| `params` | Sus parámetros. Puede omitirse si la operación no tiene. |

### Respuesta

```json
{"v": 1, "id": "c-17", "ok": true, "result": {"scanId": "…", "status": "queued"}}
{"v": 1, "id": "c-17", "ok": false, "error": {"code": "invalid_target", "message": "…"}}
```

Cada petición recibe **exactamente una** respuesta final. Una conexión puede
llevar varias peticiones seguidas; el servicio las contesta en orden.

### Eventos

Las operaciones de seguimiento (`scan.watch`) emiten, antes de su respuesta
final, cero o más eventos con el mismo `id`:

```json
{"v": 1, "id": "c-18", "event": "progress", "data": {"phase": "fingerprinting", "done": 12, "total": 40}}
```

Un mensaje con `event` nunca es la respuesta final; la respuesta final es el
primero con `ok`.

### Claves y valores

- Las claves van en **camelCase**, como en la API de EllysiaServer.
- Los instantes son cadenas ISO 8601 en UTC con sufijo `Z`.
- El cliente **ignora las claves que no conoce**. Añadir una clave a una
  respuesta no cambia la versión del protocolo; quitarla o cambiar su
  significado sí (pasa a `v: 2`).

### Códigos de error

| Código | Cuándo |
|---|---|
| `bad_request` | El mensaje no es JSON válido, o le falta `v`, `id` u `op`. |
| `unsupported_version` | `v` no es una versión que el servicio hable. |
| `unknown_op` | La operación no existe. |
| `invalid_params` | Faltan parámetros o tienen un valor no válido. |
| `invalid_target` | El objetivo no es una IP, un nombre o un rango válido. |
| `target_not_allowed` | El objetivo es una dirección privada y el servicio no las admite (ver §5). |
| `not_found` | El escaneo, la CVE o el producto pedido no existe. |
| `busy` | La cola de escaneos está llena; se puede reintentar. |
| `kb_unavailable` | La base de conocimiento aún no se ha sincronizado nunca. |
| `internal` | Error no previsto del servicio. El mensaje no expone detalles internos. |

## 3. Operaciones

### 3.1 Servicio

**`engine.info`** — sin parámetros. Devuelve las versiones del motor y del
protocolo, la versión de los feeds de checks y el estado de la base de
conocimiento:

```json
{"engineVersion": "0.1.0", "protocolVersions": [1], "checksFeedVersion": "…",
 "kb": {"feedVersion": "…", "lastSyncAt": "…Z", "cveCount": 351204}}
```

### 3.2 Escaneos de red

Un escaneo es asíncrono: se encola, corre en el servicio y su resultado se
consulta después. El servicio limita cuántos corren a la vez.

**`scan.start`**

| Parámetro | Tipo | Qué es |
|---|---|---|
| `target` | cadena | IP, nombre de host o rango CIDR. Obligatorio. |
| `profile` | `"fast"` \| `"full"` | Qué puertos se barren. Por defecto `"fast"`. |
| `ports` | lista de enteros | Puertos concretos; sustituye a `profile`. |
| `udp` | booleano | Si se barren también los servicios UDP conocidos. Por defecto `false`. |
| `activeChecks` | booleano | Si se ejecutan los checks activos que confirman vulnerabilidades. Por defecto `true`. |
| `deep` | booleano | Si se ejecutan los corroboradores profundos (credenciales por defecto, crawler). Por defecto `false`. |
| `timeoutSeconds` | número | Presupuesto de reloj del escaneo entero. Al agotarse, el resultado sale `partial`. |
| `knownServices` | lista de `Service` | Lo que la aplicación sabe del objetivo por escaneos anteriores. El planificador lo usa para decidir qué volver a probar; el motor no guarda nada de un escaneo a otro. |

Devuelve `{"scanId": "…", "status": "queued"}`.

**`scan.status`** `{scanId}` — devuelve `{"scanId", "status", "progress"}`.
Los estados son:

| Estado | Significado |
|---|---|
| `queued` | Esperando turno. |
| `running` | En curso; `progress` dice la fase y el avance. |
| `completed` | Terminó y el barrido fue completo. |
| `partial` | Terminó, pero sin barrer todo: se agotó el presupuesto, o el objetivo dejó de contestar a mitad. **Lo que no aparece en un resultado parcial no se ha comprobado**: la aplicación no debe dar por corregido un hallazgo que falte en él. |
| `failed` | No pudo hacerse; `error` dice por qué. |
| `cancelled` | Se canceló. |

**`scan.watch`** `{scanId}` — emite eventos `progress` hasta que el escaneo
termina, y responde con lo mismo que `scan.status` en su estado final.

**`scan.result`** `{scanId}` — devuelve el `ScanResult` (§4) de un escaneo
terminado. Los resultados se conservan 24 horas tras terminar.

**`scan.cancel`** `{scanId}` — cancela un escaneo en cola o en curso.

### 3.3 Análisis sin red: CPE y versión

**`analyze`** — devuelve los hallazgos de una lista de servicios **que el
llamante ya conoce**, sin tocar la red. Es la operación que usa la
integración con Hygeia: Hygeia lee el software instalado en un equipo
(producto, versión y, si lo tiene, CPE) y el motor lo cruza con su base de
conocimiento para decir qué CVE le afectan y cuáles están en KEV o tienen
exploit. Es síncrona: responde con los hallazgos directamente.

| Parámetro | Tipo | Qué es |
|---|---|---|
| `services` | lista de `Service` | Lo que hay que analizar. Para un paquete instalado basta `product` + `version`, o `cpe` + `version`, con `origin: "inventory"`. Obligatorio, con 1 a 5000 elementos. |

Un ejemplo con un CPE y su versión:

```json
{"v": 1, "id": "c-21", "op": "analyze", "params": {"services": [
  {"cpe": "cpe:2.3:a:openssl:openssl", "version": "3.0.1", "origin": "inventory"}
]}}
```

Devuelve `{"findings": [Finding, …], "kbFeedVersion": "…"}`.

Lo que el motor hace con cada servicio:

- Con `origin: "inventory"` la versión se trata como un **hecho** leído del
  equipo, no como una suposición sacada de un banner: el hallazgo nace
  `confirmed: true` y con la calidad de detección (`qod`) más alta.
- Las versiones de paquete de distribución (`1:9.6p1-3ubuntu13.5`) se
  comparan por su versión de origen y, cuando hay datos de la distribución,
  se descuentan los parches que ya trae.
- Si el producto no se puede resolver a un CPE conocido, el servicio no
  produce hallazgos de versión; aparece en `unresolved` (§4) para que la
  aplicación sepa qué no se ha podido analizar.

### 3.4 Base de conocimiento

| Operación | Parámetros | Devuelve |
|---|---|---|
| `kb.cve` | `cveId` | El detalle de una CVE: descripción, CVSS, EPSS, si está en KEV, madurez del exploit y los rangos de versiones afectados. `not_found` si no existe. |
| `kb.version` | `product`, `version` | Las CVE que afectan a esa versión de ese producto (la herramienta «¿Es vulnerable mi versión?»). |
| `kb.products` | `term`, `limit` (por defecto 20, máximo 100) | Productos conocidos cuyo nombre contiene `term`, como pares `vendor`/`product`. |
| `kb.resolve` | `names` (lista de cadenas) | Para cada nombre libre («Apache httpd», «nginx»), el par `vendor`/`product` al que corresponde, o `null`. |
| `kb.advisories` | `products` (lista de pares `vendor`/`product`), `since` (instante, opcional), `limit` | Las CVE publicadas o modificadas para esos productos, de la más reciente a la más antigua. |
| `kb.status` | — | Estado de cada fuente: última sincronización, filas, último error. |
| `kb.sync` | `source` (opcional: `nvd`, `kev`, `epss`, `oval`) | Lanza una sincronización en segundo plano y responde al instante. |

Ninguna consulta de la base busca por prefijo ni devuelve listas sin tope.

### 3.5 Inteligencia pasiva

**`osint.domain`** `{domain, sources}` — lo que Certificate Transparency y
las fuentes de terceros activadas saben de un dominio, **sin contactar con
ningún equipo del dominio**. Nunca envía a un tercero una dirección privada.

## 4. Tipos

### Service

Un servicio de red descubierto o un componente instalado: la unidad de
entrada del motor.

| Clave | Tipo | Qué es |
|---|---|---|
| `port` | entero o `null` | Puerto. `null` en un componente instalado, que no escucha en ninguno. |
| `protocol` | `"tcp"` \| `"udp"` \| `""` | Transporte. Vacío en un componente instalado. |
| `name` | cadena | Nombre del servicio (`"http"`, `"ssh"`). Puede ir vacío. |
| `product` | cadena | Producto (`"Apache httpd"`). Puede ir vacío. |
| `version` | cadena | Versión (`"2.4.49"`). Puede ir vacía. |
| `cpe` | cadena o `null` | CPE, en formato 2.2 o 2.3. |
| `origin` | `"network"` \| `"inventory"` | `network`: deducido de lo que el servicio enseña por la red, una suposición. `inventory`: leído en el propio equipo (gestor de paquetes), un hecho. Por defecto `network`. |

### Finding

Un hallazgo. Las claves siempre presentes:

| Clave | Tipo | Qué es |
|---|---|---|
| `title` | cadena | Título legible. |
| `category` | cadena | Familia: `outdated_software`, `open_port`, `misconfiguration`, `default_credentials`, `end_of_life`… |
| `source` | cadena | `"lybra"`. |
| `checkId` | cadena | Qué lo produjo, con versión: `lybra:version-match@1`, o el identificador del check. |
| `feedVersion` | cadena | Versión del feed de checks o de la base de conocimiento que lo produjo. |
| `qod` | entero 0–100 | Calidad de detección: cuánto fiarse de que el hallazgo es real. |
| `confirmed` | booleano | Si una prueba activa o un dato de inventario lo confirmó; `false` es una hipótesis. |
| `state` | `"open"` | Siempre `open` en el resultado de un escaneo; el ciclo de vida es cosa de la aplicación. |
| `port`, `protocol`, `service` | | El servicio en el que se encontró, como en `Service`. |

Y las que aparecen cuando aplican: `severity`, `cpe`, `cpeResolved`,
`cveIds`, `cvssScore`, `cvssVector`, `epssScore`, `inKev`,
`exploitMaturity`, `requiredOs`, `evidence`.

### ScanResult

| Clave | Tipo | Qué es |
|---|---|---|
| `scanId` | cadena | |
| `target` | cadena | El objetivo tal como se pidió. |
| `status` | `"completed"` \| `"partial"` | Ver `scan.status`. |
| `startedAt`, `finishedAt` | instante | |
| `services` | lista de `Service` | Lo que se encontró escuchando. |
| `findings` | lista de `Finding` | |
| `unresolved` | lista de cadenas | Productos que no se pudieron resolver a un CPE, y por tanto no se analizaron por versión. |
| `kbFeedVersion` | cadena | Estado de la base de conocimiento con el que se analizó. |

## 5. Objetivos privados

Por defecto el servicio **rechaza** los objetivos en redes privadas, de
loopback y link-local (`target_not_allowed`): un motor que escanea lo que le
pidan, instalado junto a una aplicación web, es una forma de alcanzar la red
interna desde fuera. Quien quiera escanear su propia red lo activa en la
configuración del servicio (`allowPrivateTargets`). `analyze` no está afectado:
no contacta con nada.

La aplicación que integra el motor sigue siendo responsable de decidir qué
objetivos puede escanear cada usuario; este rechazo es una segunda barrera,
no la única.
