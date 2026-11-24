# Protocolo de LybraEngine — v1

Este documento es el contrato entre el servicio `lybrad` y quien lo usa: la CLI
`lybra`, el cliente de Python (`lybra-client`, en `client/`) y, a través de él,
cualquier aplicación (EllysiaServer es la primera). Lo que no esté aquí no es
contrato.

El motor es **autónomo**: guarda su propia base de conocimiento de
vulnerabilidades (NVD, CISA KEV, EPSS y avisos de distribución) y no depende de
ninguna aplicación. Lo que **no** guarda es la historia de los activos: un
escaneo devuelve los hallazgos de ese escaneo, y seguir un hallazgo en el
tiempo (si es nuevo, si sigue abierto, si se corrigió) es trabajo de la
aplicación que lo integra.

## 1. Transporte

- **Socket Unix de tipo stream.** Ruta por defecto: `/run/lybra/lybra.sock`;
  se cambia con la variable `LYBRA_SOCKET` en los dos extremos.
- **Permisos:** el socket se crea con modo `0660` y grupo `lybra`. Quien
  pertenece al grupo puede usar el motor; nadie más llega al socket. No hay
  autenticación adicional: el control de acceso es el del sistema de ficheros.
- **Sin red a propósito.** El motor sólo escucha en local. Exponerlo a otra
  máquina es decisión del operador (un túnel SSH, un proxy) y queda fuera de
  este contrato. Entre contenedores, el socket se comparte con un volumen.

## 2. Formato de los mensajes

Cada mensaje es **un objeto JSON en una sola línea**, en UTF-8, terminado en
`\n`. Una línea no puede superar 16 MiB; ante una más larga el servicio
responde `bad_request` y cierra la conexión.

### Petición

```json
{"v": 1, "id": "c-17", "op": "scan.start", "params": {"target": "198.51.100.10"}}
```

| Campo | Qué es |
|---|---|
| `v` | Versión mayor del protocolo. Hoy, `1`. |
| `id` | Identificador que elige el cliente, de 1 a 64 caracteres; la respuesta lo devuelve tal cual. |
| `op` | La operación (ver §3). |
| `params` | Sus parámetros, un objeto. Puede omitirse si la operación no tiene. |

### Respuesta

```json
{"v": 1, "id": "c-17", "ok": true, "result": {"scanId": "…", "status": "queued"}}
{"v": 1, "id": "c-17", "ok": false, "error": {"code": "invalid_params", "message": "…"}}
```

Cada petición recibe **exactamente una** respuesta final. Una conexión puede
llevar varias peticiones seguidas; el servicio las contesta en orden. Una
petición que no se puede leer recibe un error con `id: null` y la conexión
sigue abierta.

### Eventos

`scan.watch` emite, antes de su respuesta final, eventos con el mismo `id`:

```json
{"v": 1, "id": "c-18", "event": "progress", "data": {"status": "running", "phase": "fingerprint", "done": 3, "total": 8}}
```

Un mensaje con `event` nunca es la respuesta final; la respuesta final es el
primero con `ok`.

### Claves y valores

- Las claves van en **camelCase**.
- Los instantes son cadenas ISO 8601 en UTC con sufijo `Z`.
- El cliente **ignora las claves que no conoce**. Añadir una clave no cambia
  la versión del protocolo; quitarla o cambiar su significado sí (`v: 2`).

### Códigos de error

| Código | Cuándo |
|---|---|
| `bad_request` | El mensaje no es JSON válido, no es un objeto, le falta `id` u `op`, o `params` no es un objeto. |
| `unsupported_version` | `v` no es una versión que el servicio hable. |
| `unknown_op` | La operación no existe. |
| `invalid_params` | Faltan parámetros o tienen un valor no válido. |
| `invalid_target` | El objetivo no es una IP ni un nombre de host, o el nombre no resuelve. |
| `target_not_allowed` | El objetivo es (o resuelve a) una dirección privada, o es un nombre de red interna, y el servicio no los admite (ver §5). |
| `not_found` | El escaneo, la CVE o el resultado pedido no existe. |
| `busy` | La cola de escaneos está llena, o ya hay una sincronización en curso. Se puede reintentar. |
| `internal` | Error no previsto. El mensaje no expone detalles internos; el log del servicio sí. |

## 3. Operaciones

### 3.1 Servicio

**`engine.info`** — sin parámetros.

```json
{"engineVersion": "0.1.0", "protocolVersions": [1], "identificationRevision": "2",
 "kb": {"feedVersion": "lybra-kb:nvd=2026-11-24,kev=…", "counts": {"cves": 351204, "cpeMatches": …, "kev": …, "epss": …, "distroPkgStatus": …}}}
```

### 3.2 Escaneos de red

Un escaneo es asíncrono: se encola, corre en el servicio y su resultado se
consulta después. Corren a la vez como mucho `max_concurrent_scans`; los demás
esperan en cola hasta `max_queued_scans`, y más allá la petición recibe `busy`.

**`scan.start`**

| Parámetro | Tipo | Qué es |
|---|---|---|
| `target` | cadena | **Un** host: una IP o un nombre. Obligatorio. Los rangos los expande quien llama. |
| `profile` | `"fast"` \| `"standard"` \| `"thorough"` | `fast`: los ~100 puertos más comunes, sin rastreo ni checks activos. `standard`: la lista de puertos del motor, con todo. `thorough`: los 65 535 puertos, sin que el planificador se salte nada. Por defecto `standard`. |
| `ports` | lista de enteros | Puertos TCP concretos; sustituyen a los del perfil. |
| `timeoutSeconds` | número | Presupuesto de reloj del escaneo entero. Al agotarse, el resultado sale `partial`. Sin él, no hay límite. |
| `fingerprint` | booleano | Identificar cada servicio sondeándolo. Por defecto `true`. |
| `crawl` | booleano | Rastrear los servicios web. Por defecto `true` (nunca en `fast`). |
| `activeChecks` | booleano | Checks activos, superficie de API y sitios con nombre. Por defecto `true` (nunca en `fast`). |
| `aggressive` | booleano | Permitir los checks que escriben en el objetivo y el motor de credenciales por defecto (logins reales). Por defecto `false`; ignorado en `fast`. |
| `knownServices` | lista de `KnownService` | Lo que quien llama sabe del objetivo por escaneos anteriores. Un servicio identificado hace menos de 7 días por la revisión actual del motor no se vuelve a sondear (la detección por versión corre igual). Ignorado en `thorough`. |
| `siteCandidates` | lista de `{name, origin}` | Nombres de sitio que la IP no delata y que quien llama autorizó auditar. Sólo cuenta si el objetivo es una IP. |

Devuelve `{"scanId": "…", "status": "queued"}` (o `running` si ya arrancó).

**`scan.status`** `{scanId}` — devuelve `{"scanId", "target", "status",
"progress": {"phase", "done", "total"}}` y, si falló, `error`. Los estados:

| Estado | Significado |
|---|---|
| `queued` | Esperando turno. |
| `running` | En curso; `progress` dice la fase (`discovery`, `fingerprint`, `checks`) y el avance. |
| `completed` | Terminó y el barrido fue completo. |
| `partial` | Terminó sin barrer todo: plazo agotado, barrido inverosímil o un objetivo que dejó de contestar. **Lo que no aparece en un resultado parcial no se ha comprobado**: quien lleva el ciclo de vida no debe dar por corregido un hallazgo que falte. |
| `failed` | No pudo hacerse. `error.code` es `host_unreachable` (no contestó a la comprobación de alcanzabilidad), `port_discovery_failed` (el barrido quedó bloqueado) o `internal`. |
| `cancelled` | Se canceló. |

**`scan.watch`** `{scanId}` — emite eventos `progress` hasta que el escaneo
termina y responde con lo mismo que `scan.status` en su estado final.

**`scan.result`** `{scanId}` — devuelve el `ScanResult` (§4) de un escaneo
terminado. Si falló, responde con su error (`host_unreachable`…); si aún no ha
terminado, `not_found`. Los escaneos se olvidan 24 horas después de terminar.

**`scan.cancel`** `{scanId}` — cancela un escaneo en cola o en curso y
devuelve su estado.

### 3.3 Análisis sin red: CPE y versión

**`analyze`** — devuelve los hallazgos de una lista de servicios **que quien
llama ya conoce**, sin tocar la red. Es la operación de la integración con
Hygeia: un inventario dice qué hay instalado en un equipo y el motor lo cruza
con su base de conocimiento. Es síncrona.

| Parámetro | Tipo | Qué es |
|---|---|---|
| `services` | lista de `Service` | De 1 a 5000. Para un paquete instalado basta `product` + `version`, o `cpe` + `version`, con `origin: "inventory"`. |

```json
{"v": 1, "id": "c-21", "op": "analyze", "params": {"services": [
  {"cpe": "cpe:2.3:a:openssl:openssl", "version": "3.0.1", "origin": "inventory"}
]}}
```

Un CPE 2.3 se puede escribir corto, como en el ejemplo: los campos que falten
se dan por `*`. Devuelve `{"findings": [Finding, …], "kbFeedVersion": "…"}`.

- Con `origin: "inventory"` la versión es un **hecho** leído del equipo: el
  hallazgo nace `confirmed: true` y con la calidad de detección más alta.
- Las versiones de paquete de distribución (`1:9.6p1-3ubuntu13.5`) se comparan
  por su versión de origen, y los avisos de la distribución se aplican (ver
  `state` en §4).
- Un producto que no se puede resolver a un CPE no produce hallazgos de
  versión, y queda anotado en `kb.unresolved`.

### 3.4 Base de conocimiento

| Operación | Parámetros | Devuelve |
|---|---|---|
| `kb.cve` | `cveId` | `cveId`, `published`, `cvssScore`, `severity`, `description` (en inglés), `products`, `inKev`, `epssScore`, `epssPercentile`, `distroStatuses`. `not_found` si ninguna fuente la conoce. |
| `kb.version` | `product`, `version` | `recognized`, `vendor`/`product`/`version` del CPE resuelto, `cves` (hasta 25, las más urgentes primero), `cvesTotal`, `endOfLife`. |
| `kb.products` | `term`, `limit` (por defecto 20, máximo 100) | `{"products": [{vendor, product, displayName}]}`: los que empiezan por `term`. |
| `kb.resolve` | `names` (hasta 1000) | `{"products": [{vendor, product}]}`: los nombres que resuelven, sin repetir. |
| `kb.advisories` | `products` (1 a 200 `{vendor, product}`), `since` (instante, opcional), `minCvss` (opcional), `limit` | `{"advisories": [{cveId, vendor, product, published, severity, cvssScore, description, inKev, epssScore, url}]}`, del más reciente al más antiguo. |
| `kb.unresolved` | `origin` (`network` \| `inventory`, opcional), `limit` (por defecto 50) | `{"products": [{name, origin, occurrences, firstSeenAt, lastSeenAt}]}`: los nombres que más veces quedaron sin resolver. |
| `kb.status` | — | `{"sources": [...], "isStale", "isUnverified", "feedVersion"}`, una entrada por fuente con `lastAttemptAt`, `lastSuccessAt`, `rowsUpserted`, `error`, `neverSynced`, `hasContent`, `ageDays`, `maxAgeDays`, `isStale`, `isUnverified`, `newestContentAt`. |
| `kb.sync` | `source` (`all`, `nvd`, `kev`, `epss`, `oval`; por defecto `all`) | Lanza la sincronización en segundo plano y responde `{"started": true, "source"}` al momento; `busy` si ya hay una en curso. |

Ninguna consulta de la base busca por subcadena ni devuelve listas sin tope.

### 3.5 Reservado

`osint.domain` (inteligencia pasiva de un dominio) queda para una versión
posterior: necesita las claves de los servicios de terceros y una caché.

## 4. Tipos

### Service

| Clave | Tipo | Qué es |
|---|---|---|
| `port` | entero o `null` | Puerto. `null` en un componente instalado. |
| `protocol` | `"tcp"` \| `"udp"` \| `""` | Transporte. Vacío en un componente instalado. |
| `name` | cadena | Nombre del servicio (`"http"`). |
| `product` | cadena | Producto (`"Apache httpd"`). |
| `version` | cadena | Versión (`"2.4.49"`). |
| `cpe` | cadena o `null` | CPE, en formato 2.2 o 2.3. |
| `origin` | `"network"` \| `"inventory"` | `network`: deducido de lo que el servicio enseña, una suposición. `inventory`: leído en el propio equipo, un hecho. Por defecto `network`. |
| `components` | lista de `[producto, versión]` | Sólo en resultados: lo que corre dentro de un servicio web (CMS, librerías). |

`KnownService` es un `Service` con dos claves más: `identifiedAt` (instante en
que se identificó) e `identifiedBy` (la `identificationRevision` del motor que
lo hizo).

### Finding

Las claves siempre presentes: `title`, `category`, `source` (`"lybra"`),
`checkId`, `feedVersion`, `qod` (0–100: cuánto fiarse de que es real),
`confirmed`, `state`, y `port`/`protocol`/`service`.

`state` es `open`, salvo que la distribución ya haya publicado la corrección
del paquete instalado: entonces es `fixed` (un *backport*: el número de versión
dice vulnerable, pero el parche está).

Y las que aparecen cuando aplican: `severity`, `cpe`, `cpeResolved`, `cveIds`,
`cvssScore`, `cvssVector`, `epssScore`, `inKev`, `exploitMaturity`,
`requiredOs`, `vhost`, `installedVersion`, `servesDefaultSite`, `evidence`
(lo que provocó el hallazgo, en bruto: quien lo guarde debe redactarlo).

### ScanResult

| Clave | Tipo | Qué es |
|---|---|---|
| `scanId`, `target` | cadena | |
| `status` | `"completed"` \| `"partial"` \| `"cancelled"` | Ver `scan.status`. |
| `startedAt`, `finishedAt` | instante | |
| `services` | lista de `Service` | Lo que se encontró, ya identificado. |
| `probedServices` | lista de `[puerto, protocolo]` | Los servicios que este escaneo identificó sondeándolos; los que el planificador reutilizó no están. |
| `identificationRevision` | cadena | La revisión con la que se identificaron; quien guarde la superficie la necesita para `knownServices`. |
| `findings` | lista de `Finding` | |
| `refutations` | lista | Las marcas de los checks que desmintieron un hallazgo de versión (`refutes`: la CVE). Quien lleva el ciclo de vida las aplica. |
| `kbFeedVersion` | cadena | Estado de la base de conocimiento con el que se analizó. |

## 5. Objetivos privados

Por defecto el servicio **rechaza** los objetivos en redes privadas, de
loopback y link-local, los nombres de red interna (`.local`, `.internal`,
`.lan`…) y los nombres que resuelven a cualquiera de esas direcciones
(`target_not_allowed`): un motor que escanea lo que le pidan, instalado junto a
una aplicación web, es una forma de alcanzar la red interna desde fuera. Quien
quiera escanear su propia red lo activa con `allow_private_targets` o
`--allow-private-targets`. `analyze` no está afectado: no contacta con nada.

Un objetivo por nombre se fija a la IP que resolvió al validarlo durante todo
el escaneo, para que un cambio de DNS a mitad no lo desvíe.

La aplicación que integra el motor sigue siendo responsable de decidir qué
objetivos puede escanear cada usuario; este rechazo es una segunda barrera.
