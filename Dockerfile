# La imagen de lybrad.
#
# El socket se comparte con otros contenedores a través del volumen /run/lybra.
# Quien lo use tiene que pertenecer al grupo LYBRA_GID (en compose:
# `group_add: ["990"]`), porque el socket tiene permisos 0660.
FROM python:3.11-slim-bookworm

ARG LYBRA_UID=990
ARG LYBRA_GID=990

RUN groupadd --system --gid "${LYBRA_GID}" lybra \
 && useradd --system --uid "${LYBRA_UID}" --gid lybra --home-dir /var/lib/lybra --shell /usr/sbin/nologin lybra \
 && mkdir -p /var/lib/lybra /run/lybra \
 && chown lybra:lybra /var/lib/lybra /run/lybra \
 && chmod 0750 /var/lib/lybra /run/lybra

WORKDIR /opt/lybra
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /opt/lybra/src

USER lybra
ENV LYBRA_SOCKET=/run/lybra/lybra.sock \
    LYBRA_KB=/var/lib/lybra/kb.sqlite \
    PYTHONUNBUFFERED=1
VOLUME ["/var/lib/lybra", "/run/lybra"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["lybra", "info"]
ENTRYPOINT ["lybrad"]
