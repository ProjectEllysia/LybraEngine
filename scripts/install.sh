#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat << 'EOF'
Instalador oficial de LybraEngine (lybrad y lybra).

Modos de uso (mutuamente excluyentes):
  --venv                Instala en entorno virtual local (por defecto si no es root)
  --systemd             Instala o actualiza el servicio systemd en /opt/lybra/venv (requiere root)
  --docker              Construye la imagen lybra-engine:latest y levanta el contenedor docker

Opciones adicionales:
  --allow-private-targets   Activa permitir objetivos privados en lybrad.toml o en el contenedor
  --link-bin            Crea enlaces simbólicos o wrapper de lybra (--venv y --docker)
  --uninstall           Desinstala el modo especificado
  --purge               Borra también datos persistentes y configuración (requiere --uninstall)
  --dry-run             Simula las acciones sin modificar el sistema
  -h, --help            Muestra esta ayuda y sale

Ejemplos:
  ./scripts/install.sh --venv --link-bin
  sudo ./scripts/install.sh --systemd --allow-private-targets
  ./scripts/install.sh --docker --allow-private-targets --link-bin
EOF
    exit 0
}

DRY_RUN=0
MODE=""
ALLOW_PRIVATE_TARGETS=0
LINK_BIN=0
UNINSTALL=0
PURGE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --venv)
            if [[ -n "$MODE" && "$MODE" != "venv" ]]; then
                echo "Error: Modos mutuamente excluyentes especificados (--$MODE y --venv)." >&2
                exit 2
            fi
            MODE="venv"
            shift
            ;;
        --systemd)
            if [[ -n "$MODE" && "$MODE" != "systemd" ]]; then
                echo "Error: Modos mutuamente excluyentes especificados (--$MODE y --systemd)." >&2
                exit 2
            fi
            MODE="systemd"
            shift
            ;;
        --docker)
            if [[ -n "$MODE" && "$MODE" != "docker" ]]; then
                echo "Error: Modos mutuamente excluyentes especificados (--$MODE y --docker)." >&2
                exit 2
            fi
            MODE="docker"
            shift
            ;;
        --allow-private-targets)
            ALLOW_PRIVATE_TARGETS=1
            shift
            ;;
        --link-bin)
            LINK_BIN=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        *)
            echo "Error: Opción desconocida: $1" >&2
            exit 2
            ;;
        esac
done

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] $*"
    else
        echo "+ $*"
        "$@"
    fi
}

if [[ "$PURGE" -eq 1 && "$UNINSTALL" -eq 0 ]]; then
    echo "Error: --purge sólo puede usarse junto con --uninstall." >&2
    exit 2
fi

# Determinar modo por defecto si no se indicó
if [[ -z "$MODE" ]]; then
    if [[ "$UNINSTALL" -eq 1 ]]; then
        echo "Error: --uninstall requiere indicar explícitamente el modo (--venv, --systemd o --docker)." >&2
        exit 2
    fi
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        echo "Error: Debe indicar un modo explícitamente cuando se ejecuta como root (--systemd, --docker o --venv)." >&2
        exit 2
    else
        MODE="venv"
    fi
fi

# Validación de root para systemd
if [[ "$MODE" == "systemd" ]]; then
    if [[ "${EUID:-$(id -u)}" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
        echo "Error: El modo --systemd requiere privilegios de root. Sugerencia: sudo ./scripts/install.sh --systemd" >&2
        exit 1
    fi
fi

# Desinstalación
if [[ "$UNINSTALL" -eq 1 ]]; then
    if [[ "$MODE" == "venv" ]]; then
        VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venv}"
        run rm -rf "$VENV_DIR"
        if [[ "$LINK_BIN" -eq 1 || -L "${XDG_BIN_HOME:-$HOME/.local/bin}/lybra" ]]; then
            BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
            run rm -f "$BIN_DIR/lybra" "$BIN_DIR/lybrad"
        fi
        echo "Desinstalación venv completada."
    elif [[ "$MODE" == "systemd" ]]; then
        run systemctl stop lybrad || true
        run systemctl disable lybrad || true
        run rm -f /etc/systemd/system/lybrad.service
        run systemctl daemon-reload
        run rm -f /usr/bin/lybrad /usr/local/bin/lybra
        run rm -rf /opt/lybra
        if [[ "$PURGE" -eq 1 ]]; then
            run rm -rf /var/lib/lybra /etc/lybra
            run userdel lybra || true
            run groupdel lybra || true
        fi
        echo "Desinstalación systemd completada."
    elif [[ "$MODE" == "docker" ]]; then
        run docker rm -f lybra || true
        if [[ "$PURGE" -eq 1 ]]; then
            run docker volume rm lybra_kb lybra_run || true
            run docker rmi lybra-engine:latest || true
        fi
        BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
        if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
            WRAPPER_CANDIDATE="/usr/local/bin/lybra"
        else
            WRAPPER_CANDIDATE="$BIN_DIR/lybra"
        fi
        if [[ "$DRY_RUN" -eq 1 ]] || grep -q "lybra-docker-wrapper" "$WRAPPER_CANDIDATE" 2>/dev/null; then
            run rm -f "$WRAPPER_CANDIDATE"
        fi
        echo "Desinstalación docker completada."
    fi
    exit 0
fi

# Instalación / Actualización
if [[ "$MODE" == "venv" ]]; then
    VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venv}"
    run python3 -m venv "$VENV_DIR"
    run "$VENV_DIR/bin/pip" install --upgrade pip
    run "$VENV_DIR/bin/pip" install "$REPO_ROOT/client" "$REPO_ROOT"
    if [[ "$LINK_BIN" -eq 1 ]]; then
        BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
        run mkdir -p "$BIN_DIR"
        run ln -sf "$VENV_DIR/bin/lybra" "$BIN_DIR/lybra"
        run ln -sf "$VENV_DIR/bin/lybrad" "$BIN_DIR/lybrad"
    fi
    echo "Instalación venv completada en $VENV_DIR"

elif [[ "$MODE" == "systemd" ]]; then
    getent group lybra >/dev/null 2>&1 || run groupadd --system lybra
    id -u lybra >/dev/null 2>&1 || run useradd --system --gid lybra --home-dir /var/lib/lybra --shell /usr/sbin/nologin lybra
    run python3 -m venv /opt/lybra/venv
    run /opt/lybra/venv/bin/pip install --upgrade pip
    run /opt/lybra/venv/bin/pip install "$REPO_ROOT/client" "$REPO_ROOT"

    run ln -sf /opt/lybra/venv/bin/lybrad /usr/bin/lybrad
    run ln -sf /opt/lybra/venv/bin/lybra /usr/local/bin/lybra

    run mkdir -p /etc/systemd/system
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] cp packaging/lybrad.service /etc/systemd/system/lybrad.service"
        echo "[dry-run] chmod 0644 /etc/systemd/system/lybrad.service"
    else
        cp "$REPO_ROOT/packaging/lybrad.service" /etc/systemd/system/lybrad.service
        chmod 0644 /etc/systemd/system/lybrad.service
    fi

    run mkdir -p /etc/lybra /var/lib/lybra
    run chown -R lybra:lybra /var/lib/lybra
    run chmod 0750 /var/lib/lybra

    if [[ ! -f /etc/lybra/lybrad.toml ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] cp packaging/lybrad.toml /etc/lybra/lybrad.toml"
            echo "[dry-run] chmod 0644 /etc/lybra/lybrad.toml"
        else
            cp "$REPO_ROOT/packaging/lybrad.toml" /etc/lybra/lybrad.toml
            chmod 0644 /etc/lybra/lybrad.toml
        fi
    else
        echo "Aviso: /etc/lybra/lybrad.toml ya existe, se conserva intacto."
    fi

    if [[ "$ALLOW_PRIVATE_TARGETS" -eq 1 ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] Actualizar allow_private_targets = true en /etc/lybra/lybrad.toml"
        else
            if grep -q "allow_private_targets" /etc/lybra/lybrad.toml; then
                sed -i 's/^[[:space:]]*allow_private_targets[[:space:]]*=.*/allow_private_targets = true/' /etc/lybra/lybrad.toml
            else
                echo "allow_private_targets = true" >> /etc/lybra/lybrad.toml
            fi
        fi
    fi

    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        run usermod -aG lybra "$SUDO_USER" || true
        echo "Aviso: Se ha añadido al usuario $SUDO_USER al grupo lybra. Ejecute 'newgrp lybra' o reinicie sesión."
    fi

    run systemctl daemon-reload
    run systemctl enable lybrad
    run systemctl restart lybrad
    echo "Instalación systemd completada."

elif [[ "$MODE" == "docker" ]]; then
    run docker build -t lybra-engine:latest "$REPO_ROOT"
    run docker volume create lybra_kb
    run docker volume create lybra_run
    if docker inspect lybra >/dev/null 2>&1 || [[ "$DRY_RUN" -eq 1 ]]; then
        run docker rm -f lybra || true
    fi

    DOCKER_ARGS=(
        docker
        run -d
        --name lybra
        --restart unless-stopped
        -v lybra_kb:/var/lib/lybra
        -v lybra_run:/run/lybra
    )
    # Reenvío de variables de entorno sin exponer su valor
    for v in LYBRA_NVD_API_KEY LYBRA_SHODAN_API_KEY LYBRA_CENSYS_API_KEY LYBRA_SECURITYTRAILS_API_KEY; do
        if [[ -n "${!v:-}" ]]; then
            DOCKER_ARGS+=(-e "$v")
        fi
    done

    DOCKER_ARGS+=(lybra-engine:latest)
    if [[ "$ALLOW_PRIVATE_TARGETS" -eq 1 ]]; then
        DOCKER_ARGS+=(--allow-private-targets)
    fi

    run "${DOCKER_ARGS[@]}"

    if [[ "$LINK_BIN" -eq 1 ]]; then
        if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
            WRAPPER_PATH="/usr/local/bin/lybra"
        else
            BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
            run mkdir -p "$BIN_DIR"
            WRAPPER_PATH="$BIN_DIR/lybra"
        fi

        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] Crear script wrapper docker en $WRAPPER_PATH"
        else
            cat << 'EOF_WRAPPER' > "$WRAPPER_PATH"
#!/usr/bin/env sh
# lybra-docker-wrapper
if [ -t 0 ] && [ -t 1 ]; then
  exec docker exec -it lybra lybra "$@"
else
  exec docker exec -i lybra lybra "$@"
fi
EOF_WRAPPER
            chmod +x "$WRAPPER_PATH"
        fi
    fi
    echo "Instalación docker completada."
fi
