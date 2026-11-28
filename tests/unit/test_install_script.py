import os
import subprocess
import yaml
import pytest

pytestmark = pytest.mark.unit

def test_install_script_syntax_and_executable():
    script_path = os.path.abspath("scripts/install.sh")
    assert os.path.exists(script_path), "scripts/install.sh no existe"
    
    # 1. Comprobar sintaxis bash
    res = subprocess.run(["bash", "-n", script_path], capture_output=True, text=True)
    assert res.returncode == 0, f"Error de sintaxis en bash -n: {res.stderr}"

    # Asegurar permisos de ejecución
    os.chmod(script_path, 0o755)
    assert os.access(script_path, os.X_OK), "scripts/install.sh debe ser ejecutable"

def test_install_script_help():
    script_path = os.path.abspath("scripts/install.sh")
    res = subprocess.run([script_path, "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    stdout = res.stdout
    for flag in ["--venv", "--systemd", "--docker", "--uninstall", "--purge", "--allow-private-targets", "--link-bin", "--dry-run"]:
        assert flag in stdout, f"Falta la documentación del flag {flag} en --help"

def test_install_script_incompatible_modes_and_uninstall():
    script_path = os.path.abspath("scripts/install.sh")
    
    # Modos incompatibles
    res = subprocess.run([script_path, "--systemd", "--docker"], capture_output=True, text=True)
    assert res.returncode == 2

    # --uninstall sin modo explícito
    res = subprocess.run([script_path, "--uninstall"], capture_output=True, text=True)
    assert res.returncode == 2

    # --purge sin --uninstall
    res = subprocess.run([script_path, "--systemd", "--purge"], capture_output=True, text=True)
    assert res.returncode == 2

def test_install_script_systemd_non_root():
    script_path = os.path.abspath("scripts/install.sh")
    # Si no somos root, --systemd sin --dry-run debe fallar con código 1
    if os.geteuid() != 0:
        res = subprocess.run([script_path, "--systemd"], capture_output=True, text=True)
        assert res.returncode == 1

def test_install_script_systemd_dry_run():
    script_path = os.path.abspath("scripts/install.sh")
    res = subprocess.run([script_path, "--systemd", "--allow-private-targets", "--dry-run"], capture_output=True, text=True)
    assert res.returncode == 0
    stdout = res.stdout
    assert "/opt/lybra/venv" in stdout
    assert "client" in stdout
    assert "/usr/bin/lybrad" in stdout
    assert "/usr/local/bin/lybra" in stdout
    assert "lybrad.service" in stdout
    assert "lybrad.toml" in stdout
    assert "systemctl" in stdout

def test_install_script_docker_dry_run_secret_sanitization():
    script_path = os.path.abspath("scripts/install.sh")
    env = os.environ.copy()
    secret_key = "super-secret-key"
    env["LYBRA_NVD_API_KEY"] = secret_key

    res = subprocess.run(
        [script_path, "--docker", "--allow-private-targets", "--link-bin", "--dry-run"],
        env=env,
        capture_output=True,
        text=True
    )
    assert res.returncode == 0
    stdout = res.stdout
    stderr = res.stderr

    assert "-e LYBRA_NVD_API_KEY" in stdout
    assert "--allow-private-targets" in stdout
    assert secret_key not in stdout, "¡El secreto super-secret-key fue filtrado en stdout!"
    assert secret_key not in stderr, "¡El secreto super-secret-key fue filtrado en stderr!"

def test_install_script_uninstall_dry_run():
    script_path = os.path.abspath("scripts/install.sh")
    
    # Sin purge
    res = subprocess.run([script_path, "--uninstall", "--systemd", "--dry-run"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "/var/lib/lybra" not in res.stdout or "rm -rf /var/lib/lybra" not in res.stdout

    # Con purge
    res = subprocess.run([script_path, "--uninstall", "--systemd", "--purge", "--dry-run"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "/opt/lybra" in res.stdout
    assert "/var/lib/lybra" in res.stdout
    assert "/etc/lybra" in res.stdout

    # Docker con purge
    res = subprocess.run([script_path, "--uninstall", "--docker", "--purge", "--dry-run"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "docker volume rm lybra_kb lybra_run" in res.stdout
    assert "docker rmi lybra-engine:latest" in res.stdout

def test_docker_compose_validity():
    compose_path = os.path.abspath("docker-compose.yml")
    assert os.path.exists(compose_path), "docker-compose.yml no existe"
    
    with open(compose_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "services" in data
    assert "lybrad" in data["services"]
    svc = data["services"]["lybrad"]
    assert svc.get("image") == "lybra-engine:latest"
    
    volumes = data.get("volumes", {})
    assert "lybra_kb" in volumes
    assert "lybra_run" in volumes
