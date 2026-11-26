"""``lybrad`` de verdad: un socket Unix, el cliente y la línea de órdenes.

El servidor corre en un hilo sobre un socket en un directorio temporal, con el
núcleo de ``test_service`` (fases falsas, base de conocimiento real). Aquí se
prueba lo que sólo existe con el socket: el formato de línea, varias peticiones
por conexión, los eventos intermedios, los permisos del socket y la CLI.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import tempfile
import threading

import pytest

from lybra import cli
from lybra.checks import Response
from lybra_client import LybraClient, LybraError
from lybra.daemon import build_service_settings, serve
from lybra.knowledge_base import KnowledgeBase
from lybra.protocol import MAX_LINE_BYTES
from lybra.scanner import ScanSettings
from lybra.service import EngineService, ServiceSettings

from test_service import _FakePhases  # pylint: disable=import-error
from test_service_passive import _FakeNetwork  # pylint: disable=import-error

pytestmark = pytest.mark.unit


@pytest.fixture
def daemon():
    # Un directorio corto: la ruta de un socket Unix no puede pasar de ~108 bytes.
    directory = tempfile.mkdtemp(prefix="lybra-", dir="/tmp")
    kb = KnowledgeBase(os.path.join(directory, "kb.sqlite"))
    kb.upsert_cve({"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "severity": "HIGH"},
                  [{"vendor": "nginx", "product": "nginx", "version_start_including": "0.6.18",
                    "version_end_excluding": "1.20.1"}])
    service = EngineService(kb, ServiceSettings(scan=ScanSettings(blocking_recheck_ports=0)),
                            phases_factory=_FakePhases, resolve=lambda name: ["93.184.216.7"],
                            network_factory=_FakeNetwork(
                                http={("abierto.s3.amazonaws.com", "/"): Response(200, "<ListBucketResult/>", {})}
                            ).build)
    path = os.path.join(directory, "lybra.sock")
    server = serve(service, path, group=None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield path
    server.shutdown()
    server.server_close()
    service.shutdown()
    kb.close()
    shutil.rmtree(directory, ignore_errors=True)


def test_the_socket_is_only_for_its_owner_and_group(daemon):
    mode = stat.S_IMODE(os.stat(daemon).st_mode)
    assert mode == 0o660


def test_the_client_scans_and_reads_the_result(daemon):
    client = LybraClient(daemon)
    progress = []

    scan_id = client.scan_start("93.184.216.10", profile="fast")
    final = client.scan_watch(scan_id, on_progress=progress.append)
    result = client.scan_result(scan_id)

    assert final["status"] == "completed"
    # El escaneo falso termina en milisegundos: si acaba antes de que empiece
    # a seguirse, `watch` responde con el estado final sin eventos intermedios.
    assert all("phase" in item and "status" in item for item in progress)
    assert [finding["cveIds"] for finding in result["findings"] if finding.get("cveIds")] == [["CVE-2021-23017"]]


def test_errors_reach_the_client_with_their_code(daemon):
    client = LybraClient(daemon)

    with pytest.raises(LybraError) as error:
        client.scan_start("10.0.0.5")

    assert error.value.code == "target_not_allowed"


def test_one_connection_carries_several_requests_and_survives_a_bad_one(daemon):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(daemon)
        connection.sendall(b'{"v":1,"id":"a","op":"engine.info"}\n'
                           b'esto no es json\n'
                           b'{"v":1,"id":"b","op":"kb.cve","params":{"cveId":"CVE-2021-23017"}}\n')
        reader = connection.makefile("rb")
        replies = [json.loads(reader.readline()) for _ in range(3)]

    assert [(reply["id"], reply["ok"]) for reply in replies] == [("a", True), (None, False), ("b", True)]
    assert replies[1]["error"]["code"] == "bad_request"


def test_an_oversized_line_closes_the_connection(daemon):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(daemon)
        reader = connection.makefile("rb")
        try:
            connection.sendall(b"x" * (MAX_LINE_BYTES + 10))
        except (BrokenPipeError, ConnectionResetError):
            pass
        reply = json.loads(reader.readline())

    assert reply["error"]["code"] == "bad_request"


def test_the_command_line_scans_and_prints_json(daemon, capsys):
    assert cli.main(["--socket", daemon, "--json", "scan", "93.184.216.10", "--profile", "fast"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "completed"

    assert cli.main(["--socket", daemon, "--json", "analyze", "--cpe", "cpe:2.3:a:nginx:nginx",
                     "--version", "1.18.0"]) == 0
    analysis = json.loads(capsys.readouterr().out)
    assert any(finding.get("cveIds") == ["CVE-2021-23017"] for finding in analysis["findings"])


def test_the_passive_and_cloud_operations_round_trip_through_the_socket(daemon, capsys):
    client = LybraClient(daemon)

    result = client.cloud_probe(["s3:abierto"], timeout_seconds=5)
    assert [finding["checkId"] for finding in result["findings"]] == ["lybra:cloud-s3-public-bucket@1"]
    assert client.osint_hostnames("93.184.216.34") == []
    with pytest.raises(LybraError) as error:
        client.cloud_probe()
    assert error.value.code == "invalid_params"

    assert cli.main(["--socket", daemon, "cloud", "probe", "--resource", "s3:abierto"]) == 0
    assert json.loads(capsys.readouterr().out)["resources"] == ["s3:abierto"]
    assert cli.main(["--socket", daemon, "osint", "hostnames", "93.184.216.34"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert cli.main(["--socket", daemon, "cloud", "probe"]) == 2


def test_the_command_line_reports_engine_errors_and_a_missing_daemon(daemon, capsys):
    assert cli.main(["--socket", daemon, "scan", "10.0.0.5"]) == 1
    assert "target_not_allowed" in capsys.readouterr().err

    assert cli.main(["--socket", daemon + ".nope", "info"]) == 3
    assert "No se pudo hablar con lybrad" in capsys.readouterr().err


def test_the_configuration_file_reaches_the_service_settings():
    settings = build_service_settings({"daemon": {"max_concurrent_scans": 2, "allow_private_targets": True},
                                       "kb": {"nvd_window_days": 3},
                                       "scan": {"tcp_concurrency": 50}})

    assert settings.max_concurrent_scans == 2 and settings.allow_private_targets is True
    assert settings.sync.nvd_window_days == 3
    assert settings.scan.tcp_concurrency == 50
    assert build_service_settings({}, allow_private=False).allow_private_targets is False
    with pytest.raises(SystemExit):
        build_service_settings({"scan": {"turbo": True}})


def test_the_osint_keys_come_from_the_environment_before_the_file(monkeypatch):
    monkeypatch.setenv("LYBRA_SHODAN_API_KEY", "del-entorno")
    monkeypatch.delenv("LYBRA_CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("LYBRA_SECURITYTRAILS_API_KEY", raising=False)

    osint = build_service_settings({"osint": {"shodan_api_key": "del-fichero", "censys_api_key": "id:secreto",
                                              "ttl_hours": 6, "enabled_sources": ["crtsh"]}}).osint

    assert osint.api_keys == {"shodan": "del-entorno", "censys": "id:secreto"}
    assert osint.ttl_hours == 6 and osint.enabled_sources == ("crtsh",)
    with pytest.raises(SystemExit):
        build_service_settings({"osint": {"turbo": True}})
