"""Las operaciones de inteligencia pasiva y cloud del servicio, sin socket y sin red.

Lo que toca la red llega por un ``PassiveNetwork`` falso: las fuentes responden
con la forma real de cada API, el DNS sale de una tabla y las sondas cloud ven
respuestas fabricadas. La caché es la de verdad, en una base SQLite temporal.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from lybra import OsintSource
from lybra.core._shared import utcnow_naive
from lybra.checks.framework import Response
from lybra.core.engine import Service
from lybra.kb.store import KnowledgeBase
from lybra.recon.osint_network import OsintSettings, PassiveNetwork, source_request
from lybra.app.service import EngineService, ServiceSettings

from test_lybra_osint import CENSYS_PAYLOAD, CRTSH_PAYLOAD, SHODAN_PAYLOAD  # pylint: disable=import-error
from test_service import _FakePhases, _error, _ok  # pylint: disable=import-error

pytestmark = pytest.mark.unit

_S3_LISTING = '<?xml version="1.0"?><ListBucketResult><Name>b</Name></ListBucketResult>'
_ADDRESS = "93.184.216.34"

_DNS = {("example.com", "A"): [_ADDRESS], ("www.example.com", "A"): [_ADDRESS],
        ("example.com", "TXT"): ["v=spf1 include:_spf.example.com ~all"]}


class _FakeNetwork:
    """Lo que toca la red, con respuestas fijas, y la cuenta de cada llamada."""

    def __init__(self, payloads=None, http=None, cnames=None):
        self.payloads = payloads or {OsintSource.CERTIFICATE_TRANSPARENCY: CRTSH_PAYLOAD}
        self.http, self.cnames = http or {}, cnames or {}
        self.downloads, self.requests = [], []

    def download(self, source, query):
        self.downloads.append((source, query))
        return self.payloads.get(source)

    def build(self, _settings):
        return PassiveNetwork(
            download=self.download,
            lookup_records=lambda name, record_type: _DNS.get((name, record_type), []),
            resolve_cname=self.cnames.get,
            http_get=lambda host, port, path: self.requests.append((host, port, path))
            or self.http.get((host, path)))


@pytest.fixture
def kb(tmp_path):
    base = KnowledgeBase(tmp_path / "kb.sqlite")
    yield base
    base.close()


def _service(kb, network, osint=None, **settings):
    resolve = {"internal.example.com": ["10.1.2.3"]}
    service = EngineService(
        kb, ServiceSettings(osint=osint or OsintSettings(), **settings), phases_factory=_FakePhases,
        resolve=lambda name: resolve.get(name, ["93.184.216.7"]), network_factory=network.build)
    return service


def _keyed(**keys):
    return OsintSettings(api_keys=keys)


# ============================================================ osint.domain

def test_a_domain_is_reported_with_its_subdomains_sources_and_dns_findings(kb):
    network = _FakeNetwork({OsintSource.CERTIFICATE_TRANSPARENCY: CRTSH_PAYLOAD,
                            OsintSource.SHODAN: SHODAN_PAYLOAD})
    service = _service(kb, network, _keyed(shodan="k"))

    result = _ok(service, "osint.domain", {"domain": "Example.COM."})

    assert result["domain"] == "example.com"
    names = [record["name"] for record in result["subdomains"]]
    assert names == ["dev.example.com", "example.com", "www.example.com"]
    outcomes = {source["source"]: source["outcome"] for source in result["sources"]}
    assert outcomes == {"crtsh": "ok", "shodan": "ok", "censys": "skipped", "securitytrails": "skipped"}
    assert [(item["port"], item["address"], item["source"]) for item in result["observations"]
            if item["port"] == 443] == [(443, _ADDRESS, "shodan")]
    assert {check["check"] for check in result["dnsChecks"]} >= {"spf", "dmarc", "dnssec"}
    checks = {finding["checkId"] for finding in result["findings"]}
    assert "lybra:osint-exposed-service@1" in checks and any(check.startswith("lybra:dns-") for check in checks)
    assert all("provenance" in finding and "check_id" not in finding for finding in result["findings"])
    assert (OsintSource.SHODAN, _ADDRESS) in network.downloads
    service.shutdown()


def test_source_answers_are_cached_for_their_ttl(kb):
    network = _FakeNetwork()
    service = _service(kb, network)

    first = _ok(service, "osint.domain", {"domain": "example.com"})
    second = _ok(service, "osint.domain", {"domain": "example.com"})

    assert network.downloads == [(OsintSource.CERTIFICATE_TRANSPARENCY, "example.com")]
    assert first["sources"][0]["cached"] is False and second["sources"][0]["cached"] is True
    assert second["sources"][0]["retrievedAt"] == first["sources"][0]["retrievedAt"]

    kb.save_osint_cache("crtsh", "example.com", CRTSH_PAYLOAD, utcnow_naive() - timedelta(hours=25))
    _ok(service, "osint.domain", {"domain": "example.com"})
    assert len(network.downloads) == 2
    service.shutdown()


def test_a_failed_download_is_not_cached_and_does_not_break_the_rest(kb):
    network = _FakeNetwork()
    network.download = lambda source, query: (_ for _ in ()).throw(ConnectionError("caída"))
    service = _service(kb, network)

    result = _ok(service, "osint.domain", {"domain": "example.com"})

    assert result["sources"][0]["outcome"] == "failed" and result["dnsChecks"]
    assert kb.get_osint_cache("crtsh", "example.com") is None
    service.shutdown()


def test_sources_can_be_narrowed_and_a_source_the_operator_switched_off_is_never_asked(kb):
    network = _FakeNetwork({OsintSource.SHODAN: SHODAN_PAYLOAD})
    service = _service(kb, network, OsintSettings(api_keys={"shodan": "k"}, enabled_sources=("shodan",)))

    result = _ok(service, "osint.domain", {"domain": "example.com", "sources": ["crtsh", "shodan"]})

    assert {source["source"]: source["outcome"] for source in result["sources"]}["crtsh"] == "disabled"
    assert all(source is OsintSource.SHODAN for source, _ in network.downloads)
    service.shutdown()


def test_an_expired_deadline_asks_nobody(kb):
    network = _FakeNetwork()
    service = _service(kb, network)

    result = _ok(service, "osint.domain", {"domain": "example.com", "timeoutSeconds": 1e-9})

    assert network.downloads == [] and result["sources"][0]["outcome"] == "failed"
    service.shutdown()


@pytest.mark.parametrize("params", [
    {}, {"domain": "10.0.0.1"}, {"domain": "https://example.com/x"},
    {"domain": "example.com", "sources": ["bing"]}, {"domain": "example.com", "sources": "crtsh"},
    {"domain": "example.com", "dkimSelectors": ["no válido!"]},
    {"domain": "example.com", "dkimSelectors": [f"s{number}" for number in range(11)]},
    {"domain": "example.com", "timeoutSeconds": 0}, {"domain": "example.com", "timeoutSeconds": "mucho"},
])
def test_bad_domain_requests_are_rejected(kb, params):
    service = _service(kb, _FakeNetwork())
    assert _error(service, "osint.domain", params) == "invalid_params"
    service.shutdown()


def test_requested_dkim_selectors_are_checked(kb):
    service = _service(kb, _FakeNetwork())
    result = _ok(service, "osint.domain", {"domain": "example.com", "dkimSelectors": ["Selector1"]})
    assert next(check for check in result["dnsChecks"] if check["check"] == "dkim")["status"] != "not_applicable"
    service.shutdown()


def test_the_api_keys_travel_only_to_their_source_and_never_show_in_a_repr():
    url, _ = source_request(OsintSource.SHODAN, "93.184.216.34", "S3CRET")
    _, censys_headers = source_request(OsintSource.CENSYS, "93.184.216.34", "id:secreto")
    crtsh_url, crtsh_headers = source_request(OsintSource.CERTIFICATE_TRANSPARENCY, "example.com", "")

    assert url.endswith("/shodan/host/93.184.216.34?key=S3CRET")
    assert censys_headers["Authorization"].startswith("Basic ")
    assert "key" not in crtsh_url and crtsh_headers == {}
    assert "S3CRET" not in repr(_keyed(shodan="S3CRET"))


# ============================================================ osint.hostnames

def test_the_host_names_of_an_ip_come_from_the_sources_that_have_a_key(kb):
    shodan = dict(SHODAN_PAYLOAD, hostnames=["www.example.com"], domains=["example.com"])
    network = _FakeNetwork({OsintSource.SHODAN: shodan, OsintSource.CENSYS: CENSYS_PAYLOAD})
    service = _service(kb, network, _keyed(shodan="k"))

    result = _ok(service, "osint.hostnames", {"address": _ADDRESS})

    assert result == {"address": _ADDRESS, "names": ["www.example.com", "example.com"]}
    assert network.downloads == [(OsintSource.SHODAN, _ADDRESS)]
    service.shutdown()


def test_a_private_address_is_never_asked_about(kb):
    network = _FakeNetwork({OsintSource.SHODAN: SHODAN_PAYLOAD})
    service = _service(kb, network, _keyed(shodan="k"))

    assert _ok(service, "osint.hostnames", {"address": "10.0.0.5"})["names"] == []
    assert network.downloads == []
    assert _error(service, "osint.hostnames", {"address": "example.com"}) == "invalid_params"
    service.shutdown()


# ============================================================ enriquecimiento

class _UnidentifiedPhases(_FakePhases):
    """Un puerto 80 abierto que el fingerprint no logra identificar."""

    def fingerprint_services(self, target, services, cancel_check=None, on_progress=None):
        return [Service(port=80, protocol="tcp", name="http")], []


def _enrichment(findings):
    return [finding for finding in findings if finding["checkId"] == "lybra:osint-suggested-cpe@1"]


def _scan_with(kb, network, osint, params):
    service = EngineService(kb, ServiceSettings(osint=osint), phases_factory=_UnidentifiedPhases,
                            network_factory=network.build)
    scan_id = _ok(service, "scan.start", {"target": _ADDRESS, "profile": "fast", **params})["scanId"]
    _ok(service, "scan.watch", {"scanId": scan_id})
    result = _ok(service, "scan.result", {"scanId": scan_id})
    service.shutdown()
    return result


def test_a_scan_asks_third_parties_only_when_told_to_and_keyed(kb):
    shodan = {"data": [{"port": 80, "transport": "tcp", "cpe23": ["cpe:2.3:a:f5:nginx:1.18.0"]}]}
    network = _FakeNetwork({OsintSource.SHODAN: shodan})

    plain = _scan_with(kb, network, _keyed(shodan="k"), {})
    keyless = _scan_with(kb, network, OsintSettings(), {"enrich": True})
    assert network.downloads == [] and not _enrichment(plain["findings"]) and not _enrichment(keyless["findings"])

    enriched = _scan_with(kb, network, _keyed(shodan="k"), {"enrich": True})
    suggestion = _enrichment(enriched["findings"])
    assert [(finding["port"], finding["cpe"]) for finding in suggestion] == [(80, "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")]
    assert suggestion[0]["provenance"]["source"] == "shodan"
    assert network.downloads == [(OsintSource.SHODAN, _ADDRESS)]


def test_analyze_enriches_the_address_it_is_given(kb):
    shodan = {"data": [{"port": 80, "transport": "tcp", "cpe23": ["cpe:2.3:a:f5:nginx:1.18.0"]}]}
    network = _FakeNetwork({OsintSource.SHODAN: shodan})
    service = _service(kb, network, _keyed(shodan="k"))
    services = [{"port": 80, "protocol": "tcp", "name": "http"}]

    assert not _enrichment(_ok(service, "analyze", {"services": services})["findings"])
    result = _ok(service, "analyze", {"services": services, "enrich": True, "target": _ADDRESS})
    assert [finding["port"] for finding in _enrichment(result["findings"])] == [80]
    for target in (None, "example.com"):
        params = {"services": services, "enrich": True, **({"target": target} if target else {})}
        assert _error(service, "analyze", params) == "invalid_params"
    service.shutdown()


# ============================================================ cloud.probe

def test_exposed_resources_and_hijackable_subdomains_are_reported(kb):
    network = _FakeNetwork(
        http={("abierto.s3.amazonaws.com", "/"): Response(200, _S3_LISTING, {}),
              ("privado.s3.amazonaws.com", "/"): Response(403, "AccessDenied", {}),
              ("app.example.com", "/"): Response(404, "NoSuchBucket", {})},
        cnames={"app.example.com": "viejo.s3.amazonaws.com.", "www.example.com": None})
    service = _service(kb, network)

    result = _ok(service, "cloud.probe", {"resources": ["s3:abierto", "S3:abierto", "s3:privado"],
                                          "subdomains": ["app.example.com", "www.example.com"]})

    assert result["resources"] == ["s3:abierto", "s3:privado"]
    assert result["subdomains"] == [{"name": "app.example.com"}, {"name": "www.example.com"}]
    assert sorted(finding["checkId"] for finding in result["findings"]) == [
        "lybra:cloud-s3-public-bucket@1", "lybra:cloud-takeover-aws-s3@1"]
    for finding in result["findings"]:
        assert finding["dedupKey"] and finding["provenance"]["source"] == "cloud"
        assert finding["provenance"]["observedAt"].endswith("Z")
    service.shutdown()


def test_a_name_that_resolves_to_a_private_address_is_never_requested(kb):
    network = _FakeNetwork(http={("internal.example.com", "/"): Response(404, "NoSuchBucket", {})},
                           cnames={"internal.example.com": "viejo.s3.amazonaws.com"})

    strict = _service(kb, network)
    assert _ok(strict, "cloud.probe", {"subdomains": ["internal.example.com"]})["findings"] == []
    assert network.requests == []
    strict.shutdown()

    allowed = _service(kb, network, allow_private_targets=True)
    assert len(_ok(allowed, "cloud.probe", {"subdomains": ["internal.example.com"]})["findings"]) == 1
    allowed.shutdown()


@pytest.mark.parametrize("params", [
    {}, {"resources": []}, {"resources": ["ftp:x"]}, {"resources": "s3:x"}, {"subdomains": ["10.0.0.1"]},
    {"resources": [f"s3:bucket{number:03d}" for number in range(26)]},
    {"subdomains": ["a.example.com"], "timeoutSeconds": -1},
])
def test_bad_cloud_requests_are_rejected(kb, params):
    service = _service(kb, _FakeNetwork())
    assert _error(service, "cloud.probe", params) == "invalid_params"
    service.shutdown()


# ============================================================ kb.cve acotada

def test_a_cve_card_is_capped_and_says_how_many_it_left_out(kb):
    kb.upsert_cve({"cve_id": "CVE-2024-0001", "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N",
                   "severity": "CRITICAL"},
                  [{"vendor": "v", "product": f"p{number}"} for number in range(60)])
    service = _service(kb, _FakeNetwork())

    card = _ok(service, "kb.cve", {"cveId": "CVE-2024-0001"})

    assert card["cvssVector"] == "CVSS:3.1/AV:N"
    assert (len(card["products"]), card["productsTotal"]) == (50, 60)
    assert (len(card["applicability"]), card["applicabilityTotal"]) == (50, 60)
    assert card["distroStatusesTotal"] == 0
    service.shutdown()


def test_the_knowledge_base_cache_keeps_a_none_answer(kb):
    moment = utcnow_naive()
    kb.save_osint_cache("shodan", _ADDRESS, None, moment)
    kb.save_osint_cache("shodan", _ADDRESS, None, moment)

    assert kb.get_osint_cache("shodan", _ADDRESS) == (None, moment)
    assert kb.get_osint_cache("shodan", "1.1.1.1") is None
