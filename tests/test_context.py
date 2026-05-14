import src.analysis.context as context


def test_detect_local_ips_includes_loopback(monkeypatch):
    monkeypatch.setattr(context.socket, "gethostname", lambda: "host")

    def fake_gethostbyname_ex(hostname):
        return hostname, [], ["192.168.1.10"]

    monkeypatch.setattr(context.socket, "gethostbyname_ex", fake_gethostbyname_ex)

    ips = context.detect_local_ips()

    assert "127.0.0.1" in ips
    assert "192.168.1.10" in ips
