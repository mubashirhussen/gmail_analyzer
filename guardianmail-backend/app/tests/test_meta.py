from fastapi.testclient import TestClient


def test_healthz(client: TestClient):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_livez(client: TestClient):
    r = client.get("/livez")
    assert r.status_code == 200


def test_version(client: TestClient):
    r = client.get("/version")
    body = r.json()
    assert r.status_code == 200
    assert body["name"] and body["version"]
