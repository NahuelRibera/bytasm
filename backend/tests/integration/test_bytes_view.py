from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64


def test_byte_window_exact_bounds_and_integrity(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        data = ELF_X86_64.read_bytes()
        version = do_import(client, create_project(client), data).json()["sample_version"]
        url = f"/api/v1/sample-versions/{version['id']}/bytes"
        result = client.get(url, params={"offset": 17, "length": 32})
        assert result.status_code == 200, result.text
        assert bytes.fromhex(result.json()["hex"]) == data[17:49]
        assert result.json()["offset"] == 17
        assert client.get(url, params={"offset": -1}).status_code == 422
        assert client.get(url, params={"length": 4097}).status_code == 422
        assert client.get(url, params={"offset": len(data) + 1}).status_code == 422
        tail = client.get(url, params={"offset": len(data) - 1, "length": 32}).json()
        assert tail["length"] == 1 and tail["eof"] is True
        path = ctx_of(client).blobs.path(version["sha256"])
        path.chmod(0o600)
        path.write_bytes(b"corrupt")
        assert client.get(url).status_code == 409
