"""M7 CLI commands against a copied knowledge tree."""

from __future__ import annotations

from pathlib import Path

from m7_fixtures import copy_knowledge, invoke, payload


def test_cli_list_ingest_release_query_tombstone(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    args = ["--knowledge-root", str(root)]
    code, output = invoke(["knowledge", "list-sources", *args])
    assert code == 0, output
    listed = payload(output)
    assert listed["ok"] is True
    sources = listed["result"]["sources"]
    assert any(item["source_id"] == "zeroskills" for item in sources)
    code, output = invoke(["knowledge", "ingest", "zeroskills", *args])
    assert code == 0, output
    code, output = invoke(["knowledge", "ingest", "solodit", *args])
    assert code == 0, output
    code, output = invoke(["knowledge", "ingest", "0xsimao", *args])
    assert code == 0, output
    code, output = invoke(["knowledge", "ingest", "krait", *args])
    assert code == 0, output
    code, output = invoke(["knowledge", "release", "--version", "v0.1.0", *args])
    assert code == 0, output
    released = payload(output)["result"]
    assert released["content_hash"].startswith("sha256:")
    code, output = invoke(["knowledge", "status", *args])
    assert code == 0, output
    status = payload(output)["result"]
    assert status["record_counts"]
    code, output = invoke(
        [
            "knowledge",
            "query",
            "--type",
            "mechanism",
            "--filter",
            '{"language": "solidity"}',
            *args,
        ]
    )
    assert code == 0, output
    queried = payload(output)["result"]
    assert queried["count"] >= 1
    code, output = invoke(
        ["knowledge", "tombstone", "krait", "--reason", "revoked", "--version", "v0.1.1", *args]
    )
    assert code == 0, output
    code, output = invoke(["knowledge", "query", "--type", "method", "--filter", "{}", *args])
    assert code == 0, output
    methods = payload(output)["result"]["records"]
    assert all(item["source_ref"]["source_id"] != "krait" for item in methods)
