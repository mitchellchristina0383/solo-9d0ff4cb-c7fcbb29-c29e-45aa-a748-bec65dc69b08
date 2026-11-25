"""吊销核查测试：清单上传核验、单调替换、并发安全、快照隔离与逐副本判定。"""

from __future__ import annotations

import datetime
import json
import pathlib
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.app import create_app
from app.crlstore import CRLError, CRLStore
from app.revocation import evaluate_replica, run_check

SAMPLES = pathlib.Path(__file__).resolve().parent.parent / "samples_test"
HOUR = datetime.timedelta(hours=1)
DAY = datetime.timedelta(days=1)


# ---------------------------------------------------------------------- #
# 测试材料构造
# ---------------------------------------------------------------------- #
def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cn(name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def pem(obj) -> str:
    return obj.public_bytes(serialization.Encoding.PEM).decode("ascii")


def make_ca(cn: str = "Test CA", key: rsa.RSAPrivateKey | None = None):
    """自签名 CA；同 cn 多次调用可模拟同名换钥。"""
    key = key or _key()
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_cn(cn))
        .issuer_name(_cn(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + 365 * DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_leaf(serial: int, ca_cert, ca_key, cn: str = "leaf"):
    key = _key()
    now = _now()
    return (
        x509.CertificateBuilder()
        .subject_name(_cn(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - DAY)
        .not_valid_after(now + 90 * DAY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


def make_crl(
    ca_cert,
    ca_key,
    number: int = 1,
    serials=(),
    last: datetime.datetime | None = None,
    next_: datetime.datetime | None = None,
    delta: bool = False,
    omit_number: bool = False,
):
    now = _now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(last or (now - HOUR))
        .next_update(next_ or (now + 7 * DAY))
    )
    if not omit_number:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    if delta:
        builder = builder.add_extension(x509.DeltaCRLIndicator(number), critical=False)
    for serial in serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now - 2 * HOUR)
            .build()
        )
    return builder.sign(ca_key, hashes.SHA256())


@pytest.fixture(scope="session")
def revo_data(sample_data):
    """样例脚本生成的吊销核查材料（依赖 conftest 的样例生成）。"""
    return json.loads((SAMPLES / "revocation-sample.json").read_text(encoding="utf-8"))


@pytest.fixture()
def store(tmp_path):
    return CRLStore(tmp_path / "crls")


# ---------------------------------------------------------------------- #
# 上传核验
# ---------------------------------------------------------------------- #
def test_upload_valid_crl_stored(store):
    ca, key = make_ca()
    crl = make_crl(ca, key, 1, [1001, 1002])
    outcome = store.upload(pem(ca), pem(crl))
    assert outcome.accepted and outcome.action == "stored"
    records = store.list_records()
    assert len(records) == 1
    assert records[0]["crl_number"] == 1
    assert records[0]["revoked_count"] == 2
    assert records[0]["ca_name"] == "CN=Test CA"


def test_upload_rejects_issuer_name_mismatch(store):
    ca1, key1 = make_ca("CA One")
    ca2, _ = make_ca("CA Two")
    crl = make_crl(ca1, key1, 1)
    with pytest.raises(CRLError, match="颁发者不符"):
        store.upload(pem(ca2), pem(crl))


def test_upload_rejects_bad_signature_same_name(store):
    # 同名 CA 换钥场景：清单由旧钥签发，却附上新钥证书 → 签名验不过
    ca_old, key_old = make_ca("Same Name CA")
    ca_new, _ = make_ca("Same Name CA")
    crl = make_crl(ca_old, key_old, 1)
    with pytest.raises(CRLError, match="签名验不过"):
        store.upload(pem(ca_new), pem(crl))


def test_upload_rejects_delta_crl(store):
    ca, key = make_ca()
    crl = make_crl(ca, key, 3, delta=True)
    with pytest.raises(CRLError, match="增量清单"):
        store.upload(pem(ca), pem(crl))


def test_upload_rejects_expired_and_not_yet_valid(tmp_path):
    ca, key = make_ca()
    now = _now()
    expired = make_crl(ca, key, 1, last=now - 10 * DAY, next_=now - DAY)
    with pytest.raises(CRLError, match="已过期"):
        CRLStore(tmp_path / "a").upload(pem(ca), pem(expired))
    future = make_crl(ca, key, 1, last=now + DAY, next_=now + 2 * DAY)
    with pytest.raises(CRLError, match="尚未生效"):
        CRLStore(tmp_path / "b").upload(pem(ca), pem(future))


def test_upload_rejects_missing_crl_number(store):
    ca, key = make_ca()
    crl = make_crl(ca, key, omit_number=True)
    with pytest.raises(CRLError, match="编号"):
        store.upload(pem(ca), pem(crl))


def test_upload_rejects_non_ca_cert(store):
    ca, key = make_ca()
    leaf = make_leaf(9001, ca, key)
    crl = make_crl(ca, key, 1)
    with pytest.raises(CRLError, match="CA"):
        store.upload(pem(leaf), pem(crl))


def test_upload_rejects_malformed_input(store):
    ca, key = make_ca()
    crl_pem = pem(make_crl(ca, key, 1))
    with pytest.raises(CRLError):
        store.upload("not a pem", crl_pem)
    with pytest.raises(CRLError, match="一次只上传一张"):
        store.upload(pem(ca), crl_pem + crl_pem)
    with pytest.raises(CRLError, match="X509 CRL"):
        store.upload(pem(ca), "-----BEGIN CERTIFICATE-----")


# ---------------------------------------------------------------------- #
# 单调替换规则
# ---------------------------------------------------------------------- #
def test_monotonic_replace_rules(store):
    ca, key = make_ca()
    ca_pem = pem(ca)
    crl1a = pem(make_crl(ca, key, 1, [1001]))
    crl1b = pem(make_crl(ca, key, 1, [1002]))  # 同号不同内容
    crl2 = pem(make_crl(ca, key, 2, [1001, 1002]))

    assert store.upload(ca_pem, crl1a).action == "stored"
    original = store.list_records()[0]["der_sha256"]

    # 同号同内容：可重传，不报变更
    again = store.upload(ca_pem, crl1a)
    assert again.accepted and again.action == "unchanged"

    # 同号不同内容：拒绝，保留现行
    conflict = store.upload(ca_pem, crl1b)
    assert not conflict.accepted and conflict.action == "rejected"
    assert "内容不同" in conflict.message
    assert store.list_records()[0]["der_sha256"] == original

    # 编号更大：替换
    updated = store.upload(ca_pem, crl2)
    assert updated.accepted and updated.action == "updated"

    # 编号更小：拒绝，保留现行
    lower = store.upload(ca_pem, crl1a)
    assert not lower.accepted and "低于现行编号" in lower.message
    current = store.list_records()
    assert len(current) == 1 and current[0]["crl_number"] == 2


# ---------------------------------------------------------------------- #
# 并发上传（两个 Store 实例模拟 gunicorn 多 worker）
# ---------------------------------------------------------------------- #
def test_concurrent_uploads_keep_current(tmp_path):
    ca, key = make_ca()
    ca_pem = pem(ca)
    crl1 = pem(make_crl(ca, key, 1, [1001]))
    crl2 = pem(make_crl(ca, key, 2, [1001, 1002]))
    crl2_alt = pem(make_crl(ca, key, 2, [1003]))  # 同号不同内容

    directory = tmp_path / "shared"
    store_a = CRLStore(directory)
    store_b = CRLStore(directory)  # 第二个实例 ≈ 另一个进程
    assert store_a.upload(ca_pem, crl2).action == "stored"
    original = store_a.list_records()[0]["der_sha256"]

    tasks = [
        (store_a, crl1),
        (store_b, crl1),
        (store_a, crl2_alt),
        (store_b, crl2_alt),
        (store_a, crl2),
        (store_b, crl2),
    ]
    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(lambda t: t[0].upload(ca_pem, t[1]), tasks))

    rejected = [o for o in outcomes if not o.accepted]
    unchanged = [o for o in outcomes if o.action == "unchanged"]
    assert len(rejected) == 4  # 2 张低编号 + 2 张同号不同内容
    assert len(unchanged) == 2  # 同号同内容可重传
    final = store_a.list_records()
    assert len(final) == 1
    assert final[0]["crl_number"] == 2
    assert final[0]["der_sha256"] == original  # 现行清单未被并发破坏


def test_concurrent_first_upload_stores_once(tmp_path):
    ca, key = make_ca()
    ca_pem = pem(ca)
    crl1 = pem(make_crl(ca, key, 1, [1001]))
    directory = tmp_path / "shared"
    stores = [CRLStore(directory) for _ in range(6)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(lambda s: s.upload(ca_pem, crl1), stores))
    actions = sorted(o.action for o in outcomes)
    assert actions == ["stored"] + ["unchanged"] * 5
    assert len(CRLStore(directory).list_records()) == 1


def test_concurrent_race_highest_number_wins(tmp_path):
    ca, key = make_ca()
    ca_pem = pem(ca)
    crl1 = pem(make_crl(ca, key, 1, [1001]))
    crl2 = pem(make_crl(ca, key, 2, [1001, 1002]))
    directory = tmp_path / "shared"
    stores = [CRLStore(directory) for _ in range(6)]
    crls = [crl1, crl2, crl2, crl1, crl2, crl1]
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda t: t[0].upload(ca_pem, t[1]), zip(stores, crls)))
    final = CRLStore(directory).list_records()
    assert len(final) == 1 and final[0]["crl_number"] == 2


# ---------------------------------------------------------------------- #
# 逐副本核查
# ---------------------------------------------------------------------- #
def test_sample_check_statuses(revo_data, store):
    outcome = store.upload(revo_data["crls"][0]["ca_pem"], revo_data["crls"][0]["crl_pem"])
    assert outcome.action == "stored"
    result = run_check(revo_data["replicas"], store.snapshot())
    by_name = {r["name"]: r for r in result["results"]}
    assert result["checked_at"]
    assert by_name["svc-a"]["status"] == "not_listed"
    assert by_name["svc-b"]["status"] == "revoked"
    assert by_name["svc-b"]["revoked_at"]
    assert by_name["svc-c"]["status"] == "not_listed"
    # 旧中间 CA 没有上传过清单 → 待核实
    assert by_name["svc-a-old"]["status"] == "pending"
    assert "找不到匹配清单" in by_name["svc-a-old"]["reason"]
    #  decisive 行标明所用清单编号
    assert by_name["svc-a"]["crl_number"] == 1
    assert by_name["svc-b"]["crl_number"] == 1


def test_check_issuance_failures_are_pending(revo_data, store):
    store.upload(revo_data["crls"][0]["ca_pem"], revo_data["crls"][0]["crl_pem"])
    snap = store.snapshot()
    good = revo_data["replicas"][0]

    # 颁发者名称不符：把颁发 CA 换成旧中间 CA
    row = dict(good, issuer_pem=revo_data["replicas"][3]["issuer_pem"])
    res = evaluate_replica(row, snap)
    assert res["status"] == "pending" and "颁发关系验不过" in res["reason"]

    # 同名不同钥：名称一致但签名验不过（换钥 CA 的证书）
    row = dict(good, issuer_pem=revo_data["rotated"]["ca_pem"])
    res = evaluate_replica(row, snap)
    assert res["status"] == "pending" and "颁发关系验不过" in res["reason"]

    # 叶子无法解析
    res = evaluate_replica(dict(good, leaf_pem="garbage"), snap)
    assert res["status"] == "pending" and "解析失败" in res["reason"]


def test_check_expired_crl_is_pending(store):
    ca, key = make_ca()
    leaf = make_leaf(7001, ca, key)
    now = _now()
    crl = make_crl(ca, key, 1, [7001], last=now - 2 * HOUR, next_=now + HOUR)
    assert store.upload(pem(ca), pem(crl)).accepted
    snap = store.snapshot()
    row = {"name": "x", "leaf_pem": pem(leaf), "issuer_pem": pem(ca)}

    in_window = evaluate_replica(row, snap, now=now)
    assert in_window["status"] == "revoked"

    expired = evaluate_replica(row, snap, now=now + 2 * HOUR)
    assert expired["status"] == "pending" and "已过期" in expired["reason"]

    too_early = evaluate_replica(row, snap, now=now - 3 * HOUR)
    assert too_early["status"] == "pending" and "尚未生效" in too_early["reason"]


def test_snapshot_isolated_from_upload_during_check(revo_data, store):
    """核查轮次固定开始时的清单：核查中上传新清单不影响本轮。"""
    ca_pem = revo_data["crls"][0]["ca_pem"]
    store.upload(ca_pem, revo_data["crls"][0]["crl_pem"])  # 清单 #1
    rows = revo_data["replicas"]
    snap = store.snapshot()  # 本轮开始，固定清单与时刻

    barrier = threading.Event()
    holder: dict = {}

    def evaluate_round():
        barrier.wait(timeout=5)
        holder["round"] = run_check(rows, snap)

    worker = threading.Thread(target=evaluate_round)
    worker.start()
    # 模拟核查进行中并发上传了清单 #2
    outcome = store.upload(ca_pem, revo_data["crls"][1]["crl_pem"])
    assert outcome.action == "updated"
    barrier.set()
    worker.join(timeout=5)

    round1 = {r["name"]: r for r in holder["round"]["results"]}
    # 本轮仍用清单 #1：svc-c 未被吊销
    assert round1["svc-c"]["status"] == "not_listed"
    assert round1["svc-c"]["crl_number"] == 1

    # 下一轮取新快照：清单 #2 生效，svc-c 已吊销
    round2 = {r["name"]: r for r in run_check(rows, store.snapshot())["results"]}
    assert round2["svc-c"]["status"] == "revoked"
    assert round2["svc-c"]["crl_number"] == 2


def test_same_name_ca_key_rotation(store):
    """同名 CA 换钥：两张清单按公钥分别保存，核查按公钥匹配。"""
    ca_v1, key_v1 = make_ca("Rotated CA")
    ca_v2, key_v2 = make_ca("Rotated CA")  # 同名不同钥
    leaf1 = make_leaf(5001, ca_v1, key_v1)
    leaf2 = make_leaf(5002, ca_v2, key_v2)

    assert store.upload(pem(ca_v1), pem(make_crl(ca_v1, key_v1, 5, [5001]))).accepted
    assert store.upload(pem(ca_v2), pem(make_crl(ca_v2, key_v2, 1, []))).accepted

    records = store.list_records()
    assert len(records) == 2  # 同名两张清单并存
    assert {r["ca_name"] for r in records} == {"CN=Rotated CA"}
    assert len({r["key_fingerprint"] for r in records}) == 2

    snap = store.snapshot()
    r1 = evaluate_replica(
        {"name": "r1", "leaf_pem": pem(leaf1), "issuer_pem": pem(ca_v1)}, snap
    )
    assert r1["status"] == "revoked" and r1["crl_number"] == 5
    r2 = evaluate_replica(
        {"name": "r2", "leaf_pem": pem(leaf2), "issuer_pem": pem(ca_v2)}, snap
    )
    assert r2["status"] == "not_listed" and r2["crl_number"] == 1
    # 错配：旧钥签的叶子 + 新钥证书 → 颁发关系验不过
    r3 = evaluate_replica(
        {"name": "r3", "leaf_pem": pem(leaf1), "issuer_pem": pem(ca_v2)}, snap
    )
    assert r3["status"] == "pending" and "颁发关系验不过" in r3["reason"]


# ---------------------------------------------------------------------- #
# 持久化（重启后保留）
# ---------------------------------------------------------------------- #
def test_persistence_across_store_instances(tmp_path):
    ca, key = make_ca()
    crl = pem(make_crl(ca, key, 7, [1001]))
    directory = tmp_path / "persist"
    assert CRLStore(directory).upload(pem(ca), crl).action == "stored"
    # 新实例（≈ 进程重启）重新加载
    reopened = CRLStore(directory)
    records = reopened.list_records()
    assert len(records) == 1 and records[0]["crl_number"] == 7
    # 重启后单调规则仍然生效
    lower = reopened.upload(pem(ca), pem(make_crl(ca, key, 6, [])))
    assert not lower.accepted


def test_persistence_across_app_instances(revo_data, tmp_path):
    directory = str(tmp_path / "crls")
    app1 = create_app({"CRL_DATA_DIR": directory})
    client1 = app1.test_client()
    resp = client1.post(
        "/api/crl/upload",
        json={
            "ca_pem": revo_data["crls"][0]["ca_pem"],
            "crl_pem": revo_data["crls"][0]["crl_pem"],
        },
    )
    assert resp.status_code == 200
    # 模拟重启：新建 app 实例指向同一数据目录
    app2 = create_app({"CRL_DATA_DIR": directory})
    client2 = app2.test_client()
    data = client2.get("/api/crls").get_json()
    assert data["ok"] and len(data["crls"]) == 1
    assert data["crls"][0]["crl_number"] == 1


# ---------------------------------------------------------------------- #
# Flask API
# ---------------------------------------------------------------------- #
@pytest.fixture()
def client(tmp_path):
    app = create_app({"CRL_DATA_DIR": str(tmp_path / "crls")})
    app.testing = True
    return app.test_client()


def test_revocation_page_renders(client):
    resp = client.get("/revocation")
    assert resp.status_code == 200
    assert "吊销清单核查".encode() in resp.data


def test_revocation_sample_api(client):
    resp = client.get("/api/revocation/sample")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["replicas"]) >= 1
    assert len(data["crls"]) >= 1


def test_crl_summary_api(client, revo_data):
    resp = client.post(
        "/api/summaries",
        json={"kind": "crl", "pem": revo_data["crls"][0]["crl_pem"]},
    )
    data = resp.get_json()
    assert data["ok"]
    assert data["summary"]["crl_number"] == 1
    assert data["summary"]["revoked_count"] == 1
    assert data["summary"]["is_delta"] is False

    resp = client.post("/api/summaries", json={"kind": "crl", "pem": "junk"})
    assert resp.get_json()["ok"] is False


def test_upload_api_flow(client, revo_data):
    # 空字段 → 400
    resp = client.post("/api/crl/upload", json={"ca_pem": "", "crl_pem": ""})
    assert resp.status_code == 400
    # 非法 PEM → 400
    resp = client.post("/api/crl/upload", json={"ca_pem": "junk", "crl_pem": "junk"})
    assert resp.status_code == 400
    # 正常上传 → stored
    ca_pem = revo_data["crls"][0]["ca_pem"]
    resp = client.post(
        "/api/crl/upload",
        json={"ca_pem": ca_pem, "crl_pem": revo_data["crls"][0]["crl_pem"]},
    )
    assert resp.status_code == 200
    assert resp.get_json()["action"] == "stored"
    # 同号同内容 → unchanged
    resp = client.post(
        "/api/crl/upload",
        json={"ca_pem": ca_pem, "crl_pem": revo_data["crls"][0]["crl_pem"]},
    )
    assert resp.status_code == 200
    assert resp.get_json()["action"] == "unchanged"
    # 编号更大 → updated
    resp = client.post(
        "/api/crl/upload",
        json={"ca_pem": ca_pem, "crl_pem": revo_data["crls"][1]["crl_pem"]},
    )
    assert resp.status_code == 200
    assert resp.get_json()["action"] == "updated"
    # 低编号 → 409 且附现行清单
    resp = client.post(
        "/api/crl/upload",
        json={"ca_pem": ca_pem, "crl_pem": revo_data["crls"][0]["crl_pem"]},
    )
    assert resp.status_code == 409
    data = resp.get_json()
    assert data["ok"] is False and data["current"]["crl_number"] == 2


def test_check_api(client, revo_data):
    # 空表单 → 400
    resp = client.post("/api/crl/check", json={"replicas": []})
    assert resp.status_code == 400
    # 上传清单后核查
    client.post(
        "/api/crl/upload",
        json={
            "ca_pem": revo_data["crls"][0]["ca_pem"],
            "crl_pem": revo_data["crls"][0]["crl_pem"],
        },
    )
    resp = client.post("/api/crl/check", json={"replicas": revo_data["replicas"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] and data["checked_at"]
    by_name = {r["name"]: r for r in data["results"]}
    assert by_name["svc-b"]["status"] == "revoked"
    assert by_name["svc-a"]["status"] == "not_listed"
    assert by_name["svc-a-old"]["status"] == "pending"
    # 超过 8 行 → 400
    too_many = [revo_data["replicas"][0]] * 9
    resp = client.post("/api/crl/check", json={"replicas": too_many})
    assert resp.status_code == 400


def test_crls_list_api(client, revo_data):
    data = client.get("/api/crls").get_json()
    assert data["ok"] and data["crls"] == []
    client.post(
        "/api/crl/upload",
        json={
            "ca_pem": revo_data["crls"][0]["ca_pem"],
            "crl_pem": revo_data["crls"][0]["crl_pem"],
        },
    )
    # 同名换钥 CA 的清单单独保存
    client.post(
        "/api/crl/upload",
        json={
            "ca_pem": revo_data["rotated"]["ca_pem"],
            "crl_pem": revo_data["rotated"]["crl_pem"],
        },
    )
    data = client.get("/api/crls").get_json()
    assert len(data["crls"]) == 2
    assert len({c["key_fingerprint"] for c in data["crls"]}) == 2
    assert len({c["ca_name"] for c in data["crls"]}) == 1  # 同名
