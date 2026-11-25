"""生成可在网页直接试跑的一套 HTTPS 根证书更换样例。

层级（新旧两套完全独立的 PKI）::

    old-root CA ── old-intermediate CA ── 各副本旧叶子证书
    new-root CA ── new-intermediate CA ── 各副本新叶子证书（相同 SAN）

产物（默认写入 samples/）：
  roots/        旧/新根 CA 自签名证书
  intermediates/旧/新中间 CA 证书
  replicas/     每个副本的旧链、新链（叶子 + 中间，PEM 拼接）
  bundles/      终端旧根包、新根包、并集过渡包
  revocation/   吊销核查样例：颁发 CA、两张递进编号的 CRL、同名换钥 CA 及其 CRL
  sample.json   换证顺序规划页表单预填数据
  revocation-sample.json  吊销核查页表单预填数据

样例只用于本地演示：私钥同样落盘，但全部为本地临时测试用途。
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

REPLICA_DOMAINS = [
    ("svc-a", "svc-a.internal.example"),
    ("svc-b", "svc-b.internal.example"),
    ("svc-c", "svc-c.internal.example"),
]


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str, ou: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS Rotation Demo"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _save(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


def make_root(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(cn, "Root CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_intermediate(
    cn: str,
    root_cert: x509.Certificate,
    root_key: rsa.RSAPrivateKey,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(cn, "Intermediate CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return cert, key


def make_leaf(
    cn: str,
    dns_names: list[str],
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn, "Service"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=398))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in dns_names]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return cert


def _pem_crl(crl: x509.CertificateRevocationList) -> str:
    return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


def make_crl(
    number: int,
    revoked_serials: list[int],
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
) -> x509.CertificateRevocationList:
    """签发一张完整 CRL（带 CRL 编号，有效期 提前 1 小时 ~ 30 天后）。"""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=30))
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now - datetime.timedelta(days=1))
            .build()
        )
    return builder.sign(issuer_key, hashes.SHA256())


def generate(out_dir: str | os.PathLike = "samples") -> pathlib.Path:
    out = pathlib.Path(out_dir)

    old_root, old_root_key = make_root("Demo Old Root CA")
    new_root, new_root_key = make_root("Demo New Root CA")
    old_int, old_int_key = make_intermediate(
        "Demo Old Intermediate CA", old_root, old_root_key
    )
    new_int, new_int_key = make_intermediate(
        "Demo New Intermediate CA", new_root, new_root_key
    )

    _save(out / "roots" / "old-root.pem", _pem_cert(old_root))
    _save(out / "roots" / "new-root.pem", _pem_cert(new_root))
    _save(out / "intermediates" / "old-intermediate.pem", _pem_cert(old_int))
    _save(out / "intermediates" / "new-intermediate.pem", _pem_cert(new_int))

    old_bundle = _pem_cert(old_root)
    new_bundle = _pem_cert(new_root)
    union_bundle = old_bundle + new_bundle
    _save(out / "bundles" / "old-bundle.pem", old_bundle)
    _save(out / "bundles" / "new-bundle.pem", new_bundle)
    _save(out / "bundles" / "union-bundle.pem", union_bundle)

    sample = {"replicas": [], "batches": [], "max_transition": 3}
    old_leaves: dict[str, x509.Certificate] = {}
    new_leaves: dict[str, x509.Certificate] = {}
    for idx, (label, domain) in enumerate(REPLICA_DOMAINS, start=1):
        old_leaf = make_leaf(domain, [domain], old_int, old_int_key)
        new_leaf = make_leaf(domain, [domain], new_int, new_int_key)
        old_leaves[label] = old_leaf
        new_leaves[label] = new_leaf
        old_chain = _pem_cert(old_leaf) + _pem_cert(old_int)
        new_chain = _pem_cert(new_leaf) + _pem_cert(new_int)
        _save(out / "replicas" / label / "old-chain.pem", old_chain)
        _save(out / "replicas" / label / "new-chain.pem", new_chain)
        sample["replicas"].append(
            {
                "name": label,
                "domain": domain,
                "old_chain": old_chain,
                "new_chain": new_chain,
            }
        )

    # 3 批终端共享同样的旧包/新包，但页面允许各批粘贴不同内容
    for idx in range(1, 4):
        sample["batches"].append(
            {
                "name": f"终端批次{idx}",
                "old_bundle": old_bundle,
                "new_bundle": new_bundle,
            }
        )

    meta_path = out / "sample.json"
    meta_path.write_text(json.dumps(sample, ensure_ascii=False, indent=2), "utf-8")

    # ---------------- 吊销核查样例 ----------------
    # 新中间 CA 的两张递进清单：#1 吊销 svc-b，#2 再吊销 svc-c（演示清单更新）
    crl1 = make_crl(1, [new_leaves["svc-b"].serial_number], new_int, new_int_key)
    crl2 = make_crl(
        2,
        [new_leaves["svc-b"].serial_number, new_leaves["svc-c"].serial_number],
        new_int,
        new_int_key,
    )
    # 同名换钥 CA：与新中间 CA 同名但密钥不同，演示按「CA 名称+公钥」分别保存
    rotated_int, rotated_int_key = make_intermediate(
        "Demo New Intermediate CA", new_root, new_root_key
    )
    rotated_crl1 = make_crl(1, [], rotated_int, rotated_int_key)

    revo_dir = out / "revocation"
    _save(revo_dir / "issuer-ca.pem", _pem_cert(new_int))
    _save(revo_dir / "crl-1.pem", _pem_crl(crl1))
    _save(revo_dir / "crl-2.pem", _pem_crl(crl2))
    _save(revo_dir / "rotated-issuer-ca.pem", _pem_cert(rotated_int))
    _save(revo_dir / "rotated-issuer-crl-1.pem", _pem_crl(rotated_crl1))

    revo_sample = {
        "replicas": [
            # svc-a-old 的颁发 CA（旧中间 CA）没有对应清单，核查时恒为“待核实”
            {
                "name": label,
                "leaf_pem": _pem_cert(new_leaves[label]),
                "issuer_pem": _pem_cert(new_int),
            }
            for label, _ in REPLICA_DOMAINS
        ]
        + [
            {
                "name": "svc-a-old",
                "leaf_pem": _pem_cert(old_leaves["svc-a"]),
                "issuer_pem": _pem_cert(old_int),
            }
        ],
        "crls": [
            {
                "label": "清单 #1（吊销 svc-b）",
                "ca_pem": _pem_cert(new_int),
                "crl_pem": _pem_crl(crl1),
            },
            {
                "label": "清单 #2（吊销 svc-b、svc-c）",
                "ca_pem": _pem_cert(new_int),
                "crl_pem": _pem_crl(crl2),
            },
        ],
        "rotated": {
            "label": "同名换钥 CA 的清单 #1（空清单）",
            "ca_pem": _pem_cert(rotated_int),
            "crl_pem": _pem_crl(rotated_crl1),
        },
    }
    (out / "revocation-sample.json").write_text(
        json.dumps(revo_sample, ensure_ascii=False, indent=2), "utf-8"
    )
    return meta_path


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "samples"
    path = generate(target)
    print(f"样例证书已生成: {path.resolve()}")
