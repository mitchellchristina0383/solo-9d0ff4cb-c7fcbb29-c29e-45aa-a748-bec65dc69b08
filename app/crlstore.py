"""内网 CA 吊销清单（CRL）的核验、并发安全存储与快照。

设计要点
========
* 上传即核验：只接受 PEM 编码、覆盖该 CA 全部直签证书的**完整**清单
  （拒绝增量清单与 IssuingDistributionPoint 限定范围的清单），并核对
  颁发者、签名、清单编号（CRL Number）与有效期（thisUpdate/nextUpdate）；
* 按 “CA 名称 + CA 公钥” 定位清单：同名 CA 换钥后新旧清单各自独立，
  互不覆盖；
* 单调替换：只接受编号更大的清单；编号更小、或同号但内容不同的上传一律
  拒绝并保留现行清单；同号同内容可重复上传（幂等，不报变更）；
* 并发安全：线程锁 + 文件锁（``fcntl.flock``），多线程与多进程
  （gunicorn 多 worker）下 “读取-比较-替换” 整体原子；落盘采用
  临时文件 + ``os.replace``，不会写出半个文件；
* 持久化：每张清单一份 JSON 文件存于数据目录，进程重启后重新加载；
* 快照：每轮核查开始时取一次快照（同时固定核验时刻），核查进行期间的
  新上传不影响本轮结果。

所有 PEM 数据均视为不可信外部输入，解析失败一律抛出 :class:`CRLError`。
"""

from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import re
import threading
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from .certutil import PemError, cert_subject, extract_certs

_CRL_PEM_RE = re.compile(
    rb"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----",
    re.DOTALL,
)

TIME_FMT = "%Y-%m-%d %H:%M UTC"


class CRLError(PemError):
    """CRL 或所附 CA 证书无法通过核验时抛出。"""


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def fmt_time(dt: datetime.datetime) -> str:
    return dt.strftime(TIME_FMT)


def verify_signature(signed, tbs: bytes, public_key, what: str) -> None:
    """用 ``public_key`` 核验证书/CRL 的签名，失败抛 :class:`CRLError`。

    ``signed`` 为 Certificate 或 CertificateRevocationList，需具备
    ``signature`` / ``signature_hash_algorithm`` 属性；若运行库提供
    ``signature_algorithm_parameters``（如 RSA-PSS），优先使用。
    """
    hash_alg = signed.signature_hash_algorithm
    params = getattr(signed, "signature_algorithm_parameters", None)
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            pad = params if isinstance(
                params, (padding.PKCS1v15, padding.PSS)
            ) else padding.PKCS1v15()
            public_key.verify(signed.signature, tbs, pad, hash_alg)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signed.signature, tbs, ec.ECDSA(hash_alg))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signed.signature, tbs)
        else:
            raise CRLError(f"不支持的公钥类型 {type(public_key).__name__}")
    except InvalidSignature as exc:
        raise CRLError(f"{what}验不过") from exc


def record_key_for_cert(ca_cert: x509.Certificate) -> str:
    """清单存储键：CA 主题名（DER）+ CA 公钥（SPKI DER）的摘要。

    同名 CA 换钥后公钥不同，键也不同，新旧清单因此各自独立保存。
    """
    spki = ca_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h = hashlib.sha256()
    h.update(ca_cert.subject.public_bytes())
    h.update(b"\x00")
    h.update(spki)
    return h.hexdigest()


def key_fingerprint(ca_cert: x509.Certificate) -> str:
    """CA 公钥指纹（SHA-256 of SPKI DER），用于界面区分同名不同钥的 CA。"""
    spki = ca_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _parse_single_crl(crl_pem: str) -> x509.CertificateRevocationList:
    if not crl_pem or not crl_pem.strip():
        raise CRLError("CRL 内容为空")
    blobs = _CRL_PEM_RE.findall(crl_pem.encode("utf-8", errors="replace"))
    if not blobs:
        raise CRLError("未找到 PEM 编码的吊销清单（需要 -----BEGIN X509 CRL----- 块）")
    if len(blobs) > 1:
        raise CRLError("一次只上传一张清单（检测到多个 CRL 块）")
    try:
        return x509.load_pem_x509_crl(blobs[0])
    except Exception as exc:
        raise CRLError(f"CRL 解析失败: {exc}") from exc


def _validate_ca_cert(ca_pem: str) -> x509.Certificate:
    try:
        certs = extract_certs(ca_pem)
    except PemError as exc:
        raise CRLError(f"颁发 CA 证书解析失败: {exc}") from exc
    if len(certs) != 1:
        raise CRLError(f"颁发 CA 证书须恰好 1 张（检测到 {len(certs)} 张）")
    ca = certs[0]
    try:
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise CRLError("所附证书缺少 BasicConstraints，不是 CA 证书") from None
    if not bc.ca:
        raise CRLError("所附证书 BasicConstraints 未标记为 CA")
    try:
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.crl_sign:
            raise CRLError("所附 CA 证书 KeyUsage 不含 cRLSign，无权签发清单")
    except x509.ExtensionNotFound:
        pass  # 未声明 KeyUsage 的 CA 不额外限制
    return ca


def _validate_crl(
    crl: x509.CertificateRevocationList,
    ca: x509.Certificate,
    now: datetime.datetime,
) -> int:
    """核对颁发者、签名、完整性、编号与有效期，返回清单编号。"""
    # 1) 颁发者：清单 issuer 必须与所附 CA 主题完全一致
    if crl.issuer.public_bytes() != ca.subject.public_bytes():
        raise CRLError(
            "颁发者不符：清单颁发者为 "
            f"{crl.issuer.rfc4514_string()}，所附 CA 主题为 "
            f"{ca.subject.rfc4514_string()}"
        )
    # 2) 签名：用所附 CA 公钥核验清单签名
    verify_signature(crl, crl.tbs_certlist_bytes, ca.public_key(), "清单签名")
    # 3) 完整性：拒绝增量清单与限定范围的清单
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        raise CRLError("只收完整清单，不收增量清单（含 Delta CRL Indicator）")
    except x509.ExtensionNotFound:
        pass
    try:
        idp = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        ).value
        if (
            idp.only_contains_user_certs
            or idp.only_contains_ca_certs
            or idp.only_contains_attribute_certs
            or idp.only_some_reasons
            or idp.indirect_crl
        ):
            raise CRLError(
                "只收覆盖该 CA 全部直签证书的完整清单"
                "（IssuingDistributionPoint 限定了范围）"
            )
    except x509.ExtensionNotFound:
        pass
    # 4) 编号：CRL Number 扩展必须存在，作为单调比较依据
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        raise CRLError("清单缺少 CRL 编号（CRL Number）扩展") from None
    # 5) 有效期：thisUpdate <= now <= nextUpdate
    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    if next_update is None:
        raise CRLError("清单缺少 nextUpdate，无法核对有效期")
    if now < this_update:
        raise CRLError(f"清单尚未生效（thisUpdate {fmt_time(this_update)}）")
    if now > next_update:
        raise CRLError(f"清单已过期（nextUpdate {fmt_time(next_update)}）")
    return number


@dataclass(frozen=True)
class StoredCRL:
    """一张已保存清单及其元数据（crl 为解析后的对象，不落盘）。"""

    key: str
    ca_name: str
    key_fingerprint: str
    crl_number: int
    this_update: datetime.datetime
    next_update: datetime.datetime
    der_sha256: str
    stored_at: str  # ISO 格式
    revoked_count: int
    ca_pem: str
    crl_pem: str
    crl: x509.CertificateRevocationList = field(compare=False)

    def summary(self) -> dict:
        return {
            "key": self.key,
            "ca_name": self.ca_name,
            "key_fingerprint": self.key_fingerprint,
            "key_fingerprint_short": self.key_fingerprint[:12],
            "crl_number": self.crl_number,
            "this_update": fmt_time(self.this_update),
            "next_update": fmt_time(self.next_update),
            "stored_at": self.stored_at,
            "revoked_count": self.revoked_count,
            "der_sha256": self.der_sha256,
        }

    def to_json(self) -> dict:
        return {
            "key": self.key,
            "ca_name": self.ca_name,
            "key_fingerprint": self.key_fingerprint,
            "crl_number": self.crl_number,
            "this_update": self.this_update.isoformat(),
            "next_update": self.next_update.isoformat(),
            "der_sha256": self.der_sha256,
            "stored_at": self.stored_at,
            "revoked_count": self.revoked_count,
            "ca_pem": self.ca_pem,
            "crl_pem": self.crl_pem,
        }

    @classmethod
    def from_json(cls, data: dict) -> "StoredCRL":
        crl = x509.load_pem_x509_crl(data["crl_pem"].encode("utf-8"))
        return cls(
            key=data["key"],
            ca_name=data["ca_name"],
            key_fingerprint=data["key_fingerprint"],
            crl_number=int(data["crl_number"]),
            this_update=datetime.datetime.fromisoformat(data["this_update"]),
            next_update=datetime.datetime.fromisoformat(data["next_update"]),
            der_sha256=data["der_sha256"],
            stored_at=data["stored_at"],
            revoked_count=int(data["revoked_count"]),
            ca_pem=data["ca_pem"],
            crl_pem=data["crl_pem"],
            crl=crl,
        )


def build_record(
    ca_pem: str, crl_pem: str, now: datetime.datetime
) -> StoredCRL:
    """核验上传材料并构造 :class:`StoredCRL`；任何一项不过即抛 CRLError。"""
    ca = _validate_ca_cert(ca_pem)
    crl = _parse_single_crl(crl_pem)
    number = _validate_crl(crl, ca, now)
    der = crl.public_bytes(serialization.Encoding.DER)
    return StoredCRL(
        key=record_key_for_cert(ca),
        ca_name=cert_subject(ca),
        key_fingerprint=key_fingerprint(ca),
        crl_number=number,
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
        der_sha256=hashlib.sha256(der).hexdigest(),
        stored_at=utcnow().isoformat(),
        revoked_count=len(crl),
        ca_pem=ca_pem,
        crl_pem=crl_pem,
        crl=crl,
    )


def summarize_crl(crl_pem: str) -> dict:
    """提取 CRL 概要供页面即时确认（不做签名校验）。"""
    crl = _parse_single_crl(crl_pem)
    try:
        number: int | None = crl.extensions.get_extension_for_class(
            x509.CRLNumber
        ).value.crl_number
    except x509.ExtensionNotFound:
        number = None
    is_delta = False
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        is_delta = True
    except x509.ExtensionNotFound:
        pass
    next_update = crl.next_update_utc
    return {
        "issuer": crl.issuer.rfc4514_string(),
        "crl_number": number,
        "this_update": fmt_time(crl.last_update_utc),
        "next_update": fmt_time(next_update) if next_update else None,
        "revoked_count": len(crl),
        "is_delta": is_delta,
    }


@dataclass
class UploadOutcome:
    accepted: bool
    action: str  # stored | updated | unchanged | rejected
    message: str
    record: StoredCRL | None = None  # 被接受的清单
    current: StoredCRL | None = None  # 拒绝时的现行清单


@dataclass(frozen=True)
class Snapshot:
    """核查轮次开始时固定的清单集合与核验时刻。"""

    records: dict[str, StoredCRL]
    taken_at: datetime.datetime

    def summaries(self) -> list[dict]:
        return [
            rec.summary()
            for rec in sorted(
                self.records.values(),
                key=lambda r: (r.ca_name, r.key_fingerprint),
            )
        ]


class CRLStore:
    """按 “CA 名称+公钥” 保存各 CA 最新清单的持久化存储。

    所有修改操作依次获取 线程锁 → 文件锁，并在锁内重新从磁盘加载，
    因此同一进程的多线程与多进程（gunicorn 多 worker）并发上传时，
    “读取-比较-替换” 整体原子，单调规则不会被并发打破。
    """

    def __init__(self, directory: str | os.PathLike):
        self._dir = pathlib.Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock_path = self._dir / ".store.lock"
        self._thread_lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # 锁与加载
    # ------------------------------------------------------------------ #
    class _Locked:
        def __init__(self, store: "CRLStore", exclusive: bool):
            self._store = store
            self._exclusive = exclusive

        def __enter__(self):
            self._store._thread_lock.acquire()
            self._fh = open(self._store._lock_path, "a+b")
            fcntl.flock(
                self._fh, fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
            )
            return self

        def __exit__(self, *exc):
            try:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
            finally:
                self._store._thread_lock.release()
            return False

    def _locked(self, exclusive: bool = True) -> "CRLStore._Locked":
        return CRLStore._Locked(self, exclusive)

    def _load_all(self) -> dict[str, StoredCRL]:
        records: dict[str, StoredCRL] = {}
        for path in sorted(self._dir.glob("*.json")):
            try:
                rec = StoredCRL.from_json(
                    json.loads(path.read_text(encoding="utf-8"))
                )
            except Exception:
                continue  # 跳过损坏文件，不影响其余清单
            records[rec.key] = rec
        return records

    def _persist(self, rec: StoredCRL) -> None:
        tmp_path = self._dir / f".{rec.key}.tmp"
        final_path = self._dir / f"{rec.key}.json"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(rec.to_json(), fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, final_path)

    # ------------------------------------------------------------------ #
    # 对外操作
    # ------------------------------------------------------------------ #
    def upload(
        self,
        ca_pem: str,
        crl_pem: str,
        now: datetime.datetime | None = None,
    ) -> UploadOutcome:
        """核验并按单调规则保存清单；并发安全。"""
        rec = build_record(ca_pem, crl_pem, now or utcnow())
        with self._locked(exclusive=True):
            records = self._load_all()
            cur = records.get(rec.key)
            if cur is not None:
                if rec.crl_number < cur.crl_number:
                    return UploadOutcome(
                        False,
                        "rejected",
                        f"清单编号 {rec.crl_number} 低于现行编号 "
                        f"{cur.crl_number}，已拒绝并保留现行清单",
                        current=cur,
                    )
                if rec.crl_number == cur.crl_number:
                    if rec.der_sha256 == cur.der_sha256:
                        return UploadOutcome(
                            True,
                            "unchanged",
                            f"清单编号 {rec.crl_number} 与现行内容一致，无需变更",
                            record=cur,
                        )
                    return UploadOutcome(
                        False,
                        "rejected",
                        f"清单编号 {rec.crl_number} 与现行相同但内容不同，"
                        "已拒绝并保留现行清单",
                        current=cur,
                    )
            self._persist(rec)
            if cur is None:
                return UploadOutcome(
                    True,
                    "stored",
                    f"已保存清单（编号 {rec.crl_number}，CA：{rec.ca_name}）",
                    record=rec,
                )
            return UploadOutcome(
                True,
                "updated",
                f"清单已更新：编号 {cur.crl_number} → {rec.crl_number}",
                record=rec,
            )

    def snapshot(self) -> Snapshot:
        """取当前全部清单的快照，并固定核验时刻。"""
        with self._locked(exclusive=False):
            records = self._load_all()
            taken_at = utcnow()
        return Snapshot(records=records, taken_at=taken_at)

    def list_records(self) -> list[dict]:
        return self.snapshot().summaries()
