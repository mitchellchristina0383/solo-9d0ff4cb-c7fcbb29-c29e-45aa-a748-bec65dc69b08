"""逐副本吊销核查：对照核查开始时的清单快照，判定 已吊销 / 未列入 / 待核实。

判定规则（与需求一一对应）
==========================
* **已吊销**：颁发关系核验通过、找到匹配清单且清单在核验时刻有效，
  叶子序列号出现在清单中；
* **未列入**：同上但序列号不在清单中；
* **待核实**：出现以下任一情况，无法给出确定结论——
    - 叶子或颁发 CA 证书无法解析；
    - 颁发关系验不过（叶子颁发者与所附 CA 主题不符，或叶子签名无法
      用所附 CA 公钥核验）；
    - 找不到匹配清单（按 CA 名称+公钥）；
    - 清单在核验时刻已失效（尚未生效或已过期）。

每轮核查使用 :class:`app.crlstore.Snapshot`：清单集合与核验时刻在轮次
开始时固定，核查期间的新上传不影响本轮结果。
"""

from __future__ import annotations

import datetime

from .certutil import PemError, cert_subject, extract_certs
from .crlstore import (
    CRLError,
    Snapshot,
    fmt_time,
    record_key_for_cert,
    verify_signature,
)

REVOKED = "revoked"
NOT_LISTED = "not_listed"
PENDING = "pending"

STATUS_LABEL = {
    REVOKED: "已吊销",
    NOT_LISTED: "未列入",
    PENDING: "待核实",
}


def evaluate_replica(
    row: dict,
    snapshot: Snapshot,
    now: datetime.datetime | None = None,
) -> dict:
    """核查单个副本；``now`` 默认取快照固定的核验时刻（测试可注入）。"""
    name = (row.get("name") or "").strip() or "未命名副本"
    moment = now or snapshot.taken_at
    result = {
        "name": name,
        "status": PENDING,
        "reason": "",
        "leaf_subject": None,
        "leaf_serial": None,
        "ca_name": None,
        "key_fingerprint": None,
        "key_fingerprint_short": None,
        "crl_number": None,
        "revoked_at": None,
    }

    try:
        leaf = extract_certs(row.get("leaf_pem", ""))[0]
    except PemError as exc:
        result["reason"] = f"叶子证书解析失败: {exc}"
        return result
    result["leaf_subject"] = cert_subject(leaf)
    result["leaf_serial"] = f"{leaf.serial_number:X}"

    try:
        ca = extract_certs(row.get("issuer_pem", ""))[0]
    except PemError as exc:
        result["reason"] = f"颁发 CA 证书解析失败: {exc}"
        return result
    result["ca_name"] = cert_subject(ca)
    result["key_fingerprint_short"] = None

    # 颁发关系：叶子颁发者名称必须与所附 CA 主题一致，且签名可核验
    if leaf.issuer.public_bytes() != ca.subject.public_bytes():
        result["reason"] = (
            "颁发关系验不过：叶子颁发者为 "
            f"{leaf.issuer.rfc4514_string()}，与所附 CA 主题不符"
        )
        return result
    try:
        verify_signature(leaf, leaf.tbs_certificate_bytes, ca.public_key(), "叶子签名")
    except CRLError as exc:
        result["reason"] = f"颁发关系验不过：{exc}"
        return result

    rec = snapshot.records.get(record_key_for_cert(ca))
    if rec is None:
        result["reason"] = "找不到匹配清单（按 CA 名称+公钥）"
        return result
    result["crl_number"] = rec.crl_number
    result["key_fingerprint"] = rec.key_fingerprint
    result["key_fingerprint_short"] = rec.key_fingerprint[:12]

    if moment < rec.this_update:
        result["reason"] = f"清单尚未生效（thisUpdate {fmt_time(rec.this_update)}）"
        return result
    if moment > rec.next_update:
        result["reason"] = f"清单已过期（nextUpdate {fmt_time(rec.next_update)}）"
        return result

    revoked = rec.crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if revoked is not None:
        result["status"] = REVOKED
        result["revoked_at"] = fmt_time(revoked.revocation_date_utc)
    else:
        result["status"] = NOT_LISTED
    return result


def run_check(rows: list[dict], snapshot: Snapshot) -> dict:
    """对一批副本执行一轮核查；清单与核验时刻均来自 ``snapshot``。"""
    return {
        "checked_at": fmt_time(snapshot.taken_at),
        "results": [evaluate_replica(row, snapshot) for row in rows],
    }
