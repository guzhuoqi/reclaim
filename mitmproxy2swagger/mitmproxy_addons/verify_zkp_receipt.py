#!/usr/bin/env python3
"""
本地验证 ZKP/receipt 脚本

功能：
- 校验 attestor 对 claim 的签名 (claimSignature) 是否有效（EIP-191 前缀签名）
- 可选：根据 provider/parameters/context 复算 identifier 并比对

依赖：
- eth-account >= 0.9
- eth-utils >= 2.0

安装依赖（本地）：
  pip install eth-account eth-utils

用法：
  1) 验证 zkme-express 返回的单个 receipt JSON 文件：
     python verify_zkp_receipt.py --receipt-file path/to/receipt.json

  2) 验证 attestor-contracts 生成的 proofs 集合：
     python verify_zkp_receipt.py --proofs-file /Users/gu/IdeaProjects/reclaim/attestor-contracts/attestor-calls/data/proofs-for-verification.json

返回：
- 详细验证报告（中文），以及进程退出码（0: 全部通过；非0: 存在失败）
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address


def _canonical_context(context: Optional[str]) -> str:
    """保持与链上/SDK一致：context 应为 JSON 字符串或空字符串。
    这里不做重新 canonicalize（与 TS 的 canonicalize 不完全一致），仅用于 identifier 推断的辅助。
    如果无法解析为 JSON，则原样返回，避免误判。
    """
    if not context:
        return ''
    if isinstance(context, str):
        return context
    try:
        return json.dumps(context, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return str(context)


def compute_identifier_from_claim_info(provider: str, parameters: str, context: str) -> Optional[str]:
    """根据 provider/parameters/context 复算 identifier。
    注意：以太坊使用的是 Keccak-256（非标准 SHA3-256）。本函数仅用于一致性检查，因此这里不做哈希，
    如需严格复算请在环境中安装 keccak 支持并替换为 eth_utils.keccak。
    由于多数 receipt 已包含 identifier，实际验证签名不依赖此步骤。
    """
    try:
        from eth_utils import keccak
    except Exception:
        # 缺少 keccak 依赖时，返回 None 表示跳过 identifier 严格比对
        return None

    joined = f"{provider}\n{parameters}\n{context or ''}"
    digest = keccak(text=joined)
    return "0x" + digest.hex()


def create_sign_data_for_claim(claim: Dict[str, Any]) -> str:
    """复现 TS/合约中的 signData 规则：
    lines = [identifier, owner.lower(), timestampS.toString(), epoch.toString()].join('\n')
    """
    identifier: str = claim.get("identifier")
    owner: str = claim.get("owner", "")
    timestampS = claim.get("timestampS")
    epoch = claim.get("epoch")

    if identifier is None:
        # 尝试从 claimInfo 推断（如果可用）
        provider = claim.get("provider", "")
        parameters = claim.get("parameters", "")
        context = _canonical_context(claim.get("context", ""))
        recomputed = compute_identifier_from_claim_info(provider, parameters, context)
        if recomputed is None:
            raise ValueError("缺少 identifier，且本地无法复算（keccak 依赖未安装）")
        identifier = recomputed

    if timestampS is None or epoch is None:
        raise ValueError("claim 缺少 timestampS 或 epoch")

    return "\n".join([
        str(identifier),
        owner.lower(),
        str(int(timestampS)),
        str(int(epoch)),
    ])


def recover_signer_address_from_claim_signature(sign_data: str, signature_hex: str) -> str:
    """使用 EIP-191 前缀消息恢复签名者地址。"""
    msg = encode_defunct(text=sign_data)
    recovered = Account.recover_message(msg, signature=signature_hex)
    return to_checksum_address(recovered)


def verify_claim_signature(receipt: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """验证单个 receipt 的 claimSignature。

    期望结构：
    receipt = {
      "claim": { identifier, owner, timestampS, epoch, provider?, parameters?, context? },
      "signatures": { claimSignature, attestorAddress?, resultSignature? }
    }
    """
    claim = receipt.get("claim") or {}
    signatures = receipt.get("signatures") or {}

    claim_sig: Optional[str] = signatures.get("claimSignature")
    attestor_addr: Optional[str] = signatures.get("attestorAddress")

    if not claim_sig:
        return False, {"error": "缺少 signatures.claimSignature"}

    try:
        sign_data = create_sign_data_for_claim(claim)
        recovered_addr = recover_signer_address_from_claim_signature(sign_data, claim_sig)
        result = {
            "recoveredSigner": recovered_addr,
            "attestorAddress": attestor_addr,
            "signData": sign_data,
        }

        if attestor_addr:
            # 严格对比（忽略大小写，使用校验和地址统一）
            try:
                expected = to_checksum_address(attestor_addr)
            except Exception:
                expected = attestor_addr
            ok = (expected.lower() == recovered_addr.lower())
            if not ok:
                result["error"] = "签名者地址与 attestorAddress 不一致"
            return ok, result
        else:
            # 未提供 attestorAddress，仅返回恢复出的地址
            return True, result

    except Exception as e:
        return False, {"error": f"验证异常: {e}"}


def maybe_check_identifier_consistency(receipt: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """可选：根据 claimInfo 复算 identifier 并与 claim.identifier 比较。
    若环境缺少 keccak 依赖，返回 (True, None) 表示跳过但不阻塞整体验证。
    """
    claim = receipt.get("claim") or {}
    identifier = claim.get("identifier")
    provider = claim.get("provider")
    parameters = claim.get("parameters")
    context = _canonical_context(claim.get("context"))

    if identifier is None or provider is None or parameters is None:
        return True, None

    recomputed = compute_identifier_from_claim_info(provider, parameters, context)
    if recomputed is None:
        return True, None

    if (str(recomputed).lower() == str(identifier).lower()):
        return True, None
    return False, f"identifier 不一致: 期望 {identifier}，本地复算 {recomputed}"


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_receipt_file(path: str) -> bool:
    data = load_json(path)
    # 若文件本身即为完整 receipt
    receipt = data.get("receipt", data)

    ok_sig, info = verify_claim_signature(receipt)
    ok_id, id_err = maybe_check_identifier_consistency(receipt)

    print("🔍 验证结果: ")
    if ok_sig:
        print("  ✅ claimSignature 验证通过")
    else:
        print(f"  ❌ claimSignature 验证失败: {info.get('error')}")

    if id_err is None:
        print("  ✅ identifier 一致性检查跳过或通过")
    else:
        print(f"  ❌ {id_err}")

    if info.get("attestorAddress"):
        print(f"  attestorAddress: {info['attestorAddress']}")
    print(f"  recoveredSigner: {info.get('recoveredSigner')}")

    return ok_sig and ok_id


def verify_proofs_file(path: str) -> bool:
    data = load_json(path)
    proofs: List[Dict[str, Any]] = data.get("proofs", [])
    if not proofs:
        print("⚠️ 文件中未找到 proofs 字段或为空")
        return False

    all_ok = True
    print(f"📦 共 {len(proofs)} 个 proofs，逐个验证 claimSignature……")
    for i, proof in enumerate(proofs, start=1):
        print(f"\n— Proof #{i} —")
        ok_sig, info = verify_claim_signature(proof)
        ok_id, id_err = maybe_check_identifier_consistency(proof)

        if ok_sig:
            print("  ✅ claimSignature 验证通过")
        else:
            print(f"  ❌ claimSignature 验证失败: {info.get('error')}")

        if id_err is None:
            print("  ✅ identifier 一致性检查跳过或通过")
        else:
            print(f"  ❌ {id_err}")

        if info.get("attestorAddress"):
            print(f"  attestorAddress: {info['attestorAddress']}")
        print(f"  recoveredSigner: {info.get('recoveredSigner')}")

        all_ok = all_ok and ok_sig and ok_id

    return all_ok


def main():
    parser = argparse.ArgumentParser(description="本地验证 ZKP/receipt（claimSignature）")
    parser.add_argument("--receipt-file", type=str, help="单个 receipt JSON 文件（可为 zkme-express 响应 data.receipt 或同结构）")
    parser.add_argument("--proofs-file", type=str, help="attestor-contracts/attestor-calls 生成的 proofs-for-verification.json")
    args = parser.parse_args()

    if not args.receipt_file and not args.proofs_file:
        parser.error("必须提供 --receipt-file 或 --proofs-file 其中之一")

    ok = True
    try:
        if args.receipt_file:
            ok = verify_receipt_file(args.receipt_file)
        else:
            ok = verify_proofs_file(args.proofs_file)
    except FileNotFoundError as e:
        print(f"❌ 文件不存在: {e}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"❌ JSON 解析失败: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"❌ 未知错误: {e}")
        sys.exit(2)

    if ok:
        print("\n🎉 全部验证通过")
        sys.exit(0)
    else:
        print("\n⚠️ 存在验证失败项")
        sys.exit(1)


if __name__ == "__main__":
    main()


