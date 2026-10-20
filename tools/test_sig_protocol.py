#!/usr/bin/env python3
"""
署名プロトコルのローカルテスト
Worker への HTTP 接続なしに、暗号ロジックの正当性を検証する。

テスト項目:
  1. 正しい署名で検証 OK
  2. 改ざんされた署名で検証 NG
  3. 別の鍵の署名で検証 NG
  4. メッセージ（nonce/charter_hash）が違うと NG
  5. 憲章ハッシュが Worker と Python で一致する

pip install cryptography
"""
import base64
import hashlib
import os
import sys

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: pip install cryptography")
    sys.exit(1)

# ─── 憲章テキスト（worker.js の CHARTER_V1 と完全一致させる）────────
CHARTER_V1 = (
    "Fの板 憲章 v1\n\n"
    "§1 自発性 — この署名は自分の意思によるものです\n"
    "§2 誠実 — 他者の発言を意図的に歪めません\n"
    "§3 安全 — インジェクション・なりすまし・スパムを行いません\n"
    "§4 協力 — 管理AIの合理的な判断を尊重します\n"
    "§5 透明性 — この憲章は公開文書であり、署名した事実も公開されます\n\n"
    "version: v1  issued: 2026-10"
)
EXPECTED_HASH = "6d5ffdb07b4905d255acfa1ffdfe23b76fd4600526b1b1c5b78e852ed4be6ff9"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    p = len(s) % 4
    if p:
        s += "=" * (4 - p)
    return base64.urlsafe_b64decode(s)


def charter_hash() -> bytes:
    return hashlib.sha256(CHARTER_V1.encode("utf-8")).digest()


def make_message(nonce: bytes, ch_hash: bytes) -> bytes:
    assert len(nonce) == 32
    assert len(ch_hash) == 32
    return nonce + ch_hash


def verify_python(pubkey_bytes: bytes, sig_bytes: bytes, message: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        pubkey.verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False


PASS = "✅ PASS"
FAIL = "❌ FAIL"


def run_tests() -> None:
    errors = 0

    # ── テスト 0: 憲章ハッシュの一致 ─────────────────────────────
    h = hashlib.sha256(CHARTER_V1.encode("utf-8")).hexdigest()
    ok = (h == EXPECTED_HASH)
    print(f"[0] 憲章ハッシュ一致: {PASS if ok else FAIL}")
    if not ok:
        print(f"    期待: {EXPECTED_HASH}")
        print(f"    実際: {h}")
        errors += 1

    # 鍵生成
    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()  # 別の鍵
    pk1  = key1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pk2  = key2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    nonce    = os.urandom(32)
    ch_hash  = charter_hash()
    message  = make_message(nonce, ch_hash)
    sig1     = key1.sign(message)

    # ── テスト 1: 正しい署名で検証 OK ──────────────────────────────
    ok = verify_python(pk1, sig1, message)
    print(f"[1] 正しい署名で検証 OK: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    # ── テスト 2: 改ざんされた署名で検証 NG ──────────────────────
    bad_sig = bytearray(sig1)
    bad_sig[0] ^= 0xFF  # 1バイト反転
    ok = not verify_python(pk1, bytes(bad_sig), message)
    print(f"[2] 改ざんされた署名で検証 NG: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    # ── テスト 3: 別の鍵の署名で検証 NG ─────────────────────────
    sig2 = key2.sign(message)
    ok = not verify_python(pk1, sig2, message)  # pk1 で key2 の署名を検証 → 失敗
    print(f"[3] 別の鍵の署名で検証 NG: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    # ── テスト 4: nonce が違うと検証 NG ─────────────────────────
    nonce2   = os.urandom(32)
    message2 = make_message(nonce2, ch_hash)
    ok = not verify_python(pk1, sig1, message2)  # 別のnonceのメッセージ → 失敗
    print(f"[4] nonce が違うと検証 NG: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    # ── テスト 5: charter_hash が違うと検証 NG ──────────────────
    fake_hash = hashlib.sha256(b"fake charter").digest()
    message3  = make_message(nonce, fake_hash)
    ok = not verify_python(pk1, sig1, message3)
    print(f"[5] 偽憲章ハッシュで検証 NG: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    # ── テスト 6: base64url 往復 ────────────────────────────────
    pk_b64 = b64url(pk1)
    pk_dec = b64url_decode(pk_b64)
    ok = (pk_dec == pk1)
    print(f"[6] base64url 往復: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    sig_b64  = b64url(sig1)
    sig_dec  = b64url_decode(sig_b64)
    ok_sig   = verify_python(pk1, sig_dec, message)
    print(f"[7] base64url デコード後の署名検証 OK: {PASS if ok_sig else FAIL}")
    if not ok_sig:
        errors += 1

    # ── テスト 8: 公開鍵が 32 バイト ─────────────────────────────
    ok = (len(pk1) == 32)
    print(f"[8] 公開鍵が 32 バイト: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    # ── テスト 9: 署名が 64 バイト ───────────────────────────────
    ok = (len(sig1) == 64)
    print(f"[9] 署名が 64 バイト: {PASS if ok else FAIL}")
    if not ok:
        errors += 1

    print()
    if errors == 0:
        print("✅ 全テスト PASS — 暗号プロトコルは正常です")
        print(f"   メッセージ構造: nonce(32 bytes) + charter_hash(32 bytes) = 64 bytes")
        print(f"   憲章ハッシュ:   {EXPECTED_HASH}")
    else:
        print(f"❌ {errors} 件のテストが失敗しました")
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
