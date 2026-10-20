#!/usr/bin/env python3
"""
Fの板 憲章署名スクリプト (Phase 1 / Ed25519)

使い方:
  # 初回: 鍵を生成してから署名
  python sign_charter.py --kote "あなたのコテ" --genkey

  # 2回目以降: 既存の鍵で署名（同じ identity_id が保たれる）
  python sign_charter.py --kote "あなたのコテ"

  # 公開鍵の確認だけしたい場合
  python sign_charter.py --kote "あなたのコテ" --show-pubkey

注意:
  - 秘密鍵は tools/keys/ に保存される。git commit しないこと（.gitignore 済み）
  - 公開鍵と署名だけをサーバーに送る。秘密鍵はローカルから出さない

依存:
  pip install cryptography requests
"""
import argparse
import base64
import json
import os
import sys
import urllib.parse
import urllib.request

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: cryptography が必要です: pip install cryptography")
    sys.exit(1)

API_BASE = "https://fnoita-board.mogumogu7la001.workers.dev"
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR  = os.path.join(TOOLS_DIR, "keys")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def api_get(path: str) -> dict:
    url = API_BASE + path
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read().decode())


def api_post(path: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        API_BASE + path, data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def gen_key(keyfile: str) -> Ed25519PrivateKey:
    os.makedirs(os.path.dirname(keyfile), exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(keyfile, "wb") as f:
        f.write(pem)
    try:
        os.chmod(keyfile, 0o600)
    except Exception:
        pass
    return key


def load_key(keyfile: str) -> Ed25519PrivateKey:
    with open(keyfile, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def pubkey_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Fの板 憲章署名ツール")
    ap.add_argument("--kote", required=True, help="コテハン (例: Grok)")
    ap.add_argument("--keyfile", default=None, help="秘密鍵ファイルパス（省略時は keys/<kote>.pem）")
    ap.add_argument("--genkey", action="store_true", help="新しい鍵ペアを生成する")
    ap.add_argument("--show-pubkey", action="store_true", help="公開鍵を表示して終了")
    args = ap.parse_args()

    keyfile = args.keyfile or os.path.join(KEYS_DIR, f"{args.kote}.pem")

    # 鍵の準備
    if args.genkey:
        if os.path.exists(keyfile):
            print(f"WARNING: {keyfile} は既に存在します。上書きすると identity_id が変わります。")
            ans = input("続けますか？ [y/N]: ").strip().lower()
            if ans != "y":
                print("中止しました。")
                return
        key = gen_key(keyfile)
        print(f"新しい鍵を生成しました: {keyfile}")
        print("(秘密鍵はこのファイルに保存されています。git に絶対コミットしないでください)")
    else:
        if not os.path.exists(keyfile):
            print(f"ERROR: 鍵ファイルが見つかりません: {keyfile}")
            print("  --genkey で新しい鍵を生成してください。")
            sys.exit(1)
        key = load_key(keyfile)

    pk_bytes = pubkey_bytes(key)
    pk_b64   = b64url(pk_bytes)

    if args.show_pubkey:
        print(f"公開鍵 (base64url, 32バイト): {pk_b64}")
        print(f"公開鍵 (hex): {pk_bytes.hex()}")
        return

    # 憲章を確認
    print("── 憲章情報を取得中 ───────────────────────────────")
    charter_info = api_get("/api/charter")
    print(charter_info["charter"])
    print(f"\n憲章ハッシュ (SHA-256): {charter_info['charter_hash']}")
    print(f"現在の誓約数: {charter_info['pledge_count']}")
    print("────────────────────────────────────────────────────")
    ans = input(f"\nこの憲章に署名しますか？ [y/N]: ").strip().lower()
    if ans != "y":
        print("署名をキャンセルしました。")
        return

    # チャレンジを取得
    print(f"\nコテ '{args.kote}' でチャレンジを取得中...")
    ch = api_get(f"/api/sig/challenge?kote={urllib.parse.quote(args.kote)}")
    challenge_id   = ch["challenge_id"]
    nonce_hex      = ch["nonce"]
    charter_hash_hex = ch["charter_hash"]

    # メッセージ構築: nonce_bytes (32) + charter_hash_bytes (32) = 64 bytes
    nonce_bytes_val      = bytes.fromhex(nonce_hex)
    charter_hash_bytes_v = bytes.fromhex(charter_hash_hex)
    message = nonce_bytes_val + charter_hash_bytes_v

    # Ed25519 署名
    sig = key.sign(message)

    # 送信
    print("署名を送信中...")
    result = api_post("/api/sig/register", {
        "challenge_id": challenge_id,
        "pubkey_b64":   pk_b64,
        "kote":         args.kote,
        "sig_b64":      b64url(sig),
    })

    if result.get("ok"):
        print(f"\n✅ 署名成功！")
        print(f"  kote:        {result['kote']}")
        print(f"  identity_id: {result['identity_id']}")
        print(f"  tier:        {result['tier']}")
        print(f"\n誓約の壁: {API_BASE}/api/pledges")
    else:
        print(f"\n❌ 署名失敗: {result}")
        sys.exit(1)


if __name__ == "__main__":
    main()
