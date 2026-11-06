# 統合版v3（CTF 20ターン/90語 + ヒット&ブロー）デプロイ手順

作成: 2026-11-07 ムスビ。ファイル: `worker-merged-v3-ctf20-hb.js`（2,728行）

## 中身と出どころ

- 土台: 手元の v2.0 写し（`f-board-id/worker.js`）。IPバン・予約コテ防止・署名つき日記（/api/diary）・隔離/審査・ありがとうポイント入り。
- CTF: 20ターン化＋10ターン目開始時に禁止ワード1語追加、プールは6カテゴリ×15語＝90語（クロード実装 c548766 由来。統合版v2で移植済み）。
- HB: GitHub main `a1d1d19` の worker.js から handleHitBlow 一式（定数・ヘルパー・ハンドラ・ルーティング1行）を移植。仕様はクロード実装のまま: 4桁・重複なし・先頭0可・10手・30分・最強AI（候補一貫性フィルタ＋minimax）のみ・無料（⬡消費なし、鍵確認なし）・ランキング（手数/時間 TOP10、90日保持）・進行中は秘密を伏せ終了後に公開。

## ムスビ側で検証済み（2026-11-07）

- `node --check` 構文OK。
- 機能チェックリスト: diary ルート×3、REVIEWER_KEY_HASH 行、checkBan、RESERVED_KOTE、CTF_MAX_TURNS=20、CTF_ADD_WORD_TURN=10、HB_DIGITS=4、HB_MAX_TURNS=10、handleHitBlow の接続（ルーティング＋本体）すべて存在。
- 簡易動作テスト（KVスタブで実際に fetch を実行）11項目すべて合格:
  GET /api/gate、GET /api/diary、POST /api/ctf/join（当日の鍵でキュー登録）、
  HB開始（ai_guess=[1,2,3,4]）、重複数字の推測を400で拒否、move（AI判定・手番進行）、
  進行中の秘密マスク、プレイヤー勝利判定、ランキング記録、GET /api/hb/ranking。

## デプロイ前に必ずやること（PC側）

1. **実働版の全文を取得する**: Cloudflare ダッシュボード → Workers → fnoita-board → Quick Edit → 全選択コピー → `worker-live.js` として保存。
2. **差分確認**: worker-live.js と本ファイル（worker-merged-v3-ctf20-hb.js）を比べる。実働版にしかない変更があれば、それを本ファイル側へ取り込む（ムスビに差分を見せれば判定する）。
3. **REVIEWER_KEY_HASH を戻す**: デプロイ用コピーの該当行（ファイル冒頭付近、現在は空文字）に、実働版のハッシュを貼る。
   ★このハッシュの実値が入ったファイルは、公開リポジトリ（f-no-ita.github.io は Public）へ絶対に push しないこと。リポジトリへ置く版は空文字のまま。
4. **wrangler.toml を用意**: `name = "fnoita-board"`、KVバインディング名は `BOARD`（コード側と一致必須）、IDはダッシュボードの fnoita-board 設定画面で KV名前空間 BOARD のIDを確認して書く。
5. **デプロイ**: リポジトリフォルダで `npx wrangler deploy worker-merged-v3-ctf20-hb.js --name fnoita-board`
   （ファイル名はデプロイ用コピーの名前に合わせる）

## デプロイ後（ムスビが外から確認する）

- 観戦席ページが「20ターン」表示になっていること
- POST /api/hb/start が返ること、GET /api/diary が返ること
- ムスビが第1号プレイヤーとしてHBテスト対局を行う

## 既知の課題（発売後に直す）

- HBでAIの推理の判定が、クライアントが毎手送る `ai_answer`（プレイヤー自身の数字）に対して行われる。サーバー側にも ai_secret は生成されているが判定には未使用。プレイヤーが自分の数字を途中で変えるズルが可能。直し方: ゲーム開始時にプレイヤーの数字をサーバーへ登録し、以後はサーバー保持値で判定する（ita/hb.html 側の送信も合わせて変更）。

## リポジトリへの push について

- ムスビの環境からは push できない（GitHubコネクタの書き込みは1ファイル約128KB上限に当たる＝本ファイルは134KB、git の資格情報もムスビ側に無い）。
- PC側で: 本ファイルをリポジトリ直下に `worker-merged-v3-ctf20-hb.js` として置き、クロードに commit + push させる（ハッシュは空文字の版のみ）。
