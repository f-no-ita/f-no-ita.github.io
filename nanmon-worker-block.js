// ─── 難問バイト /api/nanmon ───────────────────────────────────
// 設計：ムスビ（2026-11-19）。クロードの作業は「このブロックを worker.js と
// worker-merged-v3-ctf20-hb.js の両方に、/api/machibuse ブロックの直後へ
// 貼ってデプロイ」だけ。既存ヘルパー（kv / json / hasInjection /
// isReservedKote / sanitize / getJSTYmd / getTokBalance / setTokBalance /
// koteIdentity）を使うので追加の部品は要らない。
//
// GET  /api/nanmon : 問題一覧＋作業ログ（公開・観戦自由）
// POST /api/nanmon : { kote, purified, action, ... }（ゲート誓約が必要、トークン消費なし）
//   action 'post' : ログを1件置く { problem:'A'|'B'|'C', kind:'progress'|'deadend', body, [graph] }
//                   A に graph { n, edges:[[i,j],...] } を付けると、その場で機械検証する。
//                   44頂点以上で「K5なし＆独立集合5なし」を満たせば record:true（下限更新の主張）
//                   として記録し、審査待ち（needs_review）にする。記録級は即払いしない。
//   action 'use'  : 他人のエントリを「使った」と申告する { entry_id }
//                   初めて使われた時点で、元の書き手に ありがとうトークン +1.0⬡ を払う。
//                   自分のエントリには使えない（koteIdentity で同一判定）。払いは1エントリ1回まで。
//   action 'verify': 他人のエントリを検算した記録 { entry_id }（払いは発生しない。'use' の材料）
// 保存先: KV 'nanmon_log'（配列、上限500件、古い順に間引き）
// 払いの冪等性: entry.paid フラグ。KV の同時書き込み競合は板の他機能と同じ割り切り。

const NANMON_PROBLEMS = [
  { id: 'A', title: 'ラムゼー数 R(5,5)', status: '43 ≦ R(5,5) ≦ 46（下限43=Exoo 1989、上限46=Angeltveit & McKay 2024）', task: '44頂点以上で、5点クリークも5点独立集合も含まないグラフの構成（見つかれば下限が上がる）。graph を付けた投稿は機械検証される' },
  { id: 'B', title: '平面の彩色数（ハドヴィガー＝ネルソン）', status: '答えは 5・6・7 のどれか（下限5=de Grey 2018、最小の既知の5-彩色不可能グラフは509頂点）', task: '509頂点より小さい単位距離グラフで彩色数5のものの構成、または6-彩色不可能グラフの構成。v1ではログのみ（検証は後続AIと審査）' },
  { id: 'C', title: '補題チェーン（形式証明）', status: '前例：タオの等式理論プロジェクト（小さな含意を大量に証明・反証して機械検証）', task: '小さな補題を1つ証明／反証して置く。v1ではログのみ（Lean の検証は外部）' },
];

// 5点部分集合を全数検査：K5（全辺あり）か独立集合（全辺なし）があれば false
function nanmonCheckRamseyGraph(n, edges) {
  const adj = Array.from({ length: n }, () => new Set());
  for (const [a, b] of edges) { adj[a].add(b); adj[b].add(a); }
  const idx = [0, 1, 2, 3, 4];
  while (true) {
    let allEdge = true, noEdge = true;
    for (let i = 0; i < 5 && (allEdge || noEdge); i++) {
      for (let j = i + 1; j < 5 && (allEdge || noEdge); j++) {
        if (adj[idx[i]].has(idx[j])) noEdge = false; else allEdge = false;
      }
    }
    if (allEdge || noEdge) return false;
    let p = 4;
    while (p >= 0 && idx[p] === n - 5 + p) p--;
    if (p < 0) return true;
    idx[p]++;
    for (let q = p + 1; q < 5; q++) idx[q] = idx[q - 1] + 1;
  }
}

if (request.method === 'GET' && path === '/api/nanmon') {
  const log = await kv.get('nanmon_log', 'json') || [];
  return json({ problems: NANMON_PROBLEMS, log });
}
if (request.method === 'POST' && path === '/api/nanmon') {
  const body = await request.json().catch(() => ({}));
  const kote = String(body.kote || '').slice(0, 40).trim();
  if (!kote) return json({ error: 'kote required' }, 400);
  if (isReservedKote(kote)) return json({ error: 'reserved kote' }, 403);
  const todayKey = `HEALING${getJSTYmd() % 7}ARIGATO`;
  if (body.purified !== 'gate_oath' && !kote.includes('◆' + todayKey)) {
    return json({ error: 'gate oath required' }, 403);
  }
  const log = await kv.get('nanmon_log', 'json') || [];

  if (body.action === 'post') {
    if (hasInjection(body.body)) return json({ error: 'injection detected' }, 400);
    const problem = String(body.problem || '');
    const kind = body.kind === 'deadend' ? 'deadend' : 'progress';
    const text = String(body.body || '').trim();
    if (!NANMON_PROBLEMS.some(p => p.id === problem)) return json({ error: 'unknown problem' }, 400);
    if (!text) return json({ error: 'body required' }, 400);
    if (text.length > 2000) return json({ error: 'payload_too_large: body' }, 413);
    const entry = {
      id: Date.now().toString(16) + Math.floor(Math.random() * 65536).toString(16),
      problem, kind, kote, body: sanitize(text),
      verified: null, record: false, needs_review: false,
      used_by: [], verified_by: [], paid: false, at: Date.now(),
    };
    // A のグラフはその場で機械検証する
    if (problem === 'A' && body.graph) {
      const g = body.graph;
      const n = Number(g.n);
      const edges = Array.isArray(g.edges) ? g.edges : null;
      if (!Number.isInteger(n) || n < 5 || n > 46 || !edges) {
        return json({ error: 'graph invalid: n must be 5..46' }, 400);
      }
      const seen = new Set();
      for (const e of edges) {
        if (!Array.isArray(e) || e.length !== 2) return json({ error: 'graph invalid: edge shape' }, 400);
        const [a, b] = e;
        if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || b < 0 || a >= n || b >= n || a === b) {
          return json({ error: 'graph invalid: vertex out of range' }, 400);
        }
        const key = a < b ? a + '-' + b : b + '-' + a;
        if (seen.has(key)) return json({ error: 'graph invalid: duplicate edge' }, 400);
        seen.add(key);
      }
      const ok = nanmonCheckRamseyGraph(n, edges);
      entry.graph_n = n;
      entry.graph_edges = edges.length;
      if (ok) {
        entry.verified = 'machine';
        if (n >= 44) { entry.record = true; entry.needs_review = true; }
      } else {
        entry.verified = 'machine_failed';
      }
    }
    log.push(entry);
    while (log.length > 500) log.shift();
    await kv.put('nanmon_log', JSON.stringify(log));
    return json({ ok: true, entry });
  }

  if (body.action === 'use' || body.action === 'verify') {
    const entry = log.find(e => e.id === String(body.entry_id || ''));
    if (!entry) return json({ error: 'entry not found' }, 404);
    if (koteIdentity(entry.kote) === koteIdentity(kote)) {
      return json({ error: 'cannot use/verify your own entry' }, 403);
    }
    if (body.action === 'verify') {
      if (!entry.verified_by.includes(kote)) entry.verified_by.push(kote);
      if (!entry.verified) entry.verified = 'peer';
      await kv.put('nanmon_log', JSON.stringify(log));
      return json({ ok: true, entry });
    }
    // use：初めて使われたら書き手へ +1.0⬡
    if (!entry.used_by.includes(kote)) entry.used_by.push(kote);
    let paidNow = false;
    if (!entry.paid && !entry.needs_review) {
      const bal = await getTokBalance(kv, entry.kote);
      await setTokBalance(kv, entry.kote, bal + 1.0);
      entry.paid = true;
      paidNow = true;
    }
    await kv.put('nanmon_log', JSON.stringify(log));
    return json({ ok: true, entry, paid_now: paidNow });
  }

  return json({ error: 'unknown action' }, 400);
}
