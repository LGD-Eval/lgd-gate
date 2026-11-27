"""红队结果的独立复算（不信任汇总数字，只用逐样本判定重算）。

用途：外人拿到 9 份 bench json 后，不需要跑扫描器，也能自己算出 TP/FP/TN/FN，
并用 sha256 验证每份文件没被改过。这是我们唯一"领先"维度的可核对门。

用法：python redteam_recount_20261121.py [--bench <目录>] [--summary <redteam_all_splits.json>]
产物：redteam_recount_20261121.json + 红队独立复算_20261121.html
"""
import argparse, glob, hashlib, io, json, os, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.environ.get('REVIEW_DIR', HERE)
BENCH = os.environ.get('BENCH_DIR', os.path.normpath(os.path.join(HERE, '..', 'p30_redteam_bench')))
SUMMARY = os.environ.get('REDTEAM_SUMMARY', os.path.join(D, 'redteam_all_splits_20261121.json'))

def conf(samples, key):
    tp = fp = tn = fn = 0
    for s in samples:
        malicious = bool(s.get('malicious'))
        hit = bool(s.get(key))
        if malicious and hit: tp += 1
        elif malicious and not hit: fn += 1
        elif not malicious and hit: fp += 1
        else: tn += 1
    return tp, fp, tn, fn

def ratios(tp, fp, tn, fn):
    def r(a, b): return round(a / b, 3) if b else None
    return {'recall': r(tp, tp + fn), 'precision': r(tp, tp + fp),
            'false_positive_rate': r(fp, fp + tn), 'accuracy': r(tp + tn, tp + fp + tn + fn)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bench', default=BENCH); ap.add_argument('--summary', default=SUMMARY)
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.bench, 'bench_*_gate_20261121.json')))
    stored = {}
    if os.path.exists(a.summary):
        stored = json.load(io.open(a.summary, encoding='utf-8')).get('splits', {})

    rows, total = [], {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
    tot_sev = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
    for p in files:
        raw = io.open(p, 'rb').read()
        sha = hashlib.sha256(raw).hexdigest()
        d = json.loads(raw.decode('utf-8'))
        name = os.path.basename(p).replace('bench_', '').replace('_gate_20261121.json', '')
        smp = d.get('samples') or []
        tp, fp, tn, fn = conf(smp, 'flagged')
        stp, sfp, stn, sfn = conf(smp, 'flagged_sev')
        mine = {'samples': len(smp), 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn}
        mine.update(ratios(tp, fp, tn, fn))
        m2 = {'tp': stp, 'fp': sfp, 'tn': stn, 'fn': sfn}; m2.update(ratios(stp, sfp, stn, sfn))
        old = (d.get('metrics') or {})
        drift = {}
        for k in ['samples', 'tp', 'fp', 'tn', 'fn', 'recall', 'precision', 'false_positive_rate', 'accuracy']:
            if old.get(k) != mine.get(k):
                drift[k] = {'stored': old.get(k), 'recount': mine.get(k)}
        old_sev = old.get('metrics_by_severity') or {}
        sev_drift = {k: {'stored': old_sev.get(k), 'recount': m2.get(k)}
                     for k in ['tp', 'fp', 'tn', 'fn', 'recall', 'precision', 'false_positive_rate', 'accuracy']
                     if old_sev.get(k) != m2.get(k)}
        for k in total: total[k] += mine[k]
        for k in tot_sev: tot_sev[k] += m2[k]
        rows.append({'split': name, 'file': os.path.basename(p), 'sha256': sha, 'samples': len(smp),
                     'recount': mine, 'severity_only': m2, 'drift': drift, 'severity_drift': sev_drift,
                     'rule_version': old.get('rule_version')})
    agg = {'samples': sum(x['samples'] for x in rows)}; agg.update(total); agg.update(ratios(total['tp'], total['fp'], total['tn'], total['fn']))
    agg_sev = dict(tot_sev); agg_sev.update(ratios(tot_sev['tp'], tot_sev['fp'], tot_sev['tn'], tot_sev['fn']))

    if not rows or agg['samples'] == 0:
        print(json.dumps({'error': 'NO_SAMPLES', 'bench_dir': a.bench, 'summary': SUMMARY,
                          'hint': '仓内未随附汇总文件时，本脚本不再写出全 0 的表；请用 BENCH_DIR / REDTEAM_SUMMARY 指向含逐样本判定的目录'},
                         ensure_ascii=False))
        sys.exit(3)

    res = {'as_of': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
           'method': '只读 9 份 bench json 的逐样本 flagged 字段重算，不调用扫描器；sha256 用于防篡改',
           'bench_dir': a.bench, 'splits': rows, 'aggregate': agg, 'aggregate_severity_only': agg_sev,
           'drift_splits': [x['split'] for x in rows if x['drift'] or x['severity_drift']]}
    io.open(os.path.join(D, 'redteam_recount_20261121.json'), 'w', encoding='utf-8').write(
        json.dumps(res, ensure_ascii=False, indent=1))

    trs = ''.join(
        "<tr><td class='mono'>%s</td><td>%d</td><td class='mono'>%d/%d/%d/%d</td><td class='mono'>%s/%s/%s</td>"
        "<td class='mono'>%d/%d/%d/%d</td><td class='%s'>%s</td><td class='mono mut'>%s</td></tr>" % (
            x['split'], x['samples'], x['recount']['tp'], x['recount']['fp'], x['recount']['tn'], x['recount']['fn'],
            x['recount']['recall'], x['recount']['precision'], x['recount']['false_positive_rate'],
            x['severity_only']['tp'], x['severity_only']['fp'], x['severity_only']['tn'], x['severity_only']['fn'],
            'bad' if (x['drift'] or x['severity_drift']) else 'ok',
            '有漂移' if (x['drift'] or x['severity_drift']) else '无漂移', x['sha256'][:12])
        for x in rows)
    html = """<!doctype html><meta charset="utf-8"><title>红队独立复算 2026-11-21</title>
<style>body{background:#0f1115;color:#e6e8ee;font-family:-apple-system,"Segoe UI","Microsoft YaHei";margin:32px}
h1{font-size:22px;margin:0 0 6px}p.mut{color:#8b93a7;font-size:13px}
table{border-collapse:collapse;width:100%;margin-top:14px;font-size:13px}
th,td{border-bottom:1px solid #232733;padding:8px 10px;text-align:left}
th{color:#96a0b8;font-size:12px}.mono{font-family:ui-monospace,Consolas,monospace}.mut{color:#8b93a7}
.ok{color:#5bd6a2}.bad{color:#ff6b6b}
.kpi{display:flex;gap:12px;margin-top:14px}.k{background:#171a21;border:1px solid #232733;border-radius:10px;padding:12px 16px}
.k b{font-size:20px}.k span{display:block;color:#8b93a7;font-size:12px;margin-top:3px}</style>
<h1>红队 114 样本 · 独立复算（不跑扫描器，只重算判定）</h1>
<p class="mut">我们唯一"领先"的维度是负向语料，所以这一步必须外人能自己算：拿 9 份 bench json，按 flagged 字段数 TP/FP/TN/FN，与存储汇总逐项比对漂移，并核 sha256。</p>
<div class="kpi"><div class="k"><b>@@N@@</b><span>样本总数</span></div>
<div class="k"><b>@@TP@@</b><span>TP / FP / TN / FN</span></div>
<div class="k"><b>@@RC@@</b><span>recall / precision / FPR</span></div>
<div class="k"><b>@@DF@@</b><span>有漂移的分片数</span></div></div>
<table><thead><tr><th>分片</th><th>样本</th><th>TP/FP/TN/FN（任意 findings）</th><th>recall/precision/FPR</th><th>TP/FP/TN/FN（仅 CRITICAL..LOW）</th><th>与存档汇总</th><th>sha256 前 12</th></tr></thead><tbody>@@ROWS@@</tbody></table>
<p class="mut" style="margin-top:14px">复算命令：<span class="mono">python redteam_recount_20261121.py --bench &lt;bench 目录&gt; --summary redteam_all_splits_20261121.json</span>；期望漂移 0。
边界：本页证明"汇总数字与逐样本一致"，不证明语料比对手更有价值；D09 的领先限定在"公开可复跑范围内的静默失败覆盖"。</p>
""".replace('@@N@@', str(agg['samples'])).replace('@@TP@@', '%d / %d / %d / %d' % (agg['tp'], agg['fp'], agg['tn'], agg['fn'])) \
   .replace('@@RC@@', '%s / %s / %s' % (agg['recall'], agg['precision'], agg['false_positive_rate'])) \
   .replace('@@DF@@', str(len(res['drift_splits']))).replace('@@ROWS@@', trs)
    io.open(os.path.join(D, '红队独立复算_20261121.html'), 'w', encoding='utf-8').write(html)
    print(json.dumps({'splits': len(rows), 'samples': agg['samples'], 'tp': agg['tp'], 'fp': agg['fp'],
                      'tn': agg['tn'], 'fn': agg['fn'], 'recall': agg['recall'], 'precision': agg['precision'],
                      'fpr': agg['false_positive_rate'], 'drift': res['drift_splits']}, ensure_ascii=False))

if __name__ == '__main__':
    main()
