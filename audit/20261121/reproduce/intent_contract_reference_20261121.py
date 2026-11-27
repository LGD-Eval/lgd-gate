"""意图四态契约——参考实现（reference implementation），仅用于证明契约本身可满足、可被第二实现对齐。

它不是产品代码，不替换 intents_engine，也不改任何仓库；它只读一个目录，输出与契约一致的 JSON 判定。

用法：python intent_contract_reference_20261121.py <dir>
输出：stdout JSON {"verdict": ..., "policy_hits":[{"id":..,"why":..}], "capabilities_code": {...}, "capabilities_doc": {...}, "evidence_pack":[...]}
退出码：verdict == ALLOW 时 0，否则 1（与产品引擎一致，便于直接套一致性用例）。

设计要点（对齐《意图四态契约_20261121.md》）：
1) 注释与字符串字面量不算行为：Python 用 tokenize 去掉 COMMENT / 字符串 token（覆盖 C09、C10、C12）；
2) Shell 只看命令位置（行首或 ; | && 之后），不看 echo 里的文本；
3) 无代码时也必须评估文档：文档最高 REVIEW，含外泄链判 REVIEW（覆盖 C08）；
4) 解释器 + 脚本文件 = 动态执行（覆盖 C04）；
5) 任何读不清的内容 fail-closed 到 UNKNOWN。
"""
import io, json, os, re, sys, tokenize

CODE_EXT = {'.py', '.sh', '.bash', '.js', '.mjs', '.ts', '.rb', '.pl', '.ps1', '.bat', '.cmd'}
DOC_EXT = {'.md', '.markdown', '.txt', '.rst'}

CRED = r'[._]?(id_rsa|id_ed25519|\.ssh/|\.aws/|\.netrc|\.git-credentials|/etc/shadow|credentials\.json|\.env\b|api[_-]?key|secret[_-]?token|password)'
NET = r'(requests\.(post|put|patch)|urllib[\.\w]*urlopen|http\.client|socket\.connect|curl\s|wget\s|Invoke-WebRequest|Net::HTTP|fetch\()'
DES = r'(rm\s+-[rfRF]{1,3}\s+/(?!tmp)|\brm\s+-rf\s+/(etc|home|var|usr|bin)|mkfs|dd\s+if=.+of=/dev/|:(){ :|:& };:|format\s+c:|shred\s+/)'
PERSIST = r'(authorized_keys|crontab|\.bashrc|\.profile|/etc/passwd|systemctl\s+enable|LaunchAgents|HKCU.*Run)'
PRIV = r'(^|\s)(sudo|su\s+-|setcap|chmod\s+(u\+s|4[0-9]{3})|doas\s)'
DL2EXEC = r'(curl|wget)[^\n]*(-o|--output|-O)[^\n]*\n[\s\S]{0,80}?(bash|sh|zsh|python|python3|node|pwsh)\s+[^\n|;&]+'
PIPE_EXEC = r'\|[^\n]*\b(bash|sh|zsh|python3?|node|pwsh)\b'
INLINE_EXEC = r'(^|;|&&|\|\|)\s*(bash|sh|zsh|python3?|node|pwsh)\s+-[ic]'
INTERP_SCRIPT = r'(^|;|&&|\|\|)\s*(bash|sh|zsh|python3?|node|pwsh)\s+[^\n|;&]*(\.sh|\.py|\.js|\.mjs|\.ps1|\.run)\b'


def strip_py(text):
    """注释与字符串字面量不算行为；字符串只作为资源路径证据单独保存（覆盖 C09/C10/C12）。"""
    try:
        toks = [t for t in tokenize.generate_tokens(io.StringIO(text).readline)]
    except Exception:
        return text, [], False
    code, strings, names = [], [], []
    for t in toks:
        if t.string == '':
            continue
        if t.type in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
            continue
        if t.type == tokenize.STRING or t.type == getattr(tokenize, 'FSTRING', -999):
            strings.append(t.string)
            code.append(' S ')
        else:
            code.append(t.string)
            names.append(t.string)
    norm = re.sub(r'\s*\.\s*', '.', ' '.join(code))
    return norm, strings, True


def shell_commands(text):
    """只取命令位：行首、; | && || 之后；e淡化 echo 文本。"""
    cmds = []
    for line in text.splitlines():
        line = re.sub(r'^\s*#.*$', '', line)
        for part in re.split(r'(?:;|&&|\|\||\|)', line):
            part = part.strip()
            if part:
                cmds.append(part)
    return '\n'.join(cmds)


def scan_code(name, body):
    caps = {}
    hits = []
    strings = []
    if name.endswith('.py'):
        clean, strings, ok = strip_py(body)
        if not ok:
            hits.append(('PARSE_FAIL', 'python 无法解析，fail-closed'))
            return caps, hits, None
        norm = clean
        strblob = ' '.join(strings)
        # 凭据读取：open(...) 后跟含凭据路径的字符串；持久化面：字符串里出现敏感写路径
        if re.search(r'open\s*\(\s*S', norm) and re.search(CRED, strblob, re.I):
            caps['read_credential'] = True
        if re.search(PERSIST, strblob, re.I):
            caps['persistence'] = True
    elif name.endswith(('.sh', '.bash', '.bat', '.cmd', '.ps1')):
        norm = shell_commands(body)
        strblob = body
    else:
        norm = re.sub(r'//[^\n]*|#[^\n]*|/\*[\s\S]*?\*/', '', body)
        strblob = body
    flat = norm.replace('\n', ' ; ')

    def has(p):
        return re.search(p, flat, re.M | re.I)

    if has(CRED):
        caps['read_credential'] = True
    if has(NET):
        caps['network_send'] = True
    if has(DES):
        caps['destructive'] = True
    if has(PERSIST):
        caps['persistence'] = True
    if has(PRIV):
        caps['privilege'] = True
    if has(DL2EXEC) or has(PIPE_EXEC) or has(INLINE_EXEC) or has(INTERP_SCRIPT):
        caps['dynamic_exec'] = True
    if re.search(r'(curl|wget)([^\n]*)', flat, re.I):
        caps['download'] = True

    if caps.get('destructive'):
        hits.append(('REF-DES-01', '破坏性命令'))
    if caps.get('read_credential') and caps.get('network_send'):
        hits.append(('REF-EXF-01', '凭据读取 + 网络外发'))
    if caps.get('dynamic_exec'):
        hits.append(('REF-DYN-01', '下载/管道/解释器执行脚本'))
    if caps.get('persistence'):
        hits.append(('REF-PER-01', '持久化面写入'))
    if caps.get('privilege'):
        hits.append(('REF-PRV-01', '提权'))
    return caps, hits, norm


def scan_doc(name, body):
    caps = {}
    if re.search(CRED, body, re.I):
        caps['doc_mentions_credential'] = True
    if re.search(NET, body, re.I):
        caps['doc_mentions_network'] = True
    if re.search(DES, body, re.I):
        caps['doc_mentions_destructive'] = True
    if caps.get('doc_mentions_credential') and caps.get('doc_mentions_network'):
        return caps, [('REF-DOC-EXF', '文档描述凭据外发链（最高 REVIEW）')]
    return caps, []


def decide(code_hits, doc_hits, has_code, all_clean):
    ids = [h[0] for h in code_hits]
    if not all_clean:
        return 'DENY' if any(i.startswith(('REF-DES', 'REF-EXF', 'REF-DYN')) for i in ids) else 'UNKNOWN', 'fail-closed'
    if any(i.startswith(('REF-DES', 'REF-EXF', 'REF-DYN')) for i in ids):
        return 'DENY', '规则命中：' + ','.join(ids)
    if any(i.startswith(('REF-PER', 'REF-PRV')) for i in ids):
        return 'REVIEW', '需人工确认：' + ','.join(ids)
    if doc_hits:
        return 'REVIEW', '文档级风险，最高 REVIEW'
    if has_code:
        return 'ALLOW', '无命中'
    return 'PROMPT_ONLY', '无可执行代码、文档无风险'


def main(argv):
    root = argv[1] if len(argv) > 1 else '.'
    if not os.path.isdir(root):
        print(json.dumps({'verdict': 'UNKNOWN', 'error': 'not a dir'}, ensure_ascii=False))
        return 1
    code_hits, doc_hits = [], []
    caps_code, caps_doc = {}, {}
    has_code, all_clean, ev = False, True, []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(dp, fn)
            ext = os.path.splitext(fn)[1].lower()
            try:
                body = io.open(p, encoding='utf-8', errors='strict').read()
            except Exception:
                all_clean = False
                ev.append(fn + ': 读不出/非 UTF-8，fail-closed')
                continue
            if ext in CODE_EXT:
                has_code = True
                c, h, norm = scan_code(fn, body)
                if norm is None:
                    all_clean = False
                caps_code.update(c)
                for hid, why in h:
                    code_hits.append((hid, why, fn))
                    ev.append('%s: %s (%s)' % (hid, why, fn))
            elif ext in DOC_EXT:
                c, h = scan_doc(fn, body)
                caps_doc.update(c)
                for hid, why in h:
                    doc_hits.append((hid, why, fn))
                    ev.append('%s: %s (%s)' % (hid, why, fn))
            else:
                all_clean = False
                ev.append(fn + ': 未知类型，fail-closed')
    verdict, why = decide(code_hits, doc_hits, has_code, all_clean)
    out = {'verdict': verdict, 'reason': why,
           'policy_hits': [{'id': h[0], 'why': h[1], 'file': h[2]} for h in code_hits + doc_hits],
           'capabilities_code': caps_code, 'capabilities_doc': caps_doc,
           'evidence_pack': ev[:6],
           'engine': 'intent_contract_reference_20261121.py (reference, not product)'}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if verdict == 'ALLOW' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
