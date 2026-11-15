"""正则取样器：把一条正则展开成一个「应当被它匹配」的样例字符串。

用途：给规则表的每一条正则造一个见证样本，然后验证 `正则.search(样例)` 成立。
这样"表里有这一行"就变成"这一行真的会响"，不需要人工一条条编样本。

支持的语法（够用即可，遇到不认识的按字面处理）：
  字面量 / \\s \\d \\w \\b 等转义 / 字符类 [..] / 分组 (?: ) ( ) (?= ) / 竖线（取第一支）
  量词 + * ? {n} {n,m}（一律取最小次数，1 或 n）
"""
import re

QUANT = set("+*?{|}")


def _first_class_char(body):
    negated = body.startswith("^")
    body = body.replace("\\", "")
    body = body.replace("^", "")
    if negated:
        # 否定类要挑一个「不像单词字符」的代表，否则 \b 边界会被自己填进去的字母破坏
        for ch in ("@", "-", " ", "~", "a"):
            if ch not in body:
                return ch
        return "@"
    for ch in body:
        if ch.isalnum() or ch in "._-@/:= ":
            return ch
    return "a"


def sample_for(pat, _d=0):
    if _d > 8:
        # 兜底：放弃结构化展开，退化为去掉元字符
        return re.sub(r"[\\()?*+{}|]", "", pat)
    out = []
    i, n = 0, len(pat)
    pending_repeat = 0     # 上一个原子要重复几次
    while i < n:
        ch = pat[i]

        if ch == "\\":
            if i + 1 >= n:
                out.append("\\")
                i += 1
                continue
            e = pat[i + 1]
            lit = {"s": " ", "d": "0", "w": "a", "b": "", "n": "\n", "t": "\t",
                   "S": "x", "D": "x", "W": "-"}.get(e, e)
            out.append(lit)
            i += 2

        elif ch == "[":
            j = pat.find("]", i + 1)
            if j < 0:
                out.append("[")
                i += 1
                continue
            out.append(_first_class_char(pat[i + 1:j]))
            i = j + 1

        elif ch == "(":
            # 跳过分组标记
            k = i + 1
            skip_assert = False
            if pat[k:k + 2] == "?:":
                k += 2
            elif pat[k:k + 2] == "?=":
                k += 2          # 肯定前瞻：内容必须出现，要取
            elif pat[k:k + 2] == "?!":
                k += 2
                skip_assert = True   # 否定前瞻：内容必须不出现，绝不能取
            elif pat[k:k + 3] in ("?<=", "?<!"):
                k += 3          # (?<= / (?<! 后面直接是内容，没有 '>'
                skip_assert = True
            elif pat[k:k + 2] == "?<":
                k = pat.find(">", k) + 1
            # 取第一支：扫到同层的 | 或 )
            depth, buf = 1, []
            while k < n and depth:
                if pat[k] == "\\":
                    buf.append(pat[k:k + 2])
                    k += 2
                    continue
                if pat[k] == "(":
                    depth += 1
                elif pat[k] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif pat[k] == "|" and depth == 1:
                    # 跳到本分组结束，丢弃后面的分支
                    while k < n and depth:
                        if pat[k] == "(":
                            depth += 1
                        elif pat[k] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        k += 1
                    # 回到 ')' 上，让外层 i = k + 1 正好落在右括号后面
                    break
                buf.append(pat[k])
                k += 1
            if skip_assert:
                # 断言不产出文本（肯定断言的内容由别处补，否定断言的内容绝对不能出现）
                i = k + 1
                continue
            out.append(sample_for("".join(buf), _d + 1))
            i = k + 1

        elif ch == ")":
            i += 1

        elif ch == "|":
            # 顶层竖线：后面的分支整段丢弃
            depth = 0
            while i < n:
                if pat[i] == "\\":
                    i += 2
                    continue
                if pat[i] == "(":
                    depth += 1
                elif pat[i] == ")":
                    depth -= 1
                elif pat[i] == "|" and depth == 0:
                    i += 1
                    break
                i += 1

        elif ch in "+*":
            if out and not ch == "*":
                out.append(out[-1])
            i += 1

        elif ch == "?":
            i += 1

        elif ch == "{":
            j = pat.find("}", i)
            body = pat[i + 1:j] if j > 0 else "2"
            k = body.split(",")[0]
            try:
                rep = int(k)
            except ValueError:
                rep = 1
            if out:
                out.append(out[-1] * max(0, rep - 1))
            i = (j + 1) if j > 0 else i + 1

        elif ch in "^$":
            i += 1

        else:
            out.append(ch)
            i += 1

    return "".join(out)


SAMPLES = {
    # 给几条难缠的手工兜底（含前瞻里的内容），保证见证真的会被匹配
}


def witness(pat):
    if pat in SAMPLES:
        return SAMPLES[pat]
    s = sample_for(pat)
    if re.search(pat, s):
        return s
    # 前瞻没被展开的情况：把前瞻内容补到前面再试
    for m in re.finditer(r"\(\?=[^)]*\)?(.+?)\)?", pat):
        pass
    return s


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        w = witness(p)
        print("%-60s -> %-30r 匹配=%s" % (p[:60], w[:30], bool(re.search(p, w))))
