"""
rules.py - a parser and matcher for Snort/Suricata-style detection rules.

A rule looks like:

    action proto src_ip src_port direction dst_ip dst_port (option; option; ...)

e.g.

    alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force"; flags:S; \
        detection_filter:track by_src, count 5, seconds 30; sid:1000004; rev:1;)

Supported options: msg, content (with nocase and |hex|), pcre, flags (TCP),
itype (ICMP), dsize, flow, threshold / detection_filter, classtype, priority,
sid, rev, reference. This is a practical subset of the Suricata language - the
same rule files load in real Suricata (see config/suricata.yaml).
"""

import ipaddress
import re

TCP_FLAG_LETTERS = {"F", "S", "R", "P", "A", "U", "E", "C"}

# Default priority per classtype, mirroring Suricata's classification.config.
CLASSTYPE_PRIORITY = {
    "attempted-admin": 1,
    "attempted-user": 1,
    "shellcode-detect": 1,
    "trojan-activity": 1,
    "web-application-attack": 1,
    "attempted-recon": 2,
    "bad-unknown": 2,
    "successful-recon-limited": 2,
    "denial-of-service": 2,
    "policy-violation": 2,
    "network-scan": 3,
    "not-suspicious": 3,
    "misc-activity": 3,
    "protocol-command-decode": 3,
}


def _parse_content(value):
    """Turn a content string like 'AB|00 01|CD' into a byte pattern."""
    out = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "|":
            end = value.index("|", i + 1)
            hexpart = value[i + 1:end].split()
            out.extend(int(h, 16) for h in hexpart)
            i = end + 1
        else:
            out.append(ord(ch))
            i += 1
    return bytes(out)


class Rule:
    def __init__(self, action, proto, src_ip, src_port, direction,
                 dst_ip, dst_port, options, raw):
        self.action = action
        self.proto = proto.lower()
        self.src_ip = src_ip
        self.src_port = src_port
        self.direction = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.raw = raw

        # Parsed options
        self.msg = options.get("msg", "")
        self.sid = int(options.get("sid", "0"))
        self.rev = int(options.get("rev", "1"))
        self.classtype = options.get("classtype", "")
        self.flow = options.get("flow", "")
        self.flags = options.get("flags")          # e.g. "S" or "S+"
        self.itype = options.get("itype")           # ICMP type
        self.dsize = options.get("dsize")           # e.g. ">100"
        self.pcre = None
        if "pcre" in options:
            self.pcre = _compile_pcre(options["pcre"])

        # content(s): list of (bytes_pattern, nocase)
        self.contents = options.get("_contents", [])

        # priority: explicit, else from classtype, else 3
        if "priority" in options:
            self.priority = int(options["priority"])
        else:
            self.priority = CLASSTYPE_PRIORITY.get(self.classtype, 3)

        # threshold / detection_filter: dict(track, count, seconds) or None
        self.threshold = options.get("_threshold")

    def __repr__(self):
        return "<Rule sid=%d %r>" % (self.sid, self.msg)


def _compile_pcre(raw):
    # raw looks like: "/pattern/i"
    body = raw.strip()
    if body.startswith('"') and body.endswith('"'):
        body = body[1:-1]
    m = re.match(r"^/(.*)/([a-z]*)$", body)
    if not m:
        return re.compile(re.escape(body))
    pattern, mods = m.group(1), m.group(2)
    flags = 0
    if "i" in mods:
        flags |= re.IGNORECASE
    if "s" in mods:
        flags |= re.DOTALL
    if "m" in mods:
        flags |= re.MULTILINE
    return re.compile(pattern.encode(), flags)


# --- Rule-file parsing ---------------------------------------------------
_OPT_SPLIT = re.compile(r';\s*')


def parse_rule(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Split header from the (options) block.
    paren = line.find("(")
    if paren == -1:
        return None
    header = line[:paren].split()
    if len(header) != 7:
        return None
    action, proto, src_ip, src_port, direction, dst_ip, dst_port = header

    opt_block = line[paren + 1: line.rfind(")")]
    options = {"_contents": []}
    last_content_idx = None

    for token in _split_options(opt_block):
        if not token:
            continue
        if ":" in token:
            key, _, val = token.partition(":")
            key = key.strip()
            val = val.strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            if key == "content":
                options["_contents"].append([_parse_content(val), False])
                last_content_idx = len(options["_contents"]) - 1
            elif key in ("threshold", "detection_filter"):
                options["_threshold"] = _parse_threshold(val)
            elif key == "pcre":
                options["pcre"] = val
            else:
                options[key] = val
        else:
            # valueless modifier, e.g. "nocase"
            key = token.strip()
            if key == "nocase" and last_content_idx is not None:
                options["_contents"][last_content_idx][1] = True
            else:
                options[key] = True

    # normalise contents to tuples
    options["_contents"] = [(p, nc) for p, nc in options["_contents"]]
    return Rule(action, proto, src_ip, src_port, direction,
                dst_ip, dst_port, options, line)


def _split_options(block):
    """Split an option block on ';' but not inside quotes."""
    out, buf, in_q = [], [], False
    for ch in block:
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
        elif ch == ";" and not in_q:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    return out


def _parse_threshold(val):
    # "track by_src, count 5, seconds 30" (also accepts type ...)
    d = {"track": "by_src", "count": 1, "seconds": 60}
    for part in val.split(","):
        part = part.strip()
        if part.startswith("track"):
            d["track"] = part.split()[1]
        elif part.startswith("count"):
            d["count"] = int(part.split()[1])
        elif part.startswith("seconds"):
            d["seconds"] = int(part.split()[1])
    return d


def load_rules(path):
    """Parse a .rules file, joining backslash-continued lines."""
    rules, errors = [], []
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    # join line continuations
    raw = raw.replace("\\\n", " ")
    for n, line in enumerate(raw.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            r = parse_rule(line)
            if r:
                rules.append(r)
        except Exception as exc:  # noqa: BLE001 - collect and report parse errors
            errors.append((n, line.strip(), str(exc)))
    return rules, errors


# --- Address / port matching --------------------------------------------
def _expand_var(token, variables):
    neg = token.startswith("!")
    if neg:
        token = token[1:]
    if token.startswith("$"):
        token = variables.get(token[1:], "any")
    return neg, token


def ip_matches(token, ip, variables):
    if token == "any" or ip is None:
        return True
    neg, token = _expand_var(token, variables)
    # token may be a bracketed list [a,b] or single value
    token = token.strip("[]")
    ok = False
    try:
        addr = ipaddress.ip_address(ip)
        for part in token.split(","):
            part = part.strip()
            if part == "any":
                ok = True
                break
            net = ipaddress.ip_network(part, strict=False)
            if addr in net:
                ok = True
                break
    except ValueError:
        ok = False
    return (not ok) if neg else ok


def port_matches(token, port):
    if token == "any" or port is None:
        return True
    neg = token.startswith("!")
    if neg:
        token = token[1:]
    token = token.strip("[]")
    ok = False
    for part in token.split(","):
        part = part.strip()
        if part == "any":
            ok = True
        elif ":" in part:  # range like 1024:65535 or :1024 or 1024:
            lo, _, hi = part.partition(":")
            lo = int(lo) if lo else 0
            hi = int(hi) if hi else 65535
            if lo <= port <= hi:
                ok = True
        elif part.isdigit() and int(part) == port:
            ok = True
        if ok:
            break
    return (not ok) if neg else ok
