"""Quick-query enrichment: EventData extraction, conclusions, heuristics.

Turns a raw event XML blob into the three quick-tab fields added in
方向一/方向四:

* ``fields``     - ``<Data Name="X">value</Data>`` pairs (plus well-known
  UserData tags), case preserved but looked up case-insensitively.
* ``summary``    - a one-line human-readable conclusion, e.g.
  ``用户 admin 以 远程交互(RDP)(Type 10) 登录 | 来源 1.2.3.4``.
* ``suspicious`` - heuristic red-flag reasons (external source IP, encoded
  command lines, admin-group changes, log clearing, flag patterns, ...).

The module is UI-agnostic: scanner fills the :class:`~evtx_flaghunter.model.
RecordHit` slots, GUI/CLI/exporters only render them.
"""

from __future__ import annotations

import re
from html import unescape as _xml_unescape
from typing import Callable

from evtx_flaghunter.model import RecordHit

# -- EventData parsing --------------------------------------------------------

_DATA_RE = re.compile(
    r'<Data\s+Name="([^"]+)"[^>]*>(.*?)</Data>', re.DOTALL | re.IGNORECASE
)
#: Real EVTX renders EventData children as plain tags (``<LogonType>10</…``),
#: while hand-written fixtures often use the ``<Data Name="…">`` form.
_EVENTDATA_RE = re.compile(
    r"<EventData[^>]*>(.*?)</EventData>", re.DOTALL | re.IGNORECASE
)
_PLAIN_TAG_RE = re.compile(r"<([A-Za-z_][\w]*)>(.*?)</\1>", re.DOTALL)
#: UserData events (RDP 1149/21/24/25, TaskScheduler) carry ParamN attributes.
_PARAM_ATTR_RE = re.compile(r'\b(Param\d+)="([^"]*)"')
#: UserData-style plain tags that some providers emit instead of Data pairs.
_KNOWN_TAGS = (
    "SubjectUserName", "SubjectDomainName", "TargetUserName", "Channel",
    "ThreatName", "Threat Name", "SeverityName", "Severity Name",
    "ActionName", "Action Name", "Path", "ProcessName", "ScriptBlockText",
)
_KNOWN_TAG_RE = re.compile(
    r"<(" + "|".join(re.escape(t) for t in _KNOWN_TAGS) + r")>(.*?)</\1>",
    re.DOTALL | re.IGNORECASE,
)


def parse_event_data(xml: str) -> dict[str, str]:
    """Collect event payload fields from *xml* (first occurrence wins).

    Handles the ``<Data Name="X">`` form, the plain-tag EventData form and
    UserData ``ParamN`` attributes used by providers such as RDP 1149 or
    TaskScheduler 106.
    """
    fields: dict[str, str] = {}
    for match in _DATA_RE.finditer(xml):
        fields.setdefault(match.group(1), _xml_unescape(match.group(2).strip()))
    for match in _EVENTDATA_RE.finditer(xml):
        for tag in _PLAIN_TAG_RE.finditer(match.group(1)):
            fields.setdefault(tag.group(1), _xml_unescape(tag.group(2).strip()))
    for match in _PARAM_ATTR_RE.finditer(xml):
        fields.setdefault(match.group(1), _xml_unescape(match.group(2)))
    for match in _KNOWN_TAG_RE.finditer(xml):
        fields.setdefault(match.group(1), _xml_unescape(match.group(2).strip()))
    return fields


def get_field(fields: dict[str, str], name: str) -> str:
    """Case-insensitive field lookup (providers mix ``param1``/``Param1``)."""
    lowered = name.lower()
    for key, value in fields.items():
        if key.lower() == lowered:
            return value
    return ""


# -- lookup tables ------------------------------------------------------------

LOGON_TYPES: dict[str, str] = {
    "2": "交互", "3": "网络", "4": "批处理", "5": "服务", "7": "解锁",
    "8": "网络明文", "9": "新凭据", "10": "远程交互(RDP)", "11": "缓存交互",
}

SUB_STATUS: dict[str, str] = {
    "0xc0000064": "用户不存在", "0xc000006a": "密码错误",
    "0xc0000072": "账户已禁用", "0xc0000234": "账户已锁定",
    "0xc000006f": "登录时间受限", "0xc0000070": "工作站受限",
    "0xc0000071": "密码过期", "0xc0000133": "时钟偏差过大",
}

#: Paths / tokens in service images, task commands and scripts that smell
#: like attacker infrastructure in CTF-style scenarios.
_SUSPICIOUS_PATH_TOKENS = (
    "\\temp\\", "\\appdata\\", "\\users\\public\\", "\\downloads\\",
    "\\perflogs\\", "\\windows\\tasks\\", "powershell", "-enc",
    "frombase64", "http://", "https://", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "\\programdata\\",
)
_SUSPICIOUS_CMD_TOKENS = (
    "-enc", "frombase64string", "downloadstring", "invoke-expression",
    "iex ", "webclient", "mimikatz", "bypass", "-w hidden", "-nop",
    "net user", "net localgroup", "whoami", "vssadmin delete",
)
_ADMIN_GROUP_TOKENS = ("administrators", "domain admins", "管理员", "512")
_FLAG_RE = re.compile(r"(?i)(?:flag|ctf)\{[^}\s]{1,100}\}")
_PRIVATE_V4 = ("10.", "192.168.", "127.", "169.254.")


def _is_external_ip(ip: str) -> bool:
    """True when *ip* looks like a non-RFC1918 address (attacker-ish)."""
    value = (ip or "").strip().lower()
    if not value or value in {"-", "::1", "127.0.0.1", "local"}:
        return False
    if value.startswith(_PRIVATE_V4):
        return False
    if value.startswith("172."):
        try:
            second = int(value.split(".")[1])
        except (IndexError, ValueError):
            return True
        return not 16 <= second <= 31
    return True


def _account(fields: dict[str, str], name: str = "TargetUserName") -> str:
    """``DOMAIN\\user`` form, falling back to the bare user name."""
    user = get_field(fields, name)
    domain = get_field(fields, name.replace("UserName", "DomainName"))
    if domain and domain not in {"-", "NT AUTHORITY", "NT AUTHORITY\\"}:
        return f"{domain}\\{user}" if user else domain
    return user or "(空)"


def _cn(value: str) -> str:
    """Strip ``CN=...`` DN syntax down to the first component."""
    if value.upper().startswith("CN="):
        return value[3:].split(",", 1)[0]
    return value


def _ip(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = get_field(fields, name)
        if value and value not in {"-", "::1"}:
            return value
    return ""


def _task_xml(fields: dict[str, str]) -> str:
    """Unescaped scheduled-task XML content (EID 4698/4702)."""
    raw = get_field(fields, "TaskContentNew") or get_field(fields, "TaskContent")
    return _xml_unescape(raw) if raw else ""


def _task_command(fields: dict[str, str]) -> str:
    text = _task_xml(fields)
    if not text:
        return ""
    command = re.search(
        r"<Command>(.*?)</Command>", text, re.DOTALL | re.IGNORECASE
    )
    arguments = re.search(
        r"<Arguments>(.*?)</Arguments>", text, re.DOTALL | re.IGNORECASE
    )
    parts = [command.group(1).strip() if command else ""]
    if arguments:
        parts.append(arguments.group(1).strip())
    return " ".join(part for part in parts if part)


# -- per-EID summary renderers -------------------------------------------------
# Each renderer maps one event ID to a one-line conclusion. Unknown event IDs
# keep summary="" and the GUI falls back to the raw context snippet.

def _r_4624(f: dict[str, str]) -> str:
    lt = get_field(f, "LogonType")
    parts = [
        f"用户 {_account(f)} 以 {LOGON_TYPES.get(lt, lt or '?')}"
        f"(Type {lt or '?'}) 登录"
    ]
    ip = _ip(f, "IpAddress")
    if ip:
        parts.append(f"来源 {ip}")
    ws = get_field(f, "WorkstationName")
    if ws and ws != "-":
        parts.append(f"工作站 {ws}")
    proc = get_field(f, "ProcessName")
    if proc and proc != "-":
        parts.append(f"由 {proc}")
    return " | ".join(parts)


def _r_4625(f: dict[str, str]) -> str:
    lt = get_field(f, "LogonType")
    sub = get_field(f, "SubStatus") or get_field(f, "Status")
    reason = SUB_STATUS.get(sub.lower(), sub or "未知原因")
    parts = [
        f"用户 {_account(f)} 登录失败: {reason}(Type {lt or '?'})"
    ]
    ip = _ip(f, "IpAddress")
    if ip:
        parts.append(f"来源 {ip}")
    return " | ".join(parts)


def _r_4648(f: dict[str, str]) -> str:
    server = get_field(f, "TargetServerName")
    text = f"用户 {_account(f, 'SubjectUserName')} 以显式凭据访问 {_account(f)}"
    if server and server != "-":
        text += f" @ {server}"
    return text


def _r_4672(f: dict[str, str]) -> str:
    return f"特权账户 {_account(f, 'SubjectUserName')} 被分配特权"


def _r_logoff(f: dict[str, str]) -> str:
    lt = get_field(f, "LogonType")
    return (
        f"用户 {_account(f)} 注销 "
        f"({LOGON_TYPES.get(lt, lt or '?')} Type {lt or '?'})"
    )


def _r_session(kind: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        account = get_field(f, "AccountName") or _account(f)
        client = _ip(f, "ClientAddress", "IpAddress")
        text = f"RDP 会话{kind}: {account}"
        if client:
            text += f" 来自 {client}"
        return text

    return render


def _r_1149(f: dict[str, str]) -> str:
    user = get_field(f, "Param1") or get_field(f, "User")
    domain = get_field(f, "Param2") or get_field(f, "Domain")
    ip = _ip(f, "Param3", "IpAddress", "ClientAddress")
    account = f"{domain}\\{user}" if domain and user else (user or domain)
    text = f"RDP 远程连接: {account or '(空)'}"
    if ip:
        text += f" 来自 {ip}"
    return text


def _r_local_session(kind: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        user = get_field(f, "Param1") or get_field(f, "User")
        ip = _ip(f, "Param3", "ClientAddress")
        text = f"RDP 本地会话{kind}: {user or '(空)'}"
        if ip:
            text += f" 来自 {ip}"
        return text

    return render


def _r_4688(f: dict[str, str]) -> str:
    proc = get_field(f, "NewProcessName") or get_field(f, "ProcessName")
    text = f"进程创建: {proc or '(空)'}"
    creator = get_field(f, "SubjectUserName")
    if creator:
        text += f"（发起者 {creator}）"
    return text


def _r_4689(f: dict[str, str]) -> str:
    return f"进程退出: {get_field(f, 'ProcessName') or '(空)'}"


def _r_task(action: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        name = (
            get_field(f, "TargetName")
            or get_field(f, "TaskName")
            or get_field(f, "Param1")
            or "(空)"
        )
        text = f"{action} 计划任务 \"{name}\""
        actor = get_field(f, "SubjectUserName") or get_field(f, "Param2")
        if actor:
            text += f"（操作者 {actor}）"
        command = _task_command(f)
        if command:
            text += f" | 执行: {command}"
        return text

    return render


def _r_firewall(action: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        rule = get_field(f, "RuleName") or "(未命名规则)"
        direction = get_field(f, "Direction")
        return f"防火墙规则{action}: {rule} ({direction or '方向未知'})"

    return render


def _r_4719(f: dict[str, str]) -> str:
    return (
        f"审核策略更改（操作者 {_account(f, 'SubjectUserName')}，"
        f"子类别 {get_field(f, 'SubcategoryGuid') or '?'}）"
    )


def _r_1102(f: dict[str, str]) -> str:
    return f"Security 日志被 {_account(f, 'SubjectUserName')} 清除"


def _r_104(f: dict[str, str]) -> str:
    channel = get_field(f, "Channel") or "日志"
    return f"{channel} 日志被 {get_field(f, 'SubjectUserName') or '?'} 清除"


def _r_defender_detect(f: dict[str, str]) -> str:
    threat = get_field(f, "ThreatName") or get_field(f, "Threat Name") or "?"
    severity = get_field(f, "SeverityName") or get_field(f, "Severity Name")
    path = get_field(f, "Path") or get_field(f, "Path Name")
    text = f"Defender 检测到威胁 {threat}"
    if severity:
        text += f"（严重度 {severity}）"
    if path:
        text += f" 路径 {path}"
    return text


def _r_defender_action(kind: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        threat = get_field(f, "ThreatName") or get_field(f, "Threat Name")
        return f"Defender {kind}: {threat or '?'}"

    return render


def _r_4104(f: dict[str, str]) -> str:
    text = get_field(f, "ScriptBlockText")
    return f"PowerShell 脚本块: {text[:200]}" if text else "PowerShell 脚本块执行"


def _r_4720(action: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        target = get_field(f, "SamAccountName") or get_field(f, "TargetUserName")
        actor = get_field(f, "SubjectUserName")
        text = f"{action} 账户 {target or '(空)'}"
        if actor:
            text += f"（操作者 {actor}）"
        return text

    return render


def _r_group_change(f: dict[str, str]) -> str:
    member = _cn(get_field(f, "MemberName"))
    group = _cn(get_field(f, "TargetUserName"))
    actor = get_field(f, "SubjectUserName")
    text = f"成员 {member or '(空)'} 加入组 {group or '(空)'}"
    if actor:
        text += f"（操作者 {actor}）"
    return text


def _r_7045(f: dict[str, str]) -> str:
    name = get_field(f, "ServiceName") or "?"
    image = get_field(f, "ImagePath")
    account = get_field(f, "AccountName")
    text = f"安装新服务 \"{name}\""
    if image:
        text += f" | 程序: {image}"
    if account and account != "-":
        text += f" | 运行身份: {account}"
    return text


def _r_7036(f: dict[str, str]) -> str:
    return (
        f"服务 {get_field(f, 'param1') or '?'} "
        f"进入 {get_field(f, 'param2') or '?'} 状态"
    )


def _r_7040(f: dict[str, str]) -> str:
    return (
        f"服务 {get_field(f, 'param1') or '?'} 启动类型变更为 "
        f"{get_field(f, 'param2') or '?'}"
    )


def _r_share(kind: str) -> Callable[[dict[str, str]], str]:
    def render(f: dict[str, str]) -> str:
        account = get_field(f, "AccountName") or "(空)"
        source = _ip(f, "SourceAddress", "IpAddress", "ClientAddress")
        share = get_field(f, "ShareName") or "?"
        text = f"SMB {kind}: {account} 从 {source or '?'} 访问 {share}"
        target = get_field(f, "RelativeTargetName")
        if target:
            text += f"\\{target}"
        return text

    return render


def _r_priv_use(f: dict[str, str]) -> str:
    proc = get_field(f, "ProcessName")
    return f"特权调用: {_account(f, 'SubjectUserName')} via {proc or '?'}"


RENDERERS: dict[str, Callable[[dict[str, str]], str]] = {
    "4624": _r_4624,
    "4625": _r_4625,
    "4648": _r_4648,
    "4672": _r_4672,
    "4634": _r_logoff,
    "4647": _r_logoff,
    "4778": _r_session("重连"),
    "4779": _r_session("断开"),
    "1149": _r_1149,
    "21": _r_local_session("登录"),
    "24": _r_local_session("断开"),
    "25": _r_local_session("重连"),
    "4688": _r_4688,
    "4689": _r_4689,
    "4698": _r_task("创建"),
    "4699": _r_task("删除"),
    "4700": _r_task("启用"),
    "4701": _r_task("禁用"),
    "4702": _r_task("更新"),
    "106": _r_task("注册"),
    "140": _r_task("修改"),
    "141": _r_task("删除"),
    "4946": _r_firewall("添加"),
    "4947": _r_firewall("修改"),
    "4948": _r_firewall("删除"),
    "4719": _r_4719,
    "1102": _r_1102,
    "104": _r_104,
    "1116": _r_defender_detect,
    "1117": _r_defender_action("已采取措施"),
    "1118": _r_defender_action("处置失败"),
    "1119": _r_defender_action("严重威胁处置"),
    "5001": _r_defender_action("实时防护被关闭"),
    "5007": _r_defender_action("防护配置被修改"),
    "4104": _r_4104,
    "4720": _r_4720("创建"),
    "4722": _r_4720("启用"),
    "4724": _r_4720("重置密码"),
    "4726": _r_4720("删除"),
    "4740": _r_4720("锁定"),
    "4728": _r_group_change,
    "4732": _r_group_change,
    "4756": _r_group_change,
    "7045": _r_7045,
    "7036": _r_7036,
    "7040": _r_7040,
    "5140": _r_share("连接"),
    "5145": _r_share("详细访问"),
    "4673": _r_priv_use,
    "4674": _r_priv_use,
}


# -- heuristic suspicion scoring (方向四) ---------------------------------------

def _token_hit(text: str, tokens: tuple[str, ...]) -> str | None:
    lowered = text.lower()
    for token in tokens:
        if token in lowered:
            return token
    return None


def assess_suspicious(eid: str, fields: dict[str, str]) -> list[str]:
    """Return heuristic red-flag reasons for one event (方向四)."""
    reasons: list[str] = []

    def source_ip() -> str:
        return _ip(fields, "IpAddress", "SourceAddress", "ClientAddress",
                   "Param3")

    if eid in {"4624", "4625"}:
        user = get_field(fields, "TargetUserName")
        has_user_field = any(
            key.lower() == "targetusername" for key in fields
        )
        if user == "Anonymous Logon" or (user == "" and has_user_field):
            reasons.append("匿名/空用户登录")
        ip = source_ip()
        if ip and _is_external_ip(ip):
            reasons.append(f"外部来源 IP {ip}")
    elif eid == "7045":
        token = _token_hit(get_field(fields, "ImagePath"),
                           _SUSPICIOUS_PATH_TOKENS)
        if token:
            reasons.append(f"服务镜像路径可疑（{token.strip()}）")
    elif eid in {"4698", "4702"}:
        token = _token_hit(_task_xml(fields), _SUSPICIOUS_CMD_TOKENS)
        if token:
            reasons.append(f"计划任务命令可疑（{token.strip()}）")
    elif eid == "4104":
        token = _token_hit(get_field(fields, "ScriptBlockText"),
                           _SUSPICIOUS_CMD_TOKENS)
        if token:
            reasons.append(f"脚本内容可疑（{token.strip()}）")
    elif eid == "4688":
        token = _token_hit(get_field(fields, "CommandLine"),
                           _SUSPICIOUS_CMD_TOKENS)
        if token:
            reasons.append(f"命令行可疑（{token.strip()}）")
    elif eid in {"4728", "4732", "4756"}:
        group = (get_field(fields, "TargetUserName") or "").lower()
        if any(name in group for name in _ADMIN_GROUP_TOKENS):
            reasons.append(f"成员被加入管理员组 {_cn(get_field(fields, 'TargetUserName'))}")
    elif eid in {"1102", "104"}:
        reasons.append("事件日志被清除")
    elif eid == "4740":
        reasons.append("账户被锁定（可能由爆破触发）")
    elif eid == "5001":
        reasons.append("Defender 实时防护被关闭")

    # Generic cross-scenario rule: a flag pattern hidden in any field value.
    for value in fields.values():
        if _FLAG_RE.search(value):
            reasons.append("字段包含 flag 格式内容")
            break
    return reasons


def enrich_hit(hit: RecordHit) -> None:
    """Fill ``summary`` / ``fields`` / ``suspicious`` on a quick-query hit."""
    fields = parse_event_data(hit.content)
    hit.fields = fields
    renderer = RENDERERS.get(hit.event_id)
    hit.summary = renderer(fields) if renderer else ""
    hit.suspicious = assess_suspicious(hit.event_id, fields)
