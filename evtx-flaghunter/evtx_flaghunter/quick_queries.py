"""One-click incident-response / forensics event ID queries (FR-2 快速查询).

Each :class:`QuickQuery` bundles the event IDs (plus optional keywords and
regexes) that answer a common DFIR question, e.g. "extract every RDP login"
or "show every scheduled task change". The GUI combo box and the CLI
``--quick`` flag both consume this single registry so the two interfaces
stay mirrored.

Event IDs follow the Microsoft Security auditing reference; channels are
deliberately *not* hard-filtered because CTF archives often rename channel
paths - the event IDs alone are precise enough in practice.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QuickQuery:
    """A named one-click extraction scenario.

    Attributes:
        name: Stable identifier used by the CLI (``--quick NAME``).
        label: Chinese display label shown in the GUI combo box.
        eids: Windows event IDs to filter on.
        keywords: Extra literal keywords merged into the scan.
        regexes: Extra regular expressions merged into the scan.
        description: One-line hint about what the query surfaces.
    """

    name: str
    label: str
    eids: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    regexes: tuple[str, ...] = ()
    description: str = ""


QUICK_QUERIES: dict[str, QuickQuery] = {
    "rdp-login": QuickQuery(
        name="rdp-login",
        label="远程桌面(RDP)登录",
        eids=("4624", "4672", "4778", "4779", "21", "24", "25", "1149"),
        description="RDP 成功登录与会话重连；4624 需关注 Logon Type 10",
    ),
    "logon-success": QuickQuery(
        name="logon-success",
        label="所有成功登录",
        eids=("4624", "4648", "4672"),
        description="成功登录/显式凭据/特权登录，首次入侵时间排查",
    ),
    "logon-fail": QuickQuery(
        name="logon-fail",
        label="登录失败(爆破)",
        eids=("4625", "4771", "4776"),
        description="本地与 Kerberos/NTLM 认证失败，爆破与口令喷洒",
    ),
    "logoff": QuickQuery(
        name="logoff",
        label="注销/会话结束",
        eids=("4634", "4647", "4779"),
        description="注销与会话断开，配合登录事件还原在线时间线",
    ),
    "sched-task": QuickQuery(
        name="sched-task",
        label="计划任务 创建/修改/删除",
        eids=("4698", "4699", "4700", "4701", "4702", "106", "140", "141"),
        description="4698 详情含 Task XML：<Command> 路径与 <Arguments> 参数",
    ),
    "firewall-rule": QuickQuery(
        name="firewall-rule",
        label="防火墙规则 添加/修改/删除",
        eids=("4946", "4947", "4948", "2003", "2004", "2005", "2006",
              "5024", "5025"),
        description="4946-4948=Security审计版；2004/2005/2006=Firewall通道"
                    "规则添加/修改/删除，2003=配置文件设置更改(开关防火墙)",
    ),
    "audit-policy": QuickQuery(
        name="audit-policy",
        label="审核策略更改",
        eids=("4719", "4739", "1100"),
        description="4719 含 Subcategory GUID，需对照本地策略名",
    ),
    "log-clear": QuickQuery(
        name="log-clear",
        label="事件日志清除",
        eids=("1102", "104", "1100"),
        description="1102=安全日志清除，104=任意日志清除(写明日志全名)",
    ),
    "defender": QuickQuery(
        name="defender",
        label="杀软检测与处置(Defender)",
        eids=("1015", "1116", "1117", "1118", "1119", "5001", "5007"),
        description="1116=威胁检测(工具名/路径)，1117=已采取措施",
    ),
    "powershell": QuickQuery(
        name="powershell",
        label="PowerShell 命令执行",
        eids=("4104", "4103", "400", "600", "800"),
        description="4104 脚本块日志含完整命令文本",
    ),
    "account-change": QuickQuery(
        name="account-change",
        label="账户 创建/删除/加组",
        eids=("4720", "4722", "4724", "4726", "4728", "4732", "4756", "4740"),
        description="新建后门账户与特权组成员变动",
    ),
    "service-install": QuickQuery(
        name="service-install",
        label="服务安装(持久化)",
        eids=("7045", "7036", "7040"),
        description="7045 新服务安装，常见持久化/提权后门载体",
    ),
    "process-create": QuickQuery(
        name="process-create",
        label="进程创建与退出",
        eids=("4688", "4689"),
        description="需开启审核进程创建策略，4688 含命令行(带 4688 扩展)",
    ),
    "share-access": QuickQuery(
        name="share-access",
        label="网络共享访问(SMB)",
        eids=("5140", "5145"),
        description="共享连接与详细访问记录，横向移动排查",
    ),
    "privilege-esc": QuickQuery(
        name="privilege-esc",
        label="特权分配/提权迹象",
        eids=("4672", "4673", "4674", "4732", "4756", "7045"),
        description="特权使用与敏感权限服务安装的组合线索",
    ),
    "kerberos": QuickQuery(
        name="kerberos",
        label="Kerberos 域攻击(TGT/TGS)",
        eids=("4768", "4769", "4770", "4772", "4773", "4777"),
        description=(
            "域控日志：4769 票证请求含 RC4 加密即 Kerberoasting，"
            "黄金票据伪造则完全没有 4768"
        ),
    ),
    "cred-dump": QuickQuery(
        name="cred-dump",
        label="凭据转储线索",
        eids=("4656", "4657", "4663"),
        keywords=("mimikatz", "comsvcs", "procdump", "lsass"),
        description=(
            "4656 对象句柄请求(ObjectName 含 lsass 即凭据转储)，"
            "叠加 mimikatz/comsvcs 等工具关键词全文匹配"
        ),
    ),
    "sysmon": QuickQuery(
        name="sysmon",
        label="Sysmon 行为链(进程/网络/注册表)",
        eids=(
            "1", "2", "3", "7", "8", "9", "10", "11", "12", "13",
            "15", "16", "17", "18", "22", "23", "25", "255",
        ),
        description=(
            "有 Sysmon 部署的样本优先看：1 进程创建/3 网络外联/"
            "8 注入/10 访问 lsass/11 落盘/13 Run 键/22 DNS/25 空壳注入"
        ),
    ),
    "usb-device": QuickQuery(
        name="usb-device",
        label="USB 设备接入溯源",
        eids=("400", "410", "430", "6416"),
        description=(
            "Kernel-PnP 400/410/430 + 6416 新设备识别"
            "（DriverFrameworks 2003 与防火墙 2003 同 ID，走防火墙场景），"
            "U 盘摆渡/数据外带题的入口"
        ),
    ),
    "ransomware": QuickQuery(
        name="ransomware",
        label="勒索软件线索",
        eids=("8194", "8224", "4663"),
        keywords=("vssadmin", "shadow copy", "shadowcopy", "bcdedit", "wbadmin"),
        description=(
            "卷影副本删除(Application 8194/8224) + vssadmin/wbadmin "
            "命令关键词，大量 4663 批量对象访问配合加密行为"
        ),
    ),
}

#: All event IDs referenced by the registry, de-duplicated (kept sorted).
ALL_EIDS: list[str] = sorted({eid for q in QUICK_QUERIES.values() for eid in q.eids})


def get_query(name: str) -> QuickQuery:
    """Return the query registered under *name* (KeyError if unknown)."""
    return QUICK_QUERIES[name]


def quick_choices() -> list[str]:
    """GUI combo box entries, ``label (name)`` for both audiences."""
    return [f"{q.label} ({q.name})" for q in QUICK_QUERIES.values()]


def parse_choice(choice: str) -> QuickQuery:
    """Resolve a combo box entry back to its :class:`QuickQuery`."""
    name = choice.rsplit("(", 1)[-1].rstrip(")").strip()
    return get_query(name)


def apply_query(
    keywords: list[str],
    regexes: list[str],
    eids: list[str],
    query: QuickQuery,
) -> tuple[list[str], list[str], list[str]]:
    """Merge *query* into user-supplied lists, de-duplicated in order.

    Returns:
        ``(keywords, regexes, eids)`` with the query items appended after
        the user's own patterns, so user intent is never overridden.
    """
    merged_keywords = list(dict.fromkeys(list(keywords) + list(query.keywords)))
    merged_regexes = list(dict.fromkeys(list(regexes) + list(query.regexes)))
    merged_eids = list(dict.fromkeys(list(eids) + list(query.eids)))
    return merged_keywords, merged_regexes, merged_eids


# -- emergency "all scenarios" mode + offline smart search (no LLM) -------------

#: Chinese/English keyword aliases per query name, keyed in priority order.
SCENARIO_ALIASES: dict[str, tuple[str, ...]] = {
    "rdp-login": ("远程桌面", "rdp", "3389", "远程登录"),
    "logon-success": ("登录", "登陆", "成功登录", "logon", "首次"),
    "logon-fail": ("失败", "爆破", "brute", "密码错", "猜解"),
    "log-clear": ("清日志", "清除日志", "删除日志", "日志清除", "抹除"),
    "firewall-rule": ("防火墙", "firewall", "放行", "规则"),
    "audit-policy": ("审核策略", "审计", "策略更改", "策略修改"),
    "account-change": ("建账", "新建用户", "用户管理", "加组", "账户"),
    "privilege-esc": ("特权", "提权", "管理员", "special"),
    "kerberos": ("kerberos", "黄金票据", "白银", "kerberoast", "tgt", "tgs", "域控"),
    "cred-dump": ("凭据", "转储", "mimikatz", "lsass", "抓密码", "抓hash"),
    "sysmon": ("sysmon", "注入", "外联", "行为链"),
    "usb-device": ("usb", "u盘", "U盘", "设备接入", "摆渡"),
    "ransomware": ("勒索", "加密", "影子", "卷影", "vss", "后缀"),
    "sched-task": ("计划任务", "schtasks", "定时任务", "任务"),
    "service-install": ("服务", "持久化", "后门服务"),
    "process-create": ("进程", "命令行", "执行命令"),
    "powershell": ("powershell", "ps1", "脚本", "命令执行"),
    "defender": ("杀软", "defender", "病毒", "木马", "隔离", "告警"),
    "share-access": ("共享", "smb", "网络访问", "ipc"),
    "logoff": ("注销", "会话", "断开", "登出"),
}


def match_scenarios(text: str) -> list[QuickQuery]:
    """Offline scenario lookup: match aliases/labels against *text*.

    Pure string containment, no network or model needed. Returns queries
    ordered by match score (alias hits), then registry order.
    """
    lowered = text.strip().lower()
    if not lowered:
        return []
    scored: list[tuple[int, int, QuickQuery]] = []
    for order, query in enumerate(QUICK_QUERIES.values()):
        score = 0
        for alias in SCENARIO_ALIASES.get(query.name, ()):
            if alias.lower() in lowered:
                score += 2
        if query.label.lower() in lowered:
            score += 3
        elif any(word and word.lower() in lowered
                 for word in query.label.replace("(", " ").split("/")):
            score += 1
        if score:
            scored.append((score, -order, query))
    scored.sort(key=lambda item: (-item[0], -item[1]))
    return [query for _, _, query in scored]


def scenario_counts(hits: list) -> list[str]:
    """Per-scenario hit counts for the emergency all-scan summary."""
    eid_to_label: dict[str, str] = {}
    for query in QUICK_QUERIES.values():
        for eid in query.eids:
            eid_to_label.setdefault(eid, query.label)
    counts: dict[str, int] = {}
    for hit in hits:
        label = eid_to_label.get(getattr(hit, "event_id", ""))
        if label:
            counts[label] = counts.get(label, 0) + 1
    return [
        f"  {label} × {count}"
        for label, count in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
