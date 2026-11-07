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
        eids=("4946", "4947", "4948", "5024", "5025"),
        description="4946 详情含规则名称与方向(Inbound/Outbound)",
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
