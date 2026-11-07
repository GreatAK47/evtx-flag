# EVTX-FlagHunter

CTF 场景专用的 Windows 事件日志 (.evtx) 关键字检索工具。**图形界面优先**：
拖入文件 → 点一下"开始检索" → 秒级输出命中记录的时间、事件 ID、来源与完整内容，
Base64/Hex 编码内容自动解码展示。

对应设计方案见上级目录《EVTX-FlagHunter 设计方案.md》（当前实现覆盖 P1 里程碑，
并向 P2 部分延伸：正则模式、预设模板、自定义模板文件、自动解码展示）。

## 项目结构

```
evtx-flaghunter/
├── pyproject.toml              # 项目配置与依赖（含 evtxflaghunt 命令入口）
├── requirements.txt            # pip 依赖清单
├── samples/                    # 测试样本（system.evtx 可由 wevtutil 导出）
├── evtx_flaghunter/
│   ├── __init__.py             # 包入口，暴露核心 API
│   ├── __main__.py             # python -m evtx_flaghunter（默认 GUI，--cli 走命令行）
│   ├── model.py                # 数据模型：ScanConfig / RecordHit / FileEntry / DecodedSpan
│   ├── detect.py               # 魔数识别：EVTX / RECOVER(容错恢复) / EVT / UNKNOWN
│   ├── parser.py               # evtx(Rust 内核绑定) 解析 + JSON→XML 还原 + 字段抽取
│   ├── evt_parser.py           # EVT-Legacy：XP/2003 遗留 .evt 纯 Python 解析
│   ├── matcher.py              # 匹配引擎：Aho-Corasick 精确 + 正则（模糊）
│   ├── decode.py               # Base64/Hex/URL/ROT13 自动解码与防误报启发式
│   ├── presets.py              # 内置 CTF 模板（flag/ctf/sqli/ps-enc/webshell/all）
│   ├── scanner.py              # 编排层：文件收集(zip 解压) → 过滤 → 匹配 → 事件流
│   ├── exporter.py             # 导出：JSON / JSONL / CSV
│   ├── cli.py                  # 命令行接口（GUI 的镜像，见设计方案 4.4）
│   └── gui.py                  # 图形界面（tkinter + tkinterdnd2 拖拽，主形态）
└── tests/
    ├── test_detect.py          # 魔数识别（含改名文件、损坏头部、遗留 EVT）
    ├── test_decode.py          # 解码正确性 + 误报回归
    ├── test_matcher.py         # 精确/正则/大小写模式
    ├── test_exporter.py        # 三种导出格式
    ├── test_scanner.py         # 输入展开、zip 解压、模板合并、JSON→XML
    ├── test_evt.py             # EVT-Legacy：XP/2003 遗留 .evt 解析与容错
    └── test_e2e.py             # 真实样本端到端（无样本时自动跳过）
```

## 环境要求与安装

- Windows 10/11，Python 3.10+（3.13 验证通过）
- tkinter 为 Python 自带；拖拽需 `tkinterdnd2`

```powershell
cd evtx-flaghunter
pip install -r requirements.txt
# 或作为包安装（获得 evtxflaghunt 命令）：
pip install -e .
```

## 运行指引

```powershell
# 图形界面（主形态，推荐）
python -m evtx_flaghunter

# 命令行（辅助形态）：零参数默认 flag 模板
python -m evtx_flaghunter --cli .\samples\system.evtx
python -m evtx_flaghunter --cli .\logs\ -r "flag\{[^}]+\}" --nested --top 5

# 安装后可用全局命令
evtxflaghunt .\logs\ -k flag{ ctf{ -o result.json
```

GUI 使用：拖入 .evtx / 文件夹 / .zip →（可选：左侧面板调选项）→ 点【开始检索】
→ 结果表双击行查看完整记录与解码层 → 复制片段 / 导出 JSON/CSV。

## 单元测试

```powershell
python -m pytest tests -q
```

当前状态：**55 passed**（含真实样本端到端与 .evt 遗留格式测试；`samples/system.evtx`
可用 `wevtutil epl System samples\system.evtx` 重新生成）。

## 核心特性（对照设计方案）

| 设计条目 | 实现状态 |
|---|---|
| 批量解析 + 目录递归 + zip 自动解压 | 已实现 |
| 魔数自动识别（扩展名仅提示，改名不漏识） | 已实现 |
| 精确匹配（Aho-Corasick）+ 正则模糊模式 | 已实现 |
| 内置 CTF 模板 + 自定义模板文件 (`--preset-file`) | 已实现 |
| Base64/Hex/URL 自动解码展示 + 嵌套解码匹配 (`--nested`) | 已实现 |
| 自定义提取正则 (`--extract`)、事件ID/时间过滤、`--top` | 已实现 |
| 导出 JSON/JSONL/CSV（字段同设计方案 7.4） | 已实现 |
| GUI：拖拽、一键检索、结果表、详情面板、导出 | 已实现 |
| XP/2003 遗留 .evt 解析（EVT-Legacy） | 已实现（含损坏记录 resync 容错） |
| 编辑距离近似匹配、YAML 自定义解码规则 | 待 P2 |
| chunk 预扫描快路径、多文件并行 | 待 P3（当前单线程流式） |

## 异常处理约定

- 单条记录损坏不影响整文件；文件级损坏记录错误并继续其余文件（FR-9）
- 解码失败/非法正则/坏 zip 均降级为提示，不中断扫描
- 后台扫描线程内的意外异常会转为错误事件回传 UI，绝不静默崩溃
