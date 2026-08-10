# MySQL Inspection Toolkit

> 三步出报告：采集 → 分析 → Word

一套面向 MySQL DBA 的轻量级巡检工具。一个 Shell 脚本在数据库服务器上采集信息，Python 分析引擎运行 24 条巡检规则，最终生成专业的 Word 巡检报告。

## 为什么用这个

- **零侵入**：全程只读，不打搅业务
- **三步完成**：`采集 → 分析 → 报告`，无需配置数据库、不需要 Grafana
- **阈值可调**：改 JSON 文件就能调整告警灵敏度，不用看代码
- **输出 Word**：直接交付给客户或领导，图表、评分、建议一应俱全
- **支持多节点**：可以一次分析主库+多个从库的采集包

## 快速开始

```bash
# 第 1 步：在 MySQL 服务器上采集（约 35 秒）
bash mysql_inspection_standard.sh --login-path inspection

# 第 2 步：在分析机上分析采集包
python analyze_inspection_v2.py 采集包.tar.gz --output ./out

# 第 3 步：生成 Word 报告
python generate_report_docx_v3.py ./out \
  --customer "XX公司" \
  --target "核心业务数据库"
```

## 环境要求

**MySQL 服务器上：**
- Bash 4.0+
- mysql 客户端
- sysstat（sar / sadf）

**分析机上：**
- Python 3.9+
- `pip install python-docx matplotlib`

## 巡检规则覆盖

| 类别 | 检查项 |
|------|--------|
| 系统资源 | CPU、内存、IO wait、磁盘使用率 |
| 连接 | 连接数使用率 |
| 性能 | Buffer Pool 命中率、临时表落盘、表缓存命中 |
| Schema | 无主键表、冗余索引、自增键容量、碎片表、非 InnoDB 表 |
| SQL | 无索引查询、未使用索引的 SQL 摘要 |
| 事务与锁 | 长事务、锁等待 |
| 复制 | 复制线程状态、延迟 |
| 安全 | root 远程登录 |
| 备份 | 最近备份验证 |
| 日志 | 错误日志异常事件 |

## 调整规则阈值

打开 `inspection_rules.json`，直接改数字：

```json
"COMMON.SYSTEM.CPU_PRESSURE": {
  "threshold": { "cpu_peak_warning": 80 }
}
```

CPU 告警阈值从 90% 降到 80%。长事务、复制延迟、连接数等同理。

## 可选：LLM 增强报告

```bash
export OPENAI_API_KEY=sk-xxx
python enhance_report.py ./out --model deepseek-chat --base https://api.deepseek.com/v1
```

会用 LLM 重写风险建议和综合结论，让报告文字更专业。

## 项目结构

```
├── mysql_inspection_standard.sh   # 采集脚本（MySQL 服务器上执行）
├── analyze_inspection_v2.py       # 分析引擎
├── generate_report_docx_v3.py     # Word 报告生成
├── enhance_report.py              # LLM 增强（可选）
├── rules.py                       # 规则引擎
├── inspection_rules.json          # 规则阈值配置
├── chart_style.py                 # 图表样式
└── logo.png                       # 封面 Logo（可替换）
```

## 参与贡献

这个项目还很年轻，需要你帮忙测试和改进。不管是不是程序员，都可以参与：

### 没有代码能力？

直接在 [Issues](https://github.com/wangjinsong-ai/mysql-inspection-toolkit/issues) 里提：

- **Bug 报告** — 哪个环节报错、什么环境、贴日志
- **功能建议** — 你希望巡检覆盖什么、报告怎么展示更好
- **实测反馈** — 跑了你的环境，结果准不准、哪里不对

### 会写代码？

Fork → 改代码 → 提 PR：

```bash
git clone https://github.com/YOUR_USERNAME/mysql-inspection-toolkit.git
cd mysql-inspection-toolkit
# 改代码...
git commit -m "feat: 你的改动描述"
git push
# 然后去 GitHub 页面点 "New Pull Request"
```

改之前最好先在 Issue 里说一声要做什么，避免重复劳动。

### 最需要帮助的方向

| 方向 | 说明 |
|------|------|
| **测试** | 在不同 MySQL 版本（5.7 / 8.0 / 8.4）、不同 OS 上跑一遍，反馈兼容性（核心功能全版本通用，锁分析/错误日志等高级功能 5.7 自动降级） |
| **新规则** | `inspection_rules.json` 加定义 + `rules.py` 加检查逻辑，扩充巡检覆盖面 |
| **报告样式** | `generate_report_docx_v3.py` 和 `chart_style.py`，改进 Word 排版和图表效果 |
| **Shell 兼容性** | 采集脚本目前只测了 RHEL/CentOS，欢迎在其他 Linux 发行版测试 |
| **英语支持** | 报告和规则目前是中文，需要英文 / 多语言支持 |
| **新数据库** | PostgreSQL / Oracle / SQL Server 巡检适配（架构设计已预留扩展空间） |

## License

MIT
