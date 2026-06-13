# sshman

SSH 会话管理 CLI 工具 — 管理多台服务器的 SSH 连接，支持加密配置持久化和一键自动登录。

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-58%20passed-brightgreen.svg)](tests/)

## 功能

- **会话管理** — 添加、删除、列出、搜索 SSH 会话（支持标签和关键词过滤）
- **加密存储** — AES-256-GCM 加密 YAML 配置，主密码通过 Argon2id 派生密钥
- **自动登录** — 基于 pexpect，自动处理主机密钥确认、密码提示、MFA 验证码
- **交互式向导** — `sshman add` 逐步引导添加新会话
- **配置安全** — 明文仅存内存，文件强制 `chmod 600`，进程退出即释放

## 快速开始

### 安装

```bash
git clone <repo-url>
cd sshman

# 一键安装（创建 venv + 安装依赖 + 注册系统命令）
./scripts/install.sh
```

安装后新开终端即可直接使用 `sshman` 命令。

如需卸载：
```bash
sudo rm /usr/local/bin/sshman    # 移除系统命令
rm -rf ~/.sshman                  # 删除配置和日志
```

### 初始化

```bash
sshman init
# 输入并确认主密码（用于加密配置文件）
```

### 添加会话

```bash
# 交互式向导
sshman add
# 或通过命令行参数
sshman add --name dev-server --host 192.168.1.10 --user root --tags dev,web
```

### 连接

```bash
sshman connect dev-server
```

### 查看所有会话

```bash
sshman list                    # 表格视图
sshman list --detail           # 详细信息
sshman list --tag prod         # 按标签过滤
sshman list --keyword beijing  # 关键词搜索
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `sshman init` | 初始化配置目录、生成加密盐、设置主密码 |
| `sshman add` | 交互式添加新 SSH 会话 |
| `sshman list` | 列出所有会话（`--tag` `--keyword` `--detail`） |
| `sshman connect <name>` | 连接指定会话（自动处理登录交互） |
| `sshman remove <name>` | 删除会话（`--force` 跳过确认） |
| `sshman crypto encrypt` | 手动加密配置文件 |
| `sshman crypto decrypt` | 手动解密配置文件（输出 YAML） |

## 配置存储

所有数据存储在 `~/.sshman/`：

```
~/.sshman/
├── config.enc     # AES-256-GCM 加密的 YAML 配置文件
├── .salt          # Argon2id 密钥派生用盐（明文）
└── logs/          # 操作日志目录（预留）
```

配置文件内部结构（解密后）：

```yaml
sessions:
  - name: prod-web-01
    host: 10.0.1.100
    port: 22
    user: admin
    password: ""           # 留空则使用密钥或交互式提示
    identity_file: ~/.ssh/id_ed25519
    tags: [prod, web]
    jumphost: ""           # 跳板机（Phase 2）
    tunnels: []            # 端口转发（Phase 2）
    notes: ""
    auto_log: false
    keepalive: 60

settings:
  default_user: root
  default_port: 22
  connect_timeout: 10
```

## 开发

```bash
source venv/bin/activate
pip install -e ".[dev]"

# 运行全部测试
python3 -m pytest tests/ -v

# 单文件测试
python3 -m pytest tests/test_crypto.py -v

# 覆盖率
pip install pytest-cov
python3 -m pytest tests/ -v --cov=sshman --cov-report=term-missing
```

## 路线图

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 | 核心骨架 + 基础连接（init/add/list/connect/remove） | ✅ 完成 |
| Phase 2 | 跳板机 ProxyJump、端口转发 -L/-R/-D | 计划中 |
| Phase 3 | 批量命令执行、并发控制、健康检查 | 计划中 |
| Phase 4 | 配置导入（ssh_config/Ansible/CSV）、操作日志 | 计划中 |
| Phase 5 | Shell 补全、密码过期提醒、会话分组 | 计划中 |

## 许可

MIT License
