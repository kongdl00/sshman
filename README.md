# sshman

SSH 会话管理 CLI 工具 — 管理多台服务器的 SSH 连接，支持加密配置持久化和一键自动登录。

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-90%20passed-brightgreen.svg)](tests/)

## 功能

- **会话管理** — 添加、删除、编辑、克隆、重命名、搜索 SSH 会话（标签 / 分组 / 关键词）
- **加密存储** — AES-256-GCM 加密 YAML 配置，Argon2id 派生密钥
- **密码缓存** — 主密码和 SSH 密码可存 macOS Keychain / Linux secret-tool
- **自动登录** — pexpect 处理主机密钥、密码、MFA 验证码，跳板机多密码自动填充
- **跳板机** — ProxyJump 引用另一个会话作为跳板
- **端口转发** — -L / -R / -D 三级子命令管理，冒号分隔简洁语法
- **单机命令** — One-liner 远程执行，直接打印输出
- **批量命令** — 并行在多台服务器执行命令，SSH_ASKPASS 自动密码注入
- **健康检查** — TCP 端口可达性 + 配置文件完整性校验
- **配置导入** — 从 ~/.ssh/config、Ansible inventory、CSV 批量导入
- **Shell 补全** — bash / zsh / fish 自动补全

## 快速开始

### 安装

```bash
git clone <repo-url>
cd sshman
./scripts/install.sh          # 一键安装（venv + 依赖 + 系统命令）
```

安装后新开终端即可直接使用。卸载：

```bash
sudo rm /usr/local/bin/sshman
rm -rf ~/.sshman ~/sshman
```

### 初始化

```bash
sshman init                   # 设置主密码，建议勾选 Remember in keychain
```

### 添加会话

```bash
sshman add                    # 交互式向导
# 或命令行参数
sshman add --name dev --host 192.168.1.10 --user root --tags dev,web --group development
```

### 连接

```bash
sshman connect dev
```

### 查看所有会话

```bash
sshman list
sshman list --tag prod --group production --detail
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `sshman init` | 初始化配置、设置主密码 |
| `sshman add` | 添加会话（`--keychain` 存 SSH 密码到 Keychain） |
| `sshman list` | 列出会话（`--tag` `--group` `--keyword` `--detail`） |
| `sshman edit <name>` | 编辑会话字段（只传要改的项） |
| `sshman rename <old> <new>` | 重命名会话 |
| `sshman clone <name> --as <new>` | 复制会话 |
| `sshman remove <name>` | 删除会话（`--force` 跳过确认） |
| `sshman connect <name>` | 连接会话（自动处理登录 + 跳板机 + 隧道） |
| `sshman exec <name> <cmd>` | 单机远程执行命令，直接打印输出 |
| `sshman tunnel add/rm/list/connect` | 管理端口转发（冒号分隔语法） |
| `sshman batch "<cmd>"` | 批量并行执行命令（`--tag` `--group` `--parallel`） |
| `sshman check` | 健康检查（`--config` 校验配置完整性） |
| `sshman import --source <type>` | 导入 ssh_config / Ansible / CSV |
| `sshman crypto encrypt/decrypt` | 手动加解密配置文件 |
| `sshman keyring status/clear/set/ssh-clear` | 管理缓存的密码 |
| `sshman completion bash/zsh/fish` | 生成 Shell 补全脚本 |

## 配置存储

```
~/.sshman/
├── config.enc     # AES-256-GCM 加密 YAML
├── .salt          # Argon2id 盐值（chmod 600）
└── logs/          # 操作日志目录
```

配置字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 唯一标识 |
| host | string | SSH 服务器地址 |
| port | int | SSH 端口（默认 22） |
| user | string | 登录用户名（默认 root） |
| password | string | SSH 密码（空则用 key / keychain / 交互式） |
| identity_file | string | SSH 私钥路径 |
| tags | list | 标签列表 |
| group | string | 分组（按环境隔离） |
| jumphost | string | 跳板机 session 名称 |
| tunnels | list | 端口转发配置 |
| notes | string | 备注 |
| keepalive | int | ServerAliveInterval 秒数 |

## 开发

```bash
source venv/bin/activate
pip install -e ".[dev]"

python3 -m pytest tests/ -v
python3 -m pytest tests/test_crypto.py -v                # 单文件
python3 -m pytest tests/ -v --cov=sshman --cov-report=term-missing
```

## 许可

MIT License
