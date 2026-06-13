# sshman 使用手册

## 目录

1. [安装](#1-安装)
2. [初始化](#2-初始化)
3. [会话管理](#3-会话管理)
4. [连接与登录](#4-连接与登录)
5. [密码管理](#5-密码管理)
6. [跳板机与隧道](#6-跳板机与隧道)
7. [批量操作](#7-批量操作)
8. [健康检查](#8-健康检查)
9. [导入已有配置](#9-导入已有配置)
10. [操作日志](#10-操作日志)
11. [Shell 补全](#11-shell-补全)
12. [分组管理](#12-分组管理)
13. [配置加密与安全](#13-配置加密与安全)
14. [参考附录](#14-参考附录)

---

## 1. 安装

```bash
git clone <repo-url>
cd sshman
./scripts/install.sh
```

安装脚本自动完成：创建 Python 虚拟环境 → 安装依赖 → 注册系统命令 `/usr/local/bin/sshman`。

安装后新开终端即可使用。卸载：

```bash
sudo rm /usr/local/bin/sshman
rm -rf ~/.sshman ~/sshman
```

---

## 2. 初始化

```bash
sshman init
```

设置主密码（用于加解密配置文件）。建议勾选 "Remember in system keychain"，后续所有命令不再提示输入。

配置文件存储在 `~/.sshman/config.enc`（AES-256-GCM 加密）。

---

## 3. 会话管理

### 添加会话

```bash
# 交互式向导
sshman add

# 命令行一键添加
sshman add \
  --name prod-web-01 \
  --host 10.0.1.100 \
  --port 22 \
  --user admin \
  --tags prod,web,beijing \
  --group production \
  --notes "生产 Web 服务器 #01"
```

### 列出会话

```bash
sshman list                          # 表格视图
sshman list --tag prod               # 按标签过滤
sshman list --group production       # 按分组过滤
sshman list --keyword beijing        # 关键词搜索（名称/主机/备注）
sshman list --detail                 # 详细视图
```

### 编辑会话

```bash
sshman edit prod-web-01 --port 2222                # 改端口
sshman edit prod-web-01 --tags prod,web,beijing    # 改标签
sshman edit prod-web-01 --group production         # 改分组
sshman edit prod-web-01 --notes "新备注"           # 改备注
sshman edit prod-web-01 --keepalive 60             # 心跳保活
```

只传需要修改的字段，其余保持不变。

### 克隆会话

```bash
sshman clone prod-web-01 --as prod-web-02
sshman clone prod-web-01 --as prod-web-03 --host 10.0.1.103 --port 2222
```

### 重命名会话

```bash
sshman rename <旧名称> <新名称>
# 示例
sshman rename sdp_admin_test sdp-admin-test
```

新名称不能与已有会话重复。

### 删除会话

```bash
sshman remove prod-web-01            # 需确认
sshman remove prod-web-01 --force    # 跳过确认
```

---

## 4. 连接与登录

```bash
sshman connect prod-web-01
```

自动处理：
1. 主机密钥确认（首次连接自动 yes）
2. 密码认证（从配置 / Keychain / 交互式提示）
3. MFA 验证码
4. 登录后不动用户终端输出（不会吞 MOTD）

跳过端口转发：
```bash
sshman connect prod-web-01 --no-tunnels
```

### 多服务器自动登录

```bash
sshman connect prod-web-01   # 配置了密码 / keychain
sshman connect dev-server     # 没有密码，交互式提示
sshman connect bastion         # 仅密钥认证
```

---

## 5. 密码管理

### 主密码缓存

首次 `sshman init` 后勾选记住，之后所有命令不再提示输入主密码。

```bash
sshman keyring status         # 查看是否已缓存
sshman keyring clear           # 清除缓存（下次需要重新输）
sshman keyring set             # 手动存入（先验证密码正确性）
```

### SSH 会话密码存入 Keychain

比写在 YAML 配置中更安全（即使拿到加密文件和主密码也拿不到 SSH 密码）。

```bash
# 添加时指定
sshman add --name prod-db --host 10.0.0.10 --user admin \
  --password mysqlPwd --keychain

# 编辑已有会话
sshman edit prod-db --password newPwd --keychain

# 清除单个 SSH 密码
sshman keyring ssh-clear prod-db
```

连接时的密码查找优先级：`YAML 配置 → Keychain → 交互式提示`

---

## 6. 跳板机与隧道

### 跳板机（ProxyJump）

先添加跳板机本身作为一个会话：

```bash
sshman add --name bastion --host jump.example.com --user ops --tags prod,bastion
```

然后为需要跳板的目标设置 jumphost：

```bash
sshman edit prod-web-01 --jumphost bastion
```

连接时自动添加 `-J ops@jump.example.com:22`。

### 端口转发

在会话配置中设置 tunnels 字段（JSON 数组）：

```bash
# 本地转发：本机 5432 → 远程 localhost:5432
sshman edit db-server --tunnels '[{"type":"local","local_port":5432,"remote_host":"127.0.0.1","remote_port":5432}]'

# 远程转发：远程 8080 → 本机 localhost:3000
sshman edit web-server --tunnels '[{"type":"remote","local_port":3000,"remote_host":"0.0.0.0","remote_port":8080}]'

# 动态转发（SOCKS 代理）
sshman edit proxy --tunnels '[{"type":"dynamic","local_port":1080}]'

# 多个隧道
sshman edit multi --tunnels '[
  {"type":"local","local_port":3306,"remote_host":"127.0.0.1","remote_port":3306},
  {"type":"local","local_port":6379,"remote_host":"127.0.0.1","remote_port":6379}
]'
```

**仅建立隧道不进入 Shell：**

```bash
sshman tunnel db-server
# 按 Ctrl-C 断开
```

---

## 7. 批量操作

```bash
# 按标签批量执行
sshman batch "uptime" --tag prod

# 指定服务器
sshman batch "df -h" --names web-01,web-02,db-01

# 按分组
sshman batch "systemctl status nginx" --group production

# 控制并发
sshman batch "apt update && apt upgrade -y" --tag ubuntu --parallel 3 --timeout 30
```

输出带主机名前缀，成功显示 🟢，失败显示 🔴。

---

## 8. 健康检查

### TCP 端口可达性

```bash
sshman check                           # 全部
sshman check --tag prod                # 按标签
sshman check --group production        # 按分组
sshman check --names web-01,web-02     # 指定服务器
sshman check --timeout 5               # 自定义超时
```

输出表格：🟢 可达（带延迟）或 🔴 不可达（带错误信息）。

### 配置完整性检查

```bash
sshman check --config
```

检测项：
- 缺少 host / user 字段
- 无效端口号（< 1 或 > 65535）
- 重复的会话名称
- 悬空的跳板机引用（引用的 session 不存在）

---

## 9. 导入已有配置

### 从 ~/.ssh/config

```bash
sshman import --source ssh-config
sshman import --source ssh-config --dry-run    # 预览不写入
```

解析 Host / HostName / Port / User / IdentityFile 字段。

### 从 Ansible Inventory

```bash
sshman import --source ansible /path/to/inventory
sshman import --source ansible /path/to/inventory --dry-run
```

支持标准 INI 格式：

```ini
[production]
web-01 ansible_host=10.0.1.10 ansible_user=admin
db-01  ansible_host=10.0.1.20 ansible_port=3306

[staging]
stage-01 ansible_host=10.0.2.10
```

### 从 CSV

```bash
sshman import --source csv servers.csv
sshman import --source csv servers.csv --dry-run
```

CSV 格式（首行为列名）：

```csv
name,host,port,user,tags
web-01,10.0.1.10,22,admin,"prod,web"
db-01,10.0.1.20,3306,root,"prod,db"
```

---

## 10. 操作日志

### 启用日志

为会话设置 `auto_log: true`，连接时自动录制终端输出：

```bash
sshman edit prod-web-01 --auto-log true   # 计划在后续版本中支持
```

或通过编辑会话配置 YAML 手动设置。

日志存储在 `~/.sshman/logs/<session_name>/YYYY-MM-DD_HHMMSS.log`。

### 查看日志

```bash
sshman log                    # 列出所有有日志的会话
sshman log prod-web-01        # 查看最近 20 行
sshman log prod-web-01 --last 50
sshman log prod-web-01 --date 2026-06-13
sshman log prod-web-01 --search "error"
```

---

## 11. Shell 补全

```bash
# bash: 添加到 ~/.bashrc
eval "$(sshman completion bash)"

# zsh: 添加到 ~/.zshrc
eval "$(sshman completion zsh)"

# fish: 添加到 ~/.config/fish/config.fish
sshman completion fish | source
```

启用后 `sshman <Tab>` 自动补全命令，`sshman connect <Tab>` 补全会话名称。

---

## 12. 分组管理

会话支持 `group` 字段，可与标签配合使用：

```bash
# 设置分组
sshman edit web-01 --group production
sshman edit web-02 --group production
sshman edit db-01 --group production
sshman edit dev-01 --group staging

# 按分组过滤
sshman list --group production
sshman check --group production
sshman batch "uptime" --group production
```

标签 vs 分组：
- **标签**：灵活，一个会话可以有多个标签（`prod,web,beijing`），用于交叉过滤
- **分组**：互斥，一个会话只属于一个组（`production` / `staging` / `dev`），用于环境隔离

---

## 13. 配置加密与安全

### 加密机制

| 环节 | 算法 |
|------|------|
| 密钥派生 | Argon2id（memory=64MB, iterations=3, lanes=4） |
| 文件加密 | AES-256-GCM（每次加密随机 96-bit nonce） |
| 认证 | GCM 认证标签（防篡改） |

### 文件权限

```
~/.sshman/
├── config.enc    chmod 600   AES-256-GCM 密文
├── .salt         chmod 600   Argon2id 盐值
└── logs/         chmod 700   操作日志目录
```

### 手动加解密

```bash
sshman crypto decrypt                    # 解密输出到终端
sshman crypto decrypt --output plain.yaml # 解密输出到文件
sshman crypto encrypt                     # 加密回 config.enc
```

### 安全最佳实践

1. **主密码设复杂一些**：Argon2id 参数已经足够强，但弱密码仍然可被暴力
2. **用 Keychain 存 SSH 密码**：`sshman add ... --password xxx --keychain`
3. **定期 `sshman check --config`**：检查配置是否有异常
4. **`~/.sshman` 目录不要分享**：即使加密了也不要分享配置文件

---

## 14. 参考附录

### 完整命令参数

| 命令 | 参数 | 说明 |
|------|------|------|
| `init` | `--config-dir PATH` | 自定义配置目录 |
| `add` | `--name --host --port --user --password --identity-file --tags --group --notes --keychain --config-dir` | 添加会话 |
| `list` | `--tag --group --keyword --detail --config-dir` | 列出会话 |
| `edit` | 同 add 字段 + `--keychain` + `--keepalive` | 编辑会话 |
| `rename` | `<old_name> <new_name> --config-dir` | 重命名会话 |
| `clone` | `<name> --as <new> [--host --port --user] --config-dir` | 克隆会话 |
| `remove` | `<name> [--force] --config-dir` | 删除会话 |
| `connect` | `<name> [--log/--no-log] [--no-tunnels] --config-dir` | 连接会话 |
| `tunnel` | `<name> --config-dir` | 仅端口转发 |
| `batch` | `<command> [--tag --group --names --parallel --timeout] --config-dir` | 批量执行 |
| `check` | `[--tag --group --names --timeout] [--config] --config-dir` | 健康/配置检查 |
| `import` | `--source [ssh-config\|ansible\|csv] [--path] [--dry-run] --config-dir` | 导入配置 |
| `log` | `[name] [--last N] [--date YYYY-MM-DD] [--search KW] --config-dir` | 查看日志 |
| `crypto` | `encrypt / decrypt [--config-dir] [--output PATH]` | 手动加解密 |
| `keyring` | `status / set / clear / ssh-clear <name>` | 密码缓存管理 |
| `completion` | `bash / zsh / fish` | 生成补全脚本 |

### Session 配置字段

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `name` | string | (必填) | 唯一标识 |
| `host` | string | (必填) | SSH 服务器地址 |
| `port` | int | 22 | SSH 端口 |
| `user` | string | root | 登录用户名 |
| `password` | string | "" | SSH 密码（空则用 key / keychain / 交互式） |
| `identity_file` | string | "" | SSH 私钥路径 |
| `tags` | list | [] | 标签列表 |
| `group` | string | "" | 分组（按环境/项目隔离） |
| `jumphost` | string | "" | 跳板机 session 名称 |
| `tunnels` | list | [] | 端口转发配置 |
| `notes` | string | "" | 备注 |
| `auto_log` | bool | false | 是否自动录制终端日志 |
| `keepalive` | int | 0 | ServerAliveInterval 秒数 |

### Tunnels 格式

```json
[
  {"type": "local",   "local_port": 5432, "remote_host": "127.0.0.1", "remote_port": 5432},
  {"type": "remote",  "local_port": 3000, "remote_host": "0.0.0.0",   "remote_port": 8080},
  {"type": "dynamic", "local_port": 1080}
]
```

### 列出已配置的 tunnels

```bash
sshman list --detail          # 显示每个会话的隧道数量
sshman crypto decrypt         # 查看完整 YAML 中的 tunnels 配置
```
