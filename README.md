# sshesame-pro

一个简单易用的 SSH 蜜罐，模拟 SSH 服务器并记录所有活动（包括通道和请求），但不会在主机上执行任何实际操作（例如执行命令或发起网络请求）。

此为[原版 sshesame](https://github.com/jaksi/sshesame) 的增强版，完成了日志输出和模拟的 SSH 的汉化，并添加了几个攻击者常用的指令。

## 安装与使用
> [!WARNING]
> 官方 Debian（及衍生发行版）仓库中的 [sshesame 包](https://packages.debian.org/stable/sshesame) 对[原来的版本](https://github.com/jaksi/sshesame)可能已过时。

> [!WARNING]
> 本项目仍在汉化中，部分界面和功能尚未完全翻译。此外，部分常见 SSH 指令目前尚不支持，后续版本会逐步完善。

### 从源码安装

> [!WARNING]
> 其中的许多指令的内容建议你最好手动修改以达到你的要求。
> 例如`lscpu`，它默认会模拟一个 AMD Athlon(tm) II X4 645 Processor。


请先使用你的包管理器安装golang。
```Bash
git clone https://github.com/Windows10555/sshesame-pro.git

# 如果你在中国内网络不好：
git clone https://githubfast.com/Windows10555/sshesame-pro.git

cd sshesame-pro
go build
```

### 使用预编译二进制文件

有时间再说吧。

## 使用方法

- `-config string`：可选的配置文件路径，如不添加，将使用内置配置。
- `-data_dir string`：存储自动生成的主机密钥的目录（在 Linux 上默认值为 `$HOME/.local/share/sshesame`）

调试和错误日志会输出到标准错误。活动日志默认输出到标准输出，除非设置了 `logging.file` 配置选项。

### systemd 配置

```desktop
[Unit]
Description=SSH honey
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/path/to/sshesame -config /path/to/sshesame.yaml
Restart=always

[Install]
WantedBy=multi-user.target
```

### 配置文件
可以通过 `-config` 参数传递一个可选的配置文件。如果不指定配置文件，程序会使用合理的默认值，并在 `-data_dir` 指定的目录中生成 RSA、ECDSA 和 Ed25519 主机密钥。
项目包含一个[示例配置文件](sshesame.yaml)，其中包含所有配置选项的默认值和说明。此外还有一个[最小化配置文件](openssh.yaml)，用于模仿 OpenSSH 服务器的行为。

## 示例输出
```
2025/04/05 18:28:23 [83.40.226.213:43212] 以用户名 "root" 附带密码 "zaq123456" 登录 已拒绝
2025/04/05 18:28:59 [91.92.199.36:37660] 以用户名 "slave" 附带密码 "slave" 登录 已拒绝
2025/04/05 18:29:03 [103.134.154.72:52162] 以用户名 "botuser" 附带密码 "12345" 登录 已拒绝
2025/04/05 18:29:24 [101.36.119.98:41244] 以用户名 "cheeki" 附带密码 "M3gaP33!" 登录 已拒绝
2025/04/05 18:29:52 [83.40.226.213:44748] 以用户名 "slave" 附带密码 "slave" 登录 已拒绝
2025/04/05 18:30:10 [91.92.199.36:55420] 以用户名 "root" 附带密码 "jerry" 登录 已拒绝
2025/04/05 18:30:23 [103.134.154.72:51514] 以用户名 "root" 附带密码 "123456@" 登录 已拒绝
2025/04/05 18:30:51 [101.36.119.98:35660] 以用户名 "kodi" 附带密码 "12345678" 登录 已拒绝
2025/04/05 18:31:11 [83.40.226.213:56790] 以用户名 "admin" 附带密码 "admin" 登录 已拒绝
2025/04/05 18:31:21 [91.92.199.36:56656] 以用户名 "clouduser" 附带密码 "12345" 登录 已拒绝
2025/04/05 18:31:45 [103.134.154.72:54794] 以用户名 "root" 附带密码 "LeitboGi0ro" 登录 已拒绝
```

~~这也是公开处刑攻击者！~~


