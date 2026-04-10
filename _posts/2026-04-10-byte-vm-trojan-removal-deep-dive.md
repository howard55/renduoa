---
layout: post
title: "记一次字节云服务器挖矿木马的深度排查与清除实战"
date: 2026-04-10
categories: security linux
tags: [挖矿木马, kswpad, rootkit, 安全, 运维, 字节跳动云]
---

最近，在处理一台运行 OpenClaw 的字节跳动云虚拟机时，遇到了一个典型但极具危险性的安全事件。起初只是简单的 CPU 占用率爆满，但随着排查的深入，发现这并非普通的性能问题，而是一次精心布局的、涉及 rootkit 的深度系统入侵。本文将完整复盘整个排查、对抗和清除过程，希望能为处理类似问题的技术人员提供一份详尽的参考。

### 问题初现：CPU 占用 100%

一切始于一个常见的告警：服务器 CPU 占用率持续 100%。登录服务器后，执行 `top` 命令，很快就定位到了一个异常进程：

```
PID   USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
96004 root      20   0  113.8g   1.2g   2428 S  99.3   7.9   1440:13 kswpad
```

问题非常明显，一个名为 `kswpad` 的进程几乎吃掉了所有 CPU 资源。这是一个非常狡猾的伪装，它企图模仿正常的内核换页进程 `kswapd`（注意，一个是 pad，一个是apd）。这种伪装是挖矿木马的常见伎俩，尤其在云服务器上。

### 第一轮交锋：简单清理与木马的顽固复活

根据初步判断，我们开始着手清理。

**第一步：确认恶意进程信息**

为了解更多信息，我们查看了该进程的真实路径和网络连接。

```bash
# 查看进程真实路径
ls -la /proc/96004/exe

# 查看进程启动命令
cat /proc/96004/cmdline | tr \'\\0\' \' \'

# 查看打开的网络连接
cat /proc/96004/net/tcp
```

**第二步：强制终止进程**

事不宜迟，先将异常进程 kill 掉，释放 CPU 资源。

```bash
kill -9 96004
```

**第三步：查找并清除木马本体与持久化机制**

木马为了能够持续运行，通常会设置定时任务或系统服务。

```bash
# 查找同名文件
find / -name "kswpad" 2>/dev/null

# 检查定时任务（木马常驻方式）
crontab -l
cat /etc/crontab
ls /etc/cron.*
```

然而，在我们清理后不久，`kswpad` 进程竟以一个新的 PID（2044162）再度复活！这说明它拥有更高级的持久化机制。

### 第二轮交锋：深挖持久化机制

简单的 `cron` 任务已经无法解释木马的复活，我们将目标锁定在 `systemd` 服务和 `init.d` 脚本上。

**1. 发现多个恶意组件**

经过一番搜寻，更多潜伏的恶意组件浮出水面：
- **/etc/kswpad**: 主木马程序。
- **/usr/lib/systemd/system/kswpad**: 伪装的 systemd 服务，这是它能够重启复活的关键！
- **/.mod**: 一个每分钟执行的恶意脚本。
- **/etc/cron.hourly/gcc.sh**: 每3分钟执行的恶意脚本。
- **/etc/init.d/DbSecuritySpt** 和 **/etc/init.d/zsnklflozh**: 两个极其可疑的 `init.d` 服务。

**2. 执行深度清除**

针对这些新发现，我们展开了更彻底的清除：

```bash
# 1. 停用并删除 kswpad 服务
systemctl stop kswpad
systemctl disable kswpad
rm -f /usr/lib/systemd/system/kswpad
rm -f /etc/kswpad

# 2. 删除 crontab 中的恶意任务
sed -i \'/\.mod/d\' /etc/crontab
sed -i \'/gcc\.sh/d\' /etc/crontab

# 3. 删除恶意脚本
rm -f /.mod
rm -f /etc/cron.hourly/gcc.sh

# 4. 强制删除可疑的 init.d 服务
systemctl stop DbSecuritySpt zsnklflozh
systemctl disable DbSecuritySpt zsnklflozh
rm -f /etc/init.d/DbSecuritySpt
rm -f /etc/init.d/zsnklflozh
# 清理软链接
rm -f /etc/rc*.d/*DbSecuritySpt*
rm -f /etc/rc*.d/*zsnklflozh*

# 5. 重载 systemd
systemctl daemon-reload
```

### 最终对决：Rootkit 现形

即便执行了如此深度的清理，`kswpad` 进程依然阴魂不散。这让我们意识到，情况可能比想象的更严重。我们决定检查 `/usr/bin` 目录下最近被修改过的文件，这是攻击者经常藏匿后门的地方。

```bash
ls -lt /usr/bin/ | head -30
```

结果令人震惊：

```
-rwxr-xr-x 1 root root 1223123 Apr 10 19:50 ss
-rwxr-xr-x 1 root root 1223123 Apr 10 19:50 ps
-rwxr-xr-x 1 root root 1223123 Apr 10 19:50 lsof
-rwxr-xr-x 1 root root 1223123 Apr 10 19:50 netstat
...
```

`ps`、`ss`、`lsof`、`netstat` 这些最基础的系统诊断工具，全都被替换成了同一个 1.2MB 的恶意文件！

**这是一个典型的 rootkit 行为。** 攻击者通过替换系统命令，让我们无法看到真实的进程和网络连接，从而完美地隐藏了自身。我们之前所做的所有 `ps` 和 `top` 操作，都是在被篡改的环境下进行的，看到的是被过滤后的“假象”。

同时，在 `/tmp` 目录下也发现了大量恶意文件：
- **/tmp/gates.lod**: 挖矿控制文件。
- **/tmp/moni.lod**: 监控文件。
- **/tmp/kal64**: 挖矿程序本体。
- **/tmp/linux**: 另一个持续运行超过2天的挖矿主进程。

**最终根除步骤**

既然系统工具不可信，我们必须先恢复它们。

```bash
# 1. 使用 apt/yum 重新安装核心工具包，恢复被替换的命令
# 对于 Debian/Ubuntu
apt-get install --reinstall procps iproute2 net-tools lsof -y

# 对于 CentOS/RHEL
# yum reinstall procps-ng iproute net-tools lsof -y

# 2. 终止所有已知恶意进程 (使用原始路径 /bin/ps 确保真实性)
/bin/ps aux | grep -v grep | awk \'\'\'/kswpad|kal64|\\.mod|zsnklflozh|voshwjyckz|\\/tmp\\/linux/{print $2}\'\'\' | xargs kill -9

# 3. 删除所有残留的恶意文件和目录
rm -f /tmp/gates.lod /tmp/moni.lod /tmp/kal64 /tmp/linux
rm -rf /usr/bin/dpkgd /usr/bin/bsd-port
```

在恢复了真实的 `ps` 工具后，我们终于看到了那个一直潜伏的主挖矿进程 `/tmp/linux`，它已经稳定运行了超过两天，持续消耗着 33% 的 CPU。

### 结论与建议

经过多轮对抗，我们终于清除了表面和深层的恶意程序。但必须清醒地认识到：

**这台服务器已经被深度入侵，并被植入了 rootkit 级别的后门。**

虽然我们清除了所有已发现的威胁，但无法保证系统内是否还潜藏着未知的后门。攻击者拥有了 root 权限，他们可以修改系统的任何部分。

因此，最安全、最彻底的解决方案只有一个：

1.  **立即备份重要数据**：如数据库、用户文件、应用程序配置等。
2.  **销毁当前虚拟机**：不要再信任这台机器的任何部分。
3.  **重建一台全新的、干净的虚拟机**：从零开始部署应用。
4.  **加强安全措施**：修改所有密码为强密码，审查并关闭不必要的公网端口，配置严格的防火墙策略。

这次事件是一个深刻的教训：对于核心生产环境，任何时候都不能掉以轻心。微小的异常背后，可能隐藏着巨大的安全风险。
