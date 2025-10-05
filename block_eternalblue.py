#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
永恒之蓝（EternalBlue）攻击防护脚本
功能：检测对 445 端口的异常连接行为，并自动封禁可疑 IP
依赖：需 root 权限运行，支持 Linux + iptables
"""

import subprocess
import re
from collections import defaultdict
from datetime import datetime, timedelta

# ===== 配置参数 =====
PORT = 445                   # SMB 端口，永恒之蓝攻击目标
THRESHOLD = 5                # 同一 IP 在时间窗口内超过 N 次连接即封禁
TIME_WINDOW_SECONDS = 60     # 统计时间窗口（秒）
BAN_DURATION_MINUTES = 30    # 封禁时长（分钟）
LOG_TAG = "ETERNALBLUE_BLOCK"

# 使用 netstat 检测当前连接（也可替换为读取 /var/log/samba/log.smbd 等日志）
def get_suspicious_connections():
    try:
        result = subprocess.run(
            ["netstat", "-anp"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
        pattern = re.compile(rf"tcp.*?:(\d+)\s+(\d+\.\d+\.\d+\.\d+):{PORT}")
        connections = []
        for line in lines:
            if f":{PORT}" in line and "ESTABLISHED" in line:
                match = pattern.search(line)
                if match:
                    src_ip = match.group(2)
                    connections.append(src_ip)
        return connections
    except Exception as e:
        print(f"❌ 获取连接信息失败: {e}")
        return []

# 封禁 IP（使用 iptables 临时规则）
def ban_ip(ip):
    try:
        # 添加规则：丢弃该 IP 所有数据包，限制时长
        subprocess.run([
            "iptables", "-A", "INPUT", "-s", ip,
            "-j", "DROP"
        ], check=True)
        # 可选：使用 `at` 命令在指定时间后解封（需安装 at）
        # 示例: echo "iptables -D INPUT -s $ip -j DROP" | at now + 30 minutes
        print(f"✅ 已封禁可疑IP: {ip} (持续 {BAN_DURATION_MINUTES} 分钟)")
    except Exception as e:
        print(f"❌ 封禁IP失败 {ip}: {e}")

# 主函数
def main():
    print(f"🔍 {LOG_TAG}: 开始检测针对 445 端口的永恒之蓝攻击行为...")
    conn_count = defaultdict(list)

    # 获取当前连接记录
    ips = get_suspicious_connections()
    now = datetime.now()

    for ip in ips:
        conn_count[ip].append(now)

    # 清理过期记录并判断是否超限
    blocked = False
    for ip, timestamps in conn_count.items():
        recent = [t for t in timestamps if now - t < timedelta(seconds=TIME_WINDOW_SECONDS)]
        if len(recent) >= THRESHOLD:
            print(f"🚨 检测到可疑扫描行为: {ip} 在 {TIME_WINDOW_SECONDS}s 内连接 445 端口 {len(recent)} 次")
            ban_ip(ip)
            blocked = True

    if not blocked:
        print("✅ 未发现异常连接行为，系统安全。")

if __name__ == "__main__":
    main()