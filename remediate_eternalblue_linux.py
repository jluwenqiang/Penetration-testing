#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔧 Linux 永恒之蓝漏洞加固脚本
功能：检查 Samba 版本是否安全，若不安全则关闭服务并封锁 445 端口
"""

import subprocess
import os
from datetime import datetime

# 日志文件路径
LOG_FILE = "/var/log/remediate_eternalblue.log"
# 安全的 Samba 版本（已修复 CVE-2017-7494 及相关漏洞）
SAFE_VERSIONS = ["4.6.16", "4.7.10", "4.8.3"]
SERVICE_NAME = "smbd"  # 常见服务名：smbd, samba, smb

def log(msg):
    """带时间戳的日志输出"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")

def get_samba_version():
    """获取 Samba 版本"""
    try:
        result = subprocess.run(["smbd", "--version"], capture_output=True, text=True, check=False)
        output = result.stdout.strip()
        if "Version" in output:
            version = output.split()[-1]
            return version
    except FileNotFoundError:
        return None
    except Exception as e:
        log(f"❌ 获取版本失败: {e}")
    return None

def is_version_safe(version):
    """判断版本是否安全"""
    if not version:
        return True  # 未安装视为安全
    try:
        for safe_v in SAFE_VERSIONS:
            if version == safe_v or version > safe_v:
                return True
        return False
    except:
        return False  # 不确定则视为不安全

def stop_samba_service():
    """停止并禁用 Samba 服务"""
    try:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], check=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], check=True)
        log(f"✅ 已停止并禁用 {SERVICE_NAME} 服务")
        return True
    except subprocess.CalledProcessError as e:
        log(f"❌ 无法停止服务: {e}")
        return False

def block_port_445():
    """通过 iptables 封锁 445 端口"""
    try:
        subprocess.run([
            "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "445", "-j", "DROP"
        ], check=True)
        log("✅ 已通过 iptables 封锁 TCP 445 端口")
        return True
    except Exception as e:
        log(f"❌ 封锁端口失败: {e}")
        return False

def main():
    log("🔍 开始检测 Linux 系统永恒之蓝风险...")

    version = get_samba_version()
    if not version:
        log("🟢 Samba 未安装，系统无此风险。")
        return

    log(f"📊 当前 Samba 版本: {version}")
    if is_version_safe(version):
        log("✅ Samba 版本安全，无需处理。")
    else:
        log(f"🚨 Samba {version} 存在永恒之蓝类漏洞风险！正在加固...")
        if stop_samba_service() or block_port_445():
            log("🛡️ 系统已加固，攻击面关闭。")
        else:
            log("⚠️ 自动加固失败，请手动处理！建议：yum update samba 或关闭服务。")

if __name__ == "__main__":
    main()