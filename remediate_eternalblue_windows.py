#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔧 Windows 永恒之蓝漏洞加固脚本
功能：检查是否安装 MS17-010 补丁，若未安装则关闭 SMBv1 并封锁 445 端口
"""

import subprocess
import os
from datetime import datetime

# 日志文件路径（Windows 风格）
LOG_DIR = os.path.join(os.environ.get("SYSTEMDRIVE", "C:\\"), "Logs")
LOG_FILE = os.path.join(LOG_DIR, "remediate_eternalblue.log")
REQUIRED_KB = "KB4012211"  # MS17-010 补丁编号

def log(msg):
    """带时间戳的日志输出（增强容错）"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {msg}"

    # 【1】先打印到控制台（最安全）
    try:
        print(formatted_msg)
    except:
        pass

    # 【2】再尝试写入日志文件（失败也不影响程序）
    try:
        log_dir_safe = os.path.normpath(LOG_DIR)
        os.makedirs(log_dir_safe, exist_ok=True)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")
    except Exception as e:
        try:
            print(f"[{timestamp}] ⚠️ 无法写入日志文件: {e}")
        except:
            pass

def check_patch_installed():
    """检查是否安装 MS17-010 补丁"""
    try:
        result = subprocess.run(
            ["wmic", "qfe", "get", "HotFixID"],
            capture_output=True,
            text=True,
            check=False
        )
        installed_patches = result.stdout.strip().split()
        if REQUIRED_KB in installed_patches:
            return True
        return False
    except Exception as e:
        log(f"❌ 检查补丁失败: {e}")
        return False

def disable_smbv1():
    """关闭 Windows SMBv1 协议（主要攻击面）"""
    try:
        subprocess.run([
            "powershell", "-Command",
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
        ], check=True)
        log("✅ 已禁用 SMBv1 服务端协议")
        return True
    except subprocess.CalledProcessError as e:
        log(f"❌ 无法禁用 SMBv1: {e}")
        return False

def block_port_445():
    """通过 Windows 防火墙封锁 445 端口"""
    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=Block EternalBlue Port 445",
            "dir=in",
            "action=block",
            "protocol=TCP",
            "localport=445"
        ], check=True, shell=True)
        log("✅ 已通过防火墙封锁 TCP 445 端口")
        return True
    except Exception as e:
        log(f"❌ 封锁端口失败: {e}")
        return False

def main():
    log("🔍 开始检测 Windows 系统永恒之蓝风险...")

    if check_patch_installed():
        log("✅ 系统已安装 MS17-010 补丁，安全。")
    else:
        log(f"🚨 未检测到 {REQUIRED_KB} 补丁，存在永恒之蓝漏洞风险！")
        log("🛠️ 正在执行缓解措施...")

        success = True
        if not disable_smbv1():
            success = False
        if not block_port_445():
            success = False

        if success:
            log("🛡️ 缓解措施已完成：SMBv1 已关闭，445 端口已封锁。")
        else:
            log("⚠️ 部分操作失败，请以管理员身份重试或手动修复。")

if __name__ == "__main__":
    main()