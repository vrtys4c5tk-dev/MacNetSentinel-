#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MacNetSentinel - macOS Background Network & Socket Monitor
Copyright (c) 2026 MacNetSentinel

Licensed under the Dual License (Non-Commercial / Commercial).
See LICENSE file in the project root for full license information.
"""

import subprocess
import re
from datetime import datetime

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Default macOS System Processes
SYSTEM_WHITELIST = {
    "mDNSResponder", "cloudd", "apsd", "TrustEvaluationAgent", 
    "nsurlsessiond", "rapportd", "identityservicesd", "bird", "sharingd"
}

# Trusted Third-Party Applications (Known Popular Software)
KNOWN_APPS_WHITELIST = {
    "Spotify", "Opera", "Code", "Google", "Chrome", "Firefox", 
    "Safari", "Slack", "Discord", "Telegram", "Zoom"
}

def clean_process_name(raw_name):
    """Cleans hex escape sequences like `Opera\\x20` into readable names."""
    clean_name = re.sub(r'\\x[0-9a-fA-F]{2}', ' ', raw_name).strip()
    return clean_name

def get_active_sockets():
    """Fetches active IPv4 and IPv6 network connections using `lsof`."""
    cmd = ["lsof", "-i", "-n", "-P"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error executing lsof: {e}{RESET}")
        return ""

def parse_network_connections(raw_output):
    """Parses lsof output and extracts connection details."""
    connections = []
    lines = raw_output.splitlines()
    
    if not lines:
        return connections

    for line in lines[1:]:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 9:
            continue

        raw_command = parts[0]
        pid = parts[1]
        user = parts[2]
        node_type = parts[4]
        name = parts[8]
        state = parts[9] if len(parts) > 9 else "N/A"

        # Filter only active network connections
        if "ESTABLISHED" in state or "SYN_SENT" in state:
            # Skip local (loopback) traffic
            if "127.0.0.1" in name or "localhost" in name or "::1" in name:
                continue

            proc_name = clean_process_name(raw_command)
            
            # Status Evaluation
            is_system = any(sys_app in proc_name for sys_app in SYSTEM_WHITELIST) or user == "root"
            is_known_app = any(known_app in proc_name for known_app in KNOWN_APPS_WHITELIST)
            
            # Flag as suspicious if it's neither a system process nor a known application
            is_suspicious = not (is_system or is_known_app)

            connections.append({
                "process": proc_name,
                "pid": pid,
                "user": user,
                "type": node_type,
                "connection": name,
                "is_system": is_system,
                "is_known": is_known_app,
                "is_suspicious": is_suspicious
            })

    return connections

def generate_net_report(connections):
    """Prints a formatted and color-coded security report to the terminal."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "="*75)
    print("      MACNETSENTINEL - BACKGROUND NETWORK & SOCKET MONITOR")
    print("      License: Dual License | Copyright (c) 2026 MacNetSentinel")
    print(f"      Execution Time: {now}")
    print("="*75)

    if not connections:
        print(f"{GREEN}[+] No active external network connections detected.{RESET}\n")
        return

    suspicious_count = sum(1 for c in connections if c["is_suspicious"])
    
    print("\n SUMMARY:")
    print(f"  • Total Active External Sockets : {len(connections)}")
    if suspicious_count > 0:
        print(f"  • {RED}Unknown / Suspicious Connections : {suspicious_count} detected!{RESET}")
    else:
        print(f"  • {GREEN}Unknown / Suspicious Connections : None detected (All traffic belongs to system/known apps).{RESET}")

    print("\n DETECTED SOCKET CONNECTIONS:")
    print("-" * 75)
    print(f"{'PROCESS':<18} {'PID':<8} {'USER':<12} {'STATUS':<14} {'CONNECTION (LOCAL -> REMOTE)'}")
    print("-" * 75)

    for conn in connections:
        if conn["is_suspicious"]:
            status_tag = f"{RED}[UNKNOWN ]{RESET}"
        elif conn["is_system"]:
            status_tag = f"{GREEN}[SYSTEM  ]{RESET}"
        else:
            status_tag = f"{CYAN}[KNOWN APP]{RESET}"

        print(f"{conn['process'][:17]:<18} {conn['pid']:<8} {conn['user'][:11]:<12} {status_tag:<14} {conn['connection']}")
    
    print("="*75 + "\n")

if __name__ == "__main__":
    raw_lsof = get_active_sockets()
    if raw_lsof:
        parsed_conns = parse_network_connections(raw_lsof)
        generate_net_report(parsed_conns)
