#!/usr/bin/env python3

#!/usr/bin/env python3
import time, os, sys, threading, requests
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

# --- SETTINGS & GLOBALS ---
captured_packets = []
security_alerts = []
intel_cache = {}
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0, "TOTAL": 0}

# File Names
PCAP_FILE = "nova_intel_v2.pcap"
HISTORY_FILE = "nova_history_log.txt"

pktdump = PcapWriter(PCAP_FILE, append=True, sync=True)

# Sensitive Keywords
KEYWORDS = ["password", "user", "login", "admin", "token", "auth", "secret", "passwd"]

def log_to_history(event_type, details):
    """Appends high-value security events to a text file for later use."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(HISTORY_FILE, "a") as f:
        f.write(f"[{timestamp}] [{event_type}] {details}\n")

def get_vendor(mac):
    """OUI Lookup for common manufacturers."""
    mac = mac.upper().replace(":", "")[:6]
    vendors = {
        "000C29": "VMware", "080027": "VirtualBox", "00155D": "Microsoft",
        "3C5AB4": "Google", "B827EB": "RaspberryPi", "DCA632": "RaspberryPi",
        "000393": "Apple", "000502": "Apple", "F01898": "Apple",
        "005056": "VMware", "ACDE48": "Private", "001A11": "Google"
    }
    return vendors.get(mac, "Unknown")

def get_intel(ip):
    """Performs Geo-IP and WHOIS lookup."""
    if ip.startswith(("192.", "10.", "172.16.")) or ip == "127.0.0.1":
        return "LOCAL", "Local Network"
    if ip in intel_cache:
        return intel_cache[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,org", timeout=1)
        if response.status_code == 200:
            data = response.json()
            country = data.get("countryCode", "??")
            org = data.get("org", "Unknown ISP")
            intel_cache[ip] = (country, org)
            return country, org
    except: pass
    return "??", "Scanning..."

def analyze_payload(pkt):
    """Extracts strings and flags credentials."""
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        decoded = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in payload])
        found_keys = [k for k in KEYWORDS if k in decoded.lower()]
        return decoded[:35], found_keys
    return "", []

def packet_callback(pkt):
    pktdump.write(pkt)
    stats["TOTAL"] += 1
    p_info = {"time": time.strftime("%H:%M:%S"), "proto": "UNK", "src": "", "dst": "", "info": "", "alert": False, "vendor": "", "geo": "??", "isp": ""}

    if pkt.haslayer(Ether):
        p_info["vendor"] = get_vendor(pkt.src)

    if pkt.haslayer(EAPOL):
        p_info.update({"proto": "EAPOL", "src": pkt.addr2 if hasattr(pkt, 'addr2') else "N/A", "info": "WPA HANDSHAKE"})
        msg = f"Vendor: {p_info['vendor']} ({p_info['src']})"
        security_alerts.append(f"{p_info['time']} | [bold red]HANDSHAKE[/bold red] | {msg}")
        log_to_history("WPA_HANDSHAKE", msg)

    elif pkt.haslayer(IP):
        p_info["src"], p_info["dst"] = pkt[IP].src, pkt[IP].dst
        p_info["geo"], p_info["isp"] = get_intel(p_info["dst"])
        
        if pkt.haslayer(TCP):
            stats["TCP"] += 1
            p_info["proto"] = "TCP"
            flags = pkt[TCP].underlayer.sprintf("%TCP.flags%")
            p_info["info"] = f"{pkt[TCP].sport}->{pkt[TCP].dport} [{flags}]"
        elif pkt.haslayer(UDP):
            stats["UDP"] += 1
            p_info["proto"] = "UDP"
            p_info["info"] = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
            if pkt.haslayer(DNSQR):
                p_info["info"] = f"DNS: {pkt[DNSQR].qname.decode()}"
        elif pkt.haslayer(ICMP):
            stats["ICMP"] += 1
            p_info["proto"] = "ICMP"
            p_info["info"] = "Control Message"
        else:
            stats["OTHER"] += 1

        preview, keys = analyze_payload(pkt)
        if keys:
            p_info["alert"] = True
            msg = f"ISP: {p_info['isp']} | Payload: {preview} | Keywords: {', '.join(keys)}"
            security_alerts.append(f"{p_info['time']} | [yellow]CREDENTIAL[/yellow] | {p_info['isp']}")
            log_to_history("CRED_FOUND", msg)
        p_info["data"] = preview

    if p_info["proto"] != "UNK":
        captured_packets.append(p_info)
        if len(captured_packets) > 10: captured_packets.pop(0)

def main():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=7),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=8)
    )

    header_text = Text()
    header_text.append(" ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n", style="cyan")
    header_text.append(" ┃   N O V A - S N I F F E R   v 2 . 7  [FINAL] ┃\n", style="bold white on blue")
    header_text.append(" ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n", style="cyan")
    header_text.append("  AUTHOR: ", style="white")
    header_text.append("Rohan Das", style="bold yellow")
    header_text.append("  |  GITHUB: ", style="white")
    header_text.append("NovaHunter06", style="bold yellow")
    
    layout["header"].update(Panel(header_text, border_style="blue", padding=(0, 1)))

    sniff_thread = threading.Thread(target=lambda: sniff(iface=conf.iface, prn=packet_callback, store=0), daemon=True)
    sniff_thread.start()

    with Live(layout, refresh_per_second=4, screen=True):
        try:
            while True:
                table = Table(expand=True, border_style="green", box=None)
                table.add_column("TIME", width=9); table.add_column("PRO", width=5)
                table.add_column("SOURCE", style="blue"); table.add_column("DEST IP", style="magenta")
                table.add_column("GEO", style="bold cyan", width=4); table.add_column("ISP/ORG", style="dim white", width=15)
                table.add_column("DETAILS", style="white")

                for p in captured_packets:
                    style = "bold red" if p.get("alert") else "white"
                    table.add_row(p["time"], p["proto"], p["src"], p["dst"], p["geo"], p["isp"][:15], Text(p["info"], style=style))
                
                stats_msg = f" [bold white]TOTAL:[/] {stats['TOTAL']} | [bold blue]TCP:[/] {stats['TCP']} | [bold yellow]UDP:[/] {stats['UDP']} | [bold red]ICMP:[/] {stats['ICMP']}"
                layout["main"].update(Panel(table, title=f"[bold green]Stream[/bold green] {stats_msg}"))

                a_table = Table(expand=True, border_style="red", box=None)
                a_table.add_column("REPORTING TO: " + HISTORY_FILE, style="bold white")
                if not security_alerts:
                    a_table.add_row("[dim]Monitoring for Forensics Data...[/dim]")
                else:
                    for alert in security_alerts[-4:]:
                        a_table.add_row(Text.from_markup(alert))
                layout["footer"].update(Panel(a_table, title="[bold red]Forensics Alert System[/bold red]"))
                time.sleep(0.2)
        except KeyboardInterrupt:
            pktdump.close()
            sys.exit(0)

if __name__ == "__main__":
    main()
