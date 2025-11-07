import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


def _detect_delimiter(path: Path) -> str:
    # Handle tab-delimited csv since tshark's output is tab-delimited by default
    try:
        with path.open("r", newline="") as f:
            # Look at a handful of non-empty lines
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                tabs = line.count("\t")
                commas = line.count(",")
                if tabs or commas:
                    return "\t" if tabs >= commas else ","
    except OSError:
        pass
    return ","


def parse_csv(path: Path, target_ip: str):
    """
    Parse CSV rows and return:
      - counts: dict[(ip, port)][second] -> count
      - min_sec, max_sec across all included packets

    Supported formats:
      - tshark header: frame.time_epoch,ip.src,udp.srcport,ip.dst,udp.dstport
      - headerless (old): t,sport,dport,sip,dip (tab or comma)
      - headerless (natural): t,sip,sport,dip,dport
    """
    counts = defaultdict(lambda: defaultdict(int))
    min_sec = None
    max_sec = None

    def looks_like_ip(s: str) -> bool:
        s = s.strip()
        return "." in s and any(ch.isdigit() for ch in s)

    delimiter = _detect_delimiter(path)
    with path.open("r", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)

        header = None
        mapping = None  # tuple of indices: (t, sip, sport, dip, dport)
        for row in reader:
            if not row or len(row) < 5:
                continue

            if header is None:
                # Detect header if row contains alphabetic characters (e.g., ip.src)
                has_alpha = any(any(c.isalpha() for c in cell) for cell in row)
                if has_alpha:
                    header = [c.strip().lower() for c in row]
                    # Build index mapping by header names (with common aliases)
                    def find(cands):
                        for name in cands:
                            if name in header:
                                return header.index(name)
                        return None

                    idx_t = find(["frame.time_epoch", "time_epoch", "time", "timestamp"])
                    idx_sip = find(["ip.src", "src_ip", "source_ip"]) 
                    idx_sport = find(["udp.srcport", "tcp.srcport", "src_port", "sport", "source_port"])
                    idx_dip = find(["ip.dst", "dst_ip", "destination_ip"]) 
                    idx_dport = find(["udp.dstport", "tcp.dstport", "dst_port", "dport", "destination_port"])

                    # If any mapping missing, fall back to natural order indices
                    if None in (idx_t, idx_sip, idx_sport, idx_dip, idx_dport):
                        mapping = (0, 1, 2, 3, 4)
                    else:
                        mapping = (idx_t, idx_sip, idx_sport, idx_dip, idx_dport)
                    # Move to next row (data starts after header)
                    continue
                else:
                    header = []  # mark as decided no header
                    # Decide mapping by inspecting first data row
                    # old format: t, sport, dport, sip, dip
                    # natural:    t, sip,  sport, dip, dport
                    if looks_like_ip(row[1]):
                        mapping = (0, 1, 2, 3, 4)  # natural
                    else:
                        mapping = (0, 3, 1, 4, 2)  # old -> reorder to (t,sip,sport,dip,dport)

            # Parse using mapping
            try:
                t = float(row[mapping[0]])
                sip = row[mapping[1]].strip()
                sport = int(row[mapping[2]])
                dip = row[mapping[3]].strip()
                dport = int(row[mapping[4]])
            except (ValueError, IndexError):
                # Skip malformed rows
                continue

            # Only consider packets where the target_ip is one endpoint
            if sip == target_ip:
                key = (target_ip, sport)
            elif dip == target_ip:
                key = (target_ip, dport)
            else:
                continue

            sec = int(math.floor(t))
            counts[key][sec] += 1

            if min_sec is None or sec < min_sec:
                min_sec = sec
            if max_sec is None or sec > max_sec:
                max_sec = sec

    if min_sec is None or max_sec is None:
        # No packets found for target
        min_sec, max_sec = 0, 0
    return counts, min_sec, max_sec


def build_series(counts_for_key, min_sec, max_sec):
    xs = list(range(min_sec, max_sec + 1))
    ys = [counts_for_key.get(s, 0) for s in xs]
    return xs, ys


def plot_counts(counts, min_sec, max_sec, target_ip: str, save_path: Path | None = None, port_filter: int | None = None):
    # Optionally filter to a single port
    if port_filter is not None:
        counts = {k: v for k, v in counts.items() if k[1] == port_filter}

    if not counts:
        if port_filter is None:
            print(f"No packets found for {target_ip}. Nothing to plot.")
        else:
            print(f"No packets found for {target_ip} on port {port_filter}. Nothing to plot.")
        return

    # Sort keys by port for stable order
    keys = sorted(counts.keys(), key=lambda k: k[1])

    # Single axes with multiple lines (one per port)
    fig, ax = plt.subplots(figsize=(10, 4))
    xs_global = list(range(min_sec, max_sec + 1))
    for key in keys:
        ys = [counts[key].get(s, 0) for s in xs_global]
        ip, port = key
        ax.step(xs_global, ys, where="post", label=f"port {port}")

    if len(keys) == 1:
        # Use a more specific title when just one port
        ip, port = keys[0]
        title = f"Packets/sec for {ip}:{port}"
    else:
        title = f"Packets/sec by port for {target_ip}"
    ax.set_title(title)
    ax.set_ylabel("pps")
    ax.set_xlabel("seconds")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper right", ncol=2, fontsize=8)
    plt.tight_layout()

    if save_path is not None:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=150)
        print(f"Saved figure to {save_path}")
    else:
        plt.show()


def main():
    # Defaults
    target_ip = "192.168.11.6"
    # Default to tshark export with header
    csv_path = Path("data/tshark.csv")
    save_path = None
    port_filter: int | None = None

    # Simple CLI: python main.py [csv_path] [--ip IP] [--save path]
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--ip" and i + 1 < len(args):
            target_ip = args[i + 1]
            i += 2
        elif arg == "--save" and i + 1 < len(args):
            save_path = Path(args[i + 1])
            i += 2
        elif arg == "--port" and i + 1 < len(args):
            try:
                port_filter = int(args[i + 1])
            except ValueError:
                print("--port expects an integer")
                return
            i += 2
        elif arg.startswith("-"):
            print("Unknown option:", arg)
            return
        else:
            csv_path = Path(arg)
            i += 1

    if not csv_path.exists():
        print(f"CSV not found: {csv_path}")
        return

    counts, min_sec, max_sec = parse_csv(csv_path, target_ip)
    plot_counts(counts, min_sec, max_sec, target_ip, save_path, port_filter)


if __name__ == "__main__":
    main()
