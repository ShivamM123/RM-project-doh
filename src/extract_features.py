import os
import glob
import pandas as pd
from scapy.all import rdpcap, IP, TCP

# --- Configuration ---
PCAPS_DIR = r"data\pcaps"
OUTPUT_CSV = r"data\dataset.csv"
RESOLVER_IP = "1.1.1.1"
SEQ_LENGTH = 50  # First N packets to use as sequence features
# ---------------------


def extract_features(pcap_path, label):
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Failed to read {pcap_path}: {e}")
        return None

    signed_sizes = []

    # 1. Extract Signed Packet Sizes — payload-only (skip bare TCP
    #    handshake/ACK packets, which carry no DoH message and just
    #    dilute the n-gram signal with connection-management noise)
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            payload_len = len(pkt[TCP].payload)
            if payload_len == 0:
                continue  # pure ACK / SYN / FIN — not a DoH message

            size = len(pkt)
            if pkt[IP].dst == RESOLVER_IP:
                signed_sizes.append(size)      # Outgoing = Positive
            elif pkt[IP].src == RESOLVER_IP:
                signed_sizes.append(-size)     # Incoming = Negative

    if not signed_sizes:
        return None

    # 2. Simple Statistics
    total_pkts = len(signed_sizes)
    out_pkts = sum(1 for x in signed_sizes if x > 0)
    in_pkts = sum(1 for x in signed_sizes if x < 0)
    out_bytes = sum(x for x in signed_sizes if x > 0)
    in_bytes = abs(sum(x for x in signed_sizes if x < 0))

    # 3. Directional N-Grams (Bigrams: Out-Out, Out-In, In-Out, In-In)
    directions = ['O' if x > 0 else 'I' for x in signed_sizes]
    bigrams = {'OO': 0, 'OI': 0, 'IO': 0, 'II': 0}
    for i in range(len(directions) - 1):
        bg = directions[i] + directions[i + 1]
        if bg in bigrams:
            bigrams[bg] += 1

    # 4. Truncate or Pad the sequence to SEQ_LENGTH
    seq_features = signed_sizes[:SEQ_LENGTH]
    seq_features += [0] * (SEQ_LENGTH - len(seq_features))

    # 5. Compile into a dictionary
    features = {
        'label': label,
        'total_pkts': total_pkts,
        'out_pkts': out_pkts,
        'in_pkts': in_pkts,
        'out_bytes': out_bytes,
        'in_bytes': in_bytes,
        'bigram_OO': bigrams['OO'],
        'bigram_OI': bigrams['OI'],
        'bigram_IO': bigrams['IO'],
        'bigram_II': bigrams['II'],
    }

    for i, val in enumerate(seq_features):
        features[f'pkt_{i + 1}'] = val

    return features


def main():
    print("[*] Starting Feature Extraction...")
    pcap_files = glob.glob(os.path.join(PCAPS_DIR, "*.pcap"))

    dataset = []
    for file in pcap_files:
        filename = os.path.basename(file)
        label = filename.split('_')[0]

        feats = extract_features(file, label)
        if feats:
            dataset.append(feats)

    if dataset:
        df = pd.DataFrame(dataset)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"[+] Extraction complete. Saved {len(dataset)} samples to {OUTPUT_CSV}")
    else:
        print("[-] No features extracted. Check if pcaps contain IP packets to/from the resolver.")


if __name__ == "__main__":
    main()