import socket
import time
import threading

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080
PACKETS = 500

_simulation_running = False
_simulation_lock = threading.Lock()


def run_attack_simulation(target_ip=TARGET_IP, target_port=TARGET_PORT, packet_count=PACKETS):
    global _simulation_running

    with _simulation_lock:
        if _simulation_running:
            return False, "Simulation is already running."
        _simulation_running = True

    def _worker():
        global _simulation_running
        success = 0
        failed = 0

        print(f"[Attack Simulator] Starting high-rate traffic burst to {target_ip}:{target_port} ({packet_count} connections)...")

        for _ in range(packet_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.05)
                sock.connect((target_ip, target_port))
                sock.sendall(b"NIDS-AI-V2-SIMULATED-ATTACK-PAYLOAD-PROBE")
                sock.close()
                success += 1
            except Exception:
                failed += 1
            time.sleep(0.002)

        print(f"[Attack Simulator] Burst completed: {packet_count} simulated attack probe packets sent to {target_ip}:{target_port}.")

        with _simulation_lock:
            _simulation_running = False

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return True, f"Triggered attack simulation burst ({packet_count} packets) against {target_ip}:{target_port}."


def main():
    print("=" * 60)
    print("NIDS-AI V2 - SAFE ATTACK-LIKE TRAFFIC SIMULATOR")
    print("=" * 60)
    ok, msg = run_attack_simulation(packet_count=1000)
    print(msg)
    time.sleep(3)


if __name__ == "__main__":
    main()