import os
import time
from scapy.all import sniff, IP
from collections import Counter, deque

# --- CẤU HÌNH ---
INTERFACE = "wlo1"  # ⚠️ THAY THẾ bằng tên giao diện WiFi của bạn (ví dụ: wlan0, eth0)
PACKET_THRESHOLD = 500000000  # Số lượng gói tối đa cho phép từ một IP trong WINDOW_SIZE
BLOCK_DURATION = 30000000000000000  # Thời gian chặn IP (giây)

# Danh sách chứa IP đang bị chặn và thời gian hết hạn
BLOCKED_IPS = {} 

# Hàng đợi để lưu trữ lịch sử gói tin (IP và thời gian)
# Sử dụng để theo dõi tỷ lệ gói tin trong một cửa sổ thời gian
packet_history = deque(maxlen=2000) 

# --- HÀM CHẶN VÀ BỎ CHẶN IP ---

def block_ip(ip_address):
    """Thực hiện lệnh chặn IP bằng iptables."""
    if ip_address not in BLOCKED_IPS:
        print(f"⚠️ [CHẶN] Đã chặn IP: {ip_address}")
        # Chèn rule chặn lên trên cùng (dùng -I)
        os.system(f"iptables -I INPUT -s {ip_address} -j DROP")
        BLOCKED_IPS[ip_address] = time.time() + BLOCK_DURATION

def unblock_ip(ip_address):
    """Thực hiện lệnh bỏ chặn IP bằng iptables."""
    print(f"✅ [MỞ] Đã mở chặn IP: {ip_address}")
    # Xóa rule chặn (dùng -D)
    os.system(f"iptables -D INPUT -s {ip_address} -j DROP")
    if ip_address in BLOCKED_IPS:
        del BLOCKED_IPS[ip_address]

# --- HÀM XỬ LÝ GÓI TIN ---

def check_for_unblock():
    """Kiểm tra và mở chặn các IP đã hết thời gian chặn."""
    current_time = time.time()
    ips_to_unblock = [ip for ip, expiry in BLOCKED_IPS.items() if expiry < current_time]
    
    for ip in ips_to_unblock:
        unblock_ip(ip)

def packet_callback(packet):
    """Hàm xử lý mỗi gói tin được bắt."""
    check_for_unblock()
    
    if IP in packet:
        src_ip = packet[IP].src
        
        # Bỏ qua các IP đang bị chặn hoặc IP nội bộ/gateway nếu cần
        if src_ip in BLOCKED_IPS:
            return

        # Thêm IP vào lịch sử với thời gian hiện tại
        packet_history.append((src_ip, time.time()))

        # Đếm tần suất trong cửa sổ thời gian gần nhất (ví dụ: 1-2 giây cuối)
        ip_counts = Counter()
        for ip, t in packet_history:
            # Nếu gói tin quá cũ, không tính vào
            # Đây là logic đơn giản, có thể cần tinh chỉnh
            ip_counts[ip] += 1

        # Kiểm tra ngưỡng (chỉ kiểm tra IP hiện tại để tiết kiệm hiệu năng)
        if ip_counts[src_ip] > PACKET_THRESHOLD:
            # Ngưỡng đã đạt, tiến hành chặn
            block_ip(src_ip)
            
def start_monitoring():
    print(f"--- Bắt đầu Giám sát DDoS trên giao diện {INTERFACE} ---")
    print(f"Ngưỡng chặn: {PACKET_THRESHOLD} gói/IP. Thời gian chặn: {BLOCK_DURATION} giây.")
    try:
        # Bắt gói tin liên tục (store=0 để không lưu trữ trong bộ nhớ)
        sniff(iface=INTERFACE, prn=packet_callback, store=0)
    except PermissionError:
        print("\n!!! LỖI QUYỀN TRUY CẬP !!!")
        print("Vui lòng chạy script với quyền root/sudo (ví dụ: sudo python3 ten_file.py)")
    except Exception as e:
        print(f"\nĐã xảy ra lỗi: {e}")

if __name__ == "__main__":
    start_monitoring()