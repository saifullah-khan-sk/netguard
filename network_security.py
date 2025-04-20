from scapy.all import sniff, DNSQR, IP
import time


SUSPICIOUS_WEBSITES = {
    "malicious.com", "flexstudent.nu.edu.pk"
}


ALL_TRAFFIC_LOG = "all_traffic.log"
ALERT_LOG = "security_alerts.log"

def log_message(log_file, message):
    """Logs network activity with timestamps."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)  
    
    with open(log_file, "a") as file:
        file.write(log_entry + "\n")

def process_packet(packet):
    if packet.haslayer(DNSQR):  
        queried_domain = packet[DNSQR].qname.decode().strip(".")
        src_ip = packet[IP].src  

        
        log_message(ALL_TRAFFIC_LOG, f"DNS Query: {queried_domain} from {src_ip}")

        
        if queried_domain in SUSPICIOUS_WEBSITES:
            log_message(ALERT_LOG, f"ALERT: Suspicious website accessed: {queried_domain} from {src_ip}")

def start_monitoring():
    print("Monitoring all network activity... Press Ctrl+C to stop.")
    sniff(filter="udp port 53", prn=process_packet, store=False)

if __name__ == "__main__":
    start_monitoring()
