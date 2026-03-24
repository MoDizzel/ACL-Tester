from scapy.all import sniff, send, IP, TCP, UDP, Raw, AsyncSniffer
import time
import ipaddress
import argparse


def parse_packet(packet):
    """
    The parser for scapy sniff.
    :param packet:
    :return:
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        sport = packet[TCP].dport
        dport = packet[TCP].sport

        ip_response = IP(src=packet[IP].dst, dst=packet[IP].src)
        ack = packet.seq
        seq = packet.ack

        # Completes 3 way handshake to verify that full TCP connection can be established.
        if packet[TCP].flags == "S":
            print(f"TCP packet received from port (Syn): {sport}")
            print(f"Attempting to establish full TCP connection...")
            tcp_response = TCP(sport=sport, dport=dport, ack=ack+1, seq=seq, flags="SA")
            response = ip_response / tcp_response
            send(response, verbose=0)

        elif packet.haslayer(Raw):
            if packet[Raw].load == b'Network segregation testing!':
                load_len = len(packet[Raw].load)
                tcp_response = TCP(sport=sport, dport=dport, ack=ack + load_len, seq=seq, flags="A")
                response = ip_response / tcp_response
                send(response, verbose=0)
                # Terminates the connection after acknowledging data sent.
                tcp_response = TCP(sport=sport, dport=dport, ack=ack + load_len + 1, seq=seq, flags="F")
                response = ip_response / tcp_response
                send(response, verbose=0)

        elif packet[TCP].flags == "FA":
            print(f"Connection established successfully! Terminating connection...  [Port: {sport}]")
            tcp_response = TCP(sport=sport, dport=dport, ack=ack+1, seq=seq,  flags="A")
            response = ip_response / tcp_response
            send(response, verbose=0)

    if packet.haslayer(IP) and packet.haslayer(UDP):
        port = packet[UDP].dport
        print(f"UDP packet received from port: {port}")


def listener(interface, sender_ip):
    """
    The function to sniff with scapy.
    :param interface:
    :param sender_ip:
    :return:
    """
    # AsyncSniffer allows CTRL + C termination.
    sniffer = AsyncSniffer(iface=interface, filter=sender_ip, prn=parse_packet)
    sniffer.start()
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        sniffer.stop()
        print("Stopped.")

    # packets.summary()


def main():
    parser = argparse.ArgumentParser("Parser for listener.")
    parser.add_argument("client_ip", help="Client IP is IP address of the sender.")
    args = parser.parse_args()

    # Change this based on the interface used!
    interface = "Wi-Fi"

    # To test if arg entered is a valid IP address.
    ipaddress.ip_address(args.client_ip)
    sender_ip = "src host " + args.client_ip

    print("Listening...")
    listener(interface, sender_ip)


if __name__ == "__main__":
    main()
