import socket
import time
import argparse
from socket import create_connection
import threading
from scapy.all import IP, TCP, send

PAYLOAD = b"Network ACL testing!"


class SenderUDP:
    def __init__(self, ip):
        self.ip = ip
        self.sock = None

    def scan(self, dest_ip, port_range):
        """
        To function to perform UDP Scan.
        :param dest_ip: 
        :param port_range: 
        :return: 
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        port_range = port_range.split("-")
        floor_port = int(port_range[0])
        ceiling_port = int(port_range[1])

        for i in range(floor_port, ceiling_port + 1):
            self.sock.sendto(PAYLOAD, (dest_ip, i))
            # May be used to add delay between each port scan.
            # time.sleep(0.05)

        self.sock.close()


class SenderTCP:
    def __init__(self, ip):
        self.ip = ip
        self.sock = None

    def scan(self, dest_ip, port_range):
        """
        The function to perform the TCP scan.
        :param dest_ip:
        :param port_range:
        :return:
        """
        port_range = port_range.split("-")
        floor_port = int(port_range[0])
        ceiling_port = int(port_range[1])

        def scan_wrapper(port):
            """
            Wrapper for threads.
            :param port:
            :return:
            """
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(1)
            try:
                # self.sock = create_connection((dest_ip, port))
                print("Port:", port)
                self.sock.connect((dest_ip, port))
                self.sock.send(PAYLOAD)
                self.sock.close()
                print(f"Connected to port {port}!")
            except TimeoutError:
                pass

        threads_list = []

        for i in range(floor_port, ceiling_port + 1):
            t = threading.Thread(target=scan_wrapper, args=(i,))
            threads_list.append(t)

        for t in threads_list:
            t.start()
            # Can change this to find the fastest scan available.
            time.sleep(0.01)

        for t in threads_list:
            t.join()

        print("Scan completed!")


def get_local_ip():
    """
    Get local IP address, subject to further tests if more than 1 interface.
    :return:
    """
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


def port_validation(port_range):
    """
    Used solely to validate port range input.
    :param port_range:
    :return:
    """
    if port_range.lower() == "full":
        return True
    port_range = port_range.split("-")
    if len(port_range) != 2:
        raise ValueError("Unknown port range format!"
                         "Please enter in this format: (Lower range)-(upper range)"
                         "Example: 1-100")
    if int(port_range[0]) > int(port_range[1]) or int(port_range[1]) > 65535 or int(port_range[0]) < 0:
        raise ValueError("Invalid port range!")
    return True


def start_scan(dest_ip, port_range, mode):
    """
    Starts scanning the destination IP.
    Built for network ACL testing only!
    :return:
    """
    # Port range: 1 - 65535
    src_ip = get_local_ip()
    full_port_range = "1-65535"
    if port_range.lower() == "full":
        port_range = full_port_range

    print("Starting scan...")
    print("Source IP:", src_ip)
    print("Destination IP:", dest_ip)
    print("Port range:", port_range)
    print("Mode:", mode)
    print("====================================================================")
    if mode.upper() == "TCP":
        # thread_tcp = threading.Thread(target=SenderTCP, args=(src_ip, port_range))
        sender_tcp = SenderTCP(src_ip)
        sender_tcp.scan(dest_ip, port_range)
    elif mode.upper() == "UDP":
        sender_udp = SenderUDP(src_ip)
        sender_udp.scan(dest_ip, port_range)


def main():
    parser = argparse.ArgumentParser("Parser for scanner.")
    parser.add_argument("dest_ip", help="Destination IP address.")
    parser.add_argument("port_range", help="Port range. Enter 'full' to scan all ports.")
    parser.add_argument("mode", help="Scan mode (TCP or UDP).")

    args = parser.parse_args()

    dest_ip = args.dest_ip
    port_range = args.port_range
    mode = args.mode
    # Validation for port range.
    start_scan(dest_ip, port_range, mode)


if __name__ == '__main__':
    main()

