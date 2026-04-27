# ==============================================================
# Basic Network Sniffer
# Rhombix Technologies - Cybersecurity Internship Task 1
# Tool: Python | OS: Windows
# ==============================================================
#libraries
import socket
import struct
import textwrap
from datetime import datetime

# HELPER FUNCTIONS

def get_ip(raw_bytes):
    # Converts raw IP bytes to readable format
    return '.'.join(map(str, raw_bytes))

def get_mac(raw_bytes):
    # Converts raw MAC bytes to readable format
    return ':'.join(map('{:02x}'.format, raw_bytes)).upper()

def format_data(prefix, data, size=80):
    # Formats raw payload data into readable lines
    size -= len(prefix)
    if isinstance(data, bytes):
        data = ''.join(r'\x{:02x}'.format(b) for b in data)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(data, size)])

def protocol_name(num):
    # Returns protocol name from number
    protocols = {
        1:  'ICMP',
        6:  'TCP',
        17: 'UDP',
        2:  'IGMP',
        89: 'OSPF'
    }
    return protocols.get(num, f'Unknown({num})')

def port_service(port):
    # Returns service name from port number
    services = {
        20:   'FTP Data',
        21:   'FTP Control',
        22:   'SSH',
        23:   'Telnet',
        25:   'SMTP',
        53:   'DNS',
        67:   'DHCP Server',
        68:   'DHCP Client',
        80:   'HTTP',
        110:  'POP3',
        143:  'IMAP',
        443:  'HTTPS',
        3306: 'MySQL',
        3389: 'RDP',
        8080: 'HTTP Alternate',
        8443: 'HTTPS Alternate',
    }
    return services.get(port, '')


# PACKET PARSERS


def parse_ethernet(data):
    # Parses Ethernet frame - extracts MAC addresses and protocol
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

def parse_ipv4(data):
    # Parses IPv4 packet - extracts version, TTL, protocol, source and destination IP
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, ihl, ttl, proto, get_ip(src), get_ip(dest), data[ihl:]

def parse_tcp(data):
    # Parses TCP segment - extracts ports, sequence number and flags
    src_port, dest_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        'URG': (offset_flags & 32) >> 5,
        'ACK': (offset_flags & 16) >> 4,
        'PSH': (offset_flags & 8)  >> 3,
        'RST': (offset_flags & 4)  >> 2,
        'SYN': (offset_flags & 2)  >> 1,
        'FIN':  offset_flags & 1
    }
    return src_port, dest_port, seq, ack, flags, data[offset:]

def parse_udp(data):
    # Parses UDP segment - extracts source port, destination port and length
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def parse_icmp(data):
    # Parses ICMP packet - Type 8 = Echo Request, Type 0 = Echo Reply
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    descriptions = {
        0:  'Echo Reply',
        8:  'Echo /Request',
        3:  'Destination Unreachable',
        11: 'Time Exceeded'
    }
    desc = descriptions.get(icmp_type, f'Type {icmp_type}')
    return icmp_type, code, checksum, desc, data[4:]


# DISPLAY FUNCTIONS

def print_ipv4(version, ihl, ttl, proto, src, dest):
    print(f"\n  [IPv4 PACKET]")
    print(f"    Version         : {version}")
    print(f"    Header Length   : {ihl} bytes")
    print(f"    TTL             : {ttl} hops")
    print(f"    Protocol        : {protocol_name(proto)}")
    print(f"    Source IP       : {src}")
    print(f"    Destination IP  : {dest}")

def print_tcp(src_port, dest_port, seq, ack, flags, payload):
    src_svc  = port_service(src_port)
    dest_svc = port_service(dest_port)
    active_flags = [f for f, v in flags.items() if v]
    print(f"\n  [TCP SEGMENT]")
    print(f"    Source Port     : {src_port} {f'({src_svc})' if src_svc else ''}")
    print(f"    Dest Port       : {dest_port} {f'({dest_svc})' if dest_svc else ''}")
    print(f"    Sequence No     : {seq}")
    print(f"    Acknowledgment  : {ack}")
    print(f"    Active Flags    : {', '.join(active_flags) if active_flags else 'None'}")
    if payload:
        print(f"    Payload         : {len(payload)} bytes")
        print(format_data('      Data: ', payload))

def print_udp(src_port, dest_port, length, payload):
    dest_svc = port_service(dest_port)
    print(f"\n  [UDP SEGMENT]")
    print(f"    Source Port     : {src_port}")
    print(f"    Dest Port       : {dest_port} {f'({dest_svc})' if dest_svc else ''}")
    print(f"    Length          : {length} bytes")
    if payload:
        print(f"    Payload         : {len(payload)} bytes")

def print_icmp(icmp_type, code, checksum, desc):
    print(f"\n  [ICMP PACKET]")
    print(f"    Type            : {icmp_type} - {desc}")
    print(f"    Code            : {code}")
    print(f"    Checksum        : {checksum}")


# MAIN SNIFFER


def start_sniffer():
    print("\n" + "=" * 65)
    print("    BASIC NETWORK SNIFFER")
    print("    Rhombix Technologies - Cybersecurity Internship Task 1")
    print("    Captures & Analyzes Live Network Traffic")
    print("=" * 65)
    print("    NOTE: Run this script as Administrator!")
    print("    Press Ctrl+C to stop\n")

    packet_count = 0
    tcp_count    = 0
    udp_count    = 0
    icmp_count   = 0

    try:
        # Create raw socket for capturing network packets
        # AF_INET = IPv4, SOCK_RAW = raw packets, IPPROTO_IP = IP level
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        my_ip = my_ip = input("Enter your IP address (from ipconfig): ").strip()
        print(f"Your IP Address : {my_ip}")
        print(f"Started At      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nListening for packets...\n")

        conn.bind((my_ip, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode - capture all packets (Windows only)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while True:
            # Receive raw data from network (max 65535 bytes)
            raw_data, addr = conn.recvfrom(65535)
            packet_count += 1

            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print("=" * 65)
            print(f"  PACKET #{packet_count}  |  Time: {timestamp}")
            print("=" * 65)

            # Parse IPv4 packet
            version, ihl, ttl, proto, src_ip, dest_ip, data = parse_ipv4(raw_data)
            print_ipv4(version, ihl, ttl, proto, src_ip, dest_ip)

            # Parse based on protocol type

            # TCP (Protocol 6)
            if proto == 6:
                tcp_count += 1
                src_port, dest_port, seq, ack, flags, payload = parse_tcp(data)
                print_tcp(src_port, dest_port, seq, ack, flags, payload)

            # UDP (Protocol 17)
            elif proto == 17:
                udp_count += 1
                src_port, dest_port, length, payload = parse_udp(data)
                print_udp(src_port, dest_port, length, payload)

            # ICMP (Protocol 1)``
            elif proto == 1:
                icmp_count += 1
                icmp_type, code, checksum, desc, _ = parse_icmp(data)
                print_icmp(icmp_type, code, checksum, desc)

            print()

    except PermissionError:
        print("\n  ERROR: Admin rights required!")
        print("  Fix: Run CMD as Administrator")
        print("  Then type: python \"Network snifferr.py\"")

    except OSError as e:
        print(f"\n  Socket Error: {e}")

    except KeyboardInterrupt:
        # Show summary when Ctrl+C is pressed
        print("\n\n" + "=" * 65)
        print("  CAPTURE SUMMARY")
        print("=" * 65)
        print(f"  Total Packets   : {packet_count}")
        print(f"  TCP Packets     : {tcp_count}")
        print(f"  UDP Packets     : {udp_count}")
        print(f"  ICMP Packets    : {icmp_count}")
        print(f"  Stopped At      : {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 65)
        print("  Sniffer stopped!")

    finally:
        try:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            conn.close()
        except:
            pass

# ==============================================================
# PROGRAM START
# ==============================================================
if __name__ == "__main__":
    start_sniffer()