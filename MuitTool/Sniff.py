#!/usr/bin/env python3
import argparse
from scapy.all import sniff, wrpcap, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP, TCP
from datetime import datetime

class DNSListener:
    def __init__(self, interface=None, verbose=False, target_ip=None, target_domains=None,
                 filter_port=None, filter_src_ip=None, filter_dst_ip=None, dns_type=None, pcap_file=None):
        self.interface = interface
        self.verbose = verbose
        self.target_ip = target_ip
        self.target_domains = set(target_domains or [])
        self.filter_port = filter_port
        self.filter_src_ip = filter_src_ip
        self.filter_dst_ip = filter_dst_ip
        self.dns_type = dns_type
        self.pcap_file = pcap_file

        self.total_dns_requests = 0
        self.unique_domains = set()
        self.most_requested_domains = {}
        self.dns_types = {}
        self.source_ips = {}
        self.destination_ips = {}

    def process_packet(self, pkt):
        # Count every DNS packet seen
        if DNS not in pkt:
            return

        self.total_dns_requests += 1

        # Apply simple filters
        if self.filter_port and UDP in pkt and pkt[UDP].sport != self.filter_port and pkt[UDP].dport != self.filter_port:
            return
        if self.filter_src_ip and IP in pkt and pkt[IP].src != self.filter_src_ip:
            return
        if self.filter_dst_ip and IP in pkt and pkt[IP].dst != self.filter_dst_ip:
            return
        if self.dns_type and IP in pkt and pkt[IP].proto != self.dns_type:
            return

        # Track source/destination IP counts
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            self.source_ips[src] = self.source_ips.get(src, 0) + 1
            self.destination_ips[dst] = self.destination_ips.get(dst, 0) + 1

        # TCP-based DNS
        if pkt.haslayer(TCP) and pkt[TCP].dport == 53:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="ignore")
                if self.target_domains and qname not in self.target_domains:
                    return
                self._record_query(qname)
                self.print_info(pkt, "DNS Request", qname)

        # UDP-based DNS
        elif pkt.haslayer(UDP) and pkt[UDP].dport == 53:
            # Query
            if pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="ignore")
                if self.target_domains and qname not in self.target_domains:
                    return
                self._record_query(qname)
                self.print_info(pkt, "DNS Request", qname)
            # Response
            elif pkt[DNS].qr == 1 and pkt.haslayer(DNSRR) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="ignore")
                # rdata may be an IP or other data
                rdata = pkt[DNSRR].rdata
                if self.target_ip and str(rdata) != str(self.target_ip):
                    return
                self._record_query(qname)
                self.print_info(pkt, "DNS Response", qname, resp_ip=rdata)
                # track DNS "type" by IP.proto as a simple metric
                if IP in pkt:
                    proto = pkt[IP].proto
                    self.dns_types[proto] = self.dns_types.get(proto, 0) + 1

        # Optionally save to pcap (scapy's wrpcap)
        if self.pcap_file:
            try:
                wrpcap(self.pcap_file, pkt, append=True)
            except Exception:
                # Avoid crashing on pcap write errors
                pass

    def _record_query(self, qname):
        self.unique_domains.add(qname)
        self.most_requested_domains[qname] = self.most_requested_domains.get(qname, 0) + 1

    def print_info(self, pkt, packet_type, qname, resp_ip=None):
        # Simple printable representation without external libs
        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f') if hasattr(pkt, "time") else "N/A"
        src_ip = pkt[IP].src if IP in pkt else "N/A"
        dst_ip = pkt[IP].dst if IP in pkt else "N/A"
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "N/A"
        length = len(pkt)
        ttl = pkt[IP].ttl if IP in pkt and hasattr(pkt[IP], "ttl") else "N/A"
        proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "Unknown")

        print(f"Timestamp      : {timestamp}")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Source MAC     : {src_mac}")
        print(f"Destination MAC: {dst_mac}")
        print(f"Packet Size    : {length}")
        print(f"TTL            : {ttl}")
        print(f"Protocol       : {proto}")
        print(f"{packet_type}   : {qname}")
        if resp_ip is not None:
            print(f"Response Data  : {resp_ip}")
        print("-" * 60)

    def listen(self):
        filter_expr = "udp port 53 or tcp port 53"
        if self.interface:
            sniff(filter=filter_expr, prn=self.process_packet, store=0, iface=self.interface)
        else:
            sniff(filter=filter_expr, prn=self.process_packet, store=0)

    def print_summary(self):
        print("\nSummary")
        print("-------")
        print("Total DNS Requests    :", self.total_dns_requests)
        print("Unique Domains        :", len(self.unique_domains))
        print("Most Requested Domains:")
        for domain, count in sorted(self.most_requested_domains.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{domain}: {count} requests")
        print("DNS Types (by IP.proto):")
        for proto, count in sorted(self.dns_types.items()):
            print(f"\t{proto}: {count}")
        print("Source IPs:")
        for ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{ip}: {count}")
        print("Destination IPs:")
        for ip, count in sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{ip}: {count}")


def parse_args():
    parser = argparse.ArgumentParser(description="DNSWatch using only scapy (no external dependencies)")
    parser.add_argument("-i", "--interface", help="Interface to listen on")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (not used)")
    parser.add_argument("-t", "--target-ip", help="Target IP to filter DNS responses for")
    parser.add_argument("-D", "--target-domains", nargs="+", default=[], help="List of target domains to monitor")
    parser.add_argument("-p", "--filter-port", type=int, help="Filter by source or destination port")
    parser.add_argument("-s", "--filter-src-ip", help="Filter by source IP address")
    parser.add_argument("-r", "--filter-dst-ip", help="Filter by destination IP address")
    parser.add_argument("--dns-type", type=int, help="Filter by DNS type (IP.proto)")
    parser.add_argument("--pcap-file", help="Save captured packets to a pcap file")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_args()
        listener = DNSListener(
            interface=args.interface,
            verbose=args.verbose,
            target_ip=args.target_ip,
            target_domains=args.target_domains,
            filter_port=args.filter_port,
            filter_src_ip=args.filter_src_ip,
            filter_dst_ip=args.filter_dst_ip,
            dns_type=args.dns_type,
            pcap_file=args.pcap_file,
        )
        listener.listen()
        listener.print_summary()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except PermissionError:
        print("Permission denied: run with appropriate privileges (e.g. sudo).")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")