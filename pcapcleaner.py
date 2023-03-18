#!/usr/bin/env python3

import logging
import argparse
import hashlib
import socket
import re
import os
import base64
import binascii
import collections.abc
from dataclasses import dataclass
from urllib.parse import unquote
from scapy.utils import PcapWriter, PcapReader
from scapy.packet import Packet, Raw
from scapy.all import sniff, load_layer, tcpdump, rdpcap
from scapy.error import Scapy_Exception


@dataclass
class Config:
    input_filename: str
    target_domains: list[str]
    target_hashes: list[tuple[str, str]]
    filter_periodicity: bool
    export_coloring_rule: bool
    tmp_file: PcapWriter
    out_file: PcapWriter


@dataclass
class PacketData:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str

    def construct_bg_id(self) -> tuple[str, str, str, str]:
        return self.src_ip, self.src_port, self.dst_ip, self.dst_port

    def construct_bg_id2(self) -> tuple[str, str, str, str]:
        return self.dst_ip, self.dst_port, self.src_ip, self.src_port


@dataclass
class TlsData:
    serial_numbers: set()
    cert_len: int
    tmp_len: int
    server_hello_time: int


class PcapCleaner:
    ips: set
    bg_ids: set
    packet_numbers: set
    old_packet_numbers: dict
    local_hashes: dict
    domains_and_ips: dict
    remaining_bg_ids: set
    periodic_domains: set

    packet_data: PacketData
    tls_data: TlsData

    config: Config
    counter: int

    def __init__(self, config: Config):
        self.config = config

        self.counter = 0
        self.packet_data = PacketData(0.0, "", "", "", "")
        self.tls_data = TlsData(set(), 0, 0, 0)
        self.old_packet_numbers = dict()
        self.domains_and_ips = dict()
        self.local_hashes = dict()
        self.packet_numbers = set()
        self.bg_ids = set()
        self.ips = set()
        self.remaining_bg_ids = set()
        self.periodic_domains = set()


    def _is_in_target_domains(self, domain_name: str) -> int:
        for td in self.config.target_domains:
            if domain_name.endswith(td):
                return 1
        return 0


    def _get_attr(self, obj, attr, default=""):
        value = getattr(obj, attr, default)
        if value is None:
            value = default
        return value


    def _concat(self, data: list) -> str:
        result = []
        for i, d in enumerate(data):
            if isinstance(d, collections.abc.Iterable):
                result.append("-".join(map(str, d)))
            else:
                result.append(str(d))
        return ",".join(result)


    def _calculate_ja3(self, msg, is_client: bool) -> str:
        try:
            tls_version = msg.version
        except AttributeError:
            return

        cipher = self._get_attr(msg, "ciphers" if is_client else "cipher")
        exts = self._get_attr(msg, "ext")
        if exts:
            extensions_type = list(map(lambda c: c.type, exts))
            if is_client:
                try:
                    loc = extensions_type.index(11)
                except IndexError:
                    ec_point_formats = []
                except ValueError:
                    ec_point_formats = []
                else:
                    ec_point_formats = self._get_attr(exts[loc], "ecpl")

                try:
                    loc = extensions_type.index(10)
                except IndexError:
                    elliptic_curves = []
                except ValueError:
                    ec_point_formats = []
                else:
                    elliptic_curves = self._get_attr(exts[loc], "groups")
        else:
            extensions_type = elliptic_curves = ec_point_formats = []

        if is_client:
            value = [
                tls_version,
                cipher,
                extensions_type,
                elliptic_curves,
                ec_point_formats,
            ]
        else:
            value = [tls_version, cipher, extensions_type]

        return hashlib.md5(self._concat(value).encode("utf8")).hexdigest()


    def _parse_dns_message(self, dns_msg) -> None:
        self.old_packet_numbers[(self.packet_data.timestamp, float(dns_msg.id))] = self.counter
        if dns_msg.an:
            domain_name = dns_msg.qd.qname.decode()[:-1]
            if domain_name not in self.domains_and_ips.keys():
                self.domains_and_ips[domain_name] = set()
            is_target = self._is_in_target_domains(domain_name)
            for i in range(dns_msg.ancount):
                rr = dns_msg.an[i]
                if rr.type == 1 or rr.type == 28:
                    # Type A (Host Address) or AAAA (IPv6)
                    ip_addr = str(rr.rdata)
                    self.domains_and_ips[domain_name].add(ip_addr)
                    if is_target:
                        self.ips.add(ip_addr)


    def _parse_http_message(self, http_msg: bytes) -> None:
        if http_msg.startswith((b"GET", b"HEAD")):
            decoded_http_msg = http_msg.decode("utf-8").strip("\r\n")
            host = decoded_http_msg.rsplit("Host: ")[1].split("\r\n")[0]
            if self.config.filter_periodicity:
                if host in self.domains_and_ips.keys():
                    self.domains_and_ips[host].add(self.packet_data.dst_ip)
                else:
                    self.domains_and_ips[host] = set([self.packet_data.dst_ip])
            if self._is_in_target_domains(host) or self.packet_data.dst_ip in self.ips:
                self.bg_ids.add(self.packet_data.construct_bg_id())
                return
            elif http_msg.startswith(b"GET"):
                # check oscp request via http get
                # in that case, the ocsp request in encoded the http request path
                # see rfc6960 appendix A.1
                path = decoded_http_msg[4:].split(" ")[0][1:]
                path_unquoted = unquote(path)
                try:
                    ocsp_layer = base64.b64decode(path_unquoted)
                except binascii.Error:
                    return

                serial_number = int.from_bytes(ocsp_layer.rsplit(b"\x30")[-1].rsplit(b"\x02\x10")[-1], "big")
                if serial_number in self.tls_data.serial_numbers:
                    self.bg_ids.add(self.packet_data.construct_bg_id())
                    return

        elif http_msg.startswith(b"POST"):
            # possible ocsp request
            ocsp_layer = http_msg.rsplit(b"\r\n")[-1]
            serial_number = int.from_bytes(ocsp_layer.rsplit(b"\x30")[-1].rsplit(b"\x02\x10")[-1], "big")
            if serial_number in self.tls_data.serial_numbers:
                self.bg_ids.add(self.packet_data.construct_bg_id())
                return


    def _parse_tls_handshake(self, msg, tcp_layer):
        if msg.msgtype == 1:
            # client hello
            identifier = self.packet_data.construct_bg_id()
            if self.config.target_domains:
                server_name = msg["TLS_Ext_ServerName"].servernames[0].servername.decode("utf-8")
                if self._is_in_target_domains(server_name) or self.packet_data.dst_ip in self.ips:
                    self.bg_ids.add(identifier)

                if self.config.filter_periodicity:
                    if server_name in self.domains_and_ips.keys():
                        self.domains_and_ips[server_name].add(self.packet_data.dst_ip)
                    else:
                        self.domains_and_ips[server_name] = set([self.packet_data.dst_ip])

            if self.config.target_hashes:
                md5_fp = self._calculate_ja3(msg, is_client=True)
                self.local_hashes[identifier] = [md5_fp, ""]
            return

        elif msg.msgtype == 2:
            # server hello
            identifier = self.packet_data.construct_bg_id2()
            if self.config.target_hashes:
                if identifier not in self.local_hashes.keys():
                    return
                md5_fp = self._calculate_ja3(msg, is_client=False)
                self.local_hashes[identifier][1] = md5_fp
                # check combination of ja3 and ja3s hash regarding bg traffic
                if tuple(self.local_hashes[identifier]) in self.config.target_hashes:
                    self.bg_ids.add(identifier)

            if identifier in self.bg_ids:
                # check following certificate message
                server_hello_len = msg.msglen
                self.tls_data.server_hello_time = self.packet_data.timestamp
                tcp_payload = bytes(tcp_layer[1])
                if re.match(b"^\x16[\x03\x03|\x03\x01][\x00-\xff]{3}\x0b$", tcp_payload[server_hello_len+9 : server_hello_len+9+6]):
                    # (+9:  we have additionally the tls record header and the server hello header)
                    # first case: tls record layer header before the following certificates
                    # extract serial number of first certificate to identify ocsp traffic regarding that certificate later
                    # serial number is max. 20 bytes
                    serial_number = tcp_payload[server_hello_len+9+6+24 : server_hello_len+9+6+24+20].split(b"\x30")[0]
                    self.tls_data.serial_numbers.add(int.from_bytes(serial_number, "big"))
                    # memorize some values so that we can also extract the serial numbers of additional certificates from CAs
                    self.tls_data.cert_len = int.from_bytes(tcp_payload[server_hello_len+21 : server_hello_len+24],"big")
                    self.tls_data.tmp_len = len(tcp_payload[server_hello_len+24 :])
                elif re.match(b"^\x0b\x00$", tcp_payload[server_hello_len+9 : server_hello_len+9+2]):
                    # second case: no tls record layer header before the following certificates (mutiple handshake messages in one record)
                    # then, the offsets are slightly different (minus 5 bytes)
                    serial_number = tcp_payload[server_hello_len+4+6+24 : server_hello_len+4+6+24+20].split(b"\x30")[0]
                    self.tls_data.serial_numbers.add(int.from_bytes(serial_number, "big"))
                    self.tls_data.cert_len = int.from_bytes(tcp_payload[server_hello_len+16 : server_hello_len+19],"big",)
                    self.tls_data.tmp_len = len(tcp_payload[server_hello_len+19 :])
                elif re.match(b"^\x00\x0b\x00$", tcp_payload[server_hello_len+9 : server_hello_len+9+3]):
                    # certificate message may be off by one byte
                    serial_number = tcp_payload[server_hello_len+5+6+24 : server_hello_len+5+6+24+20].split(b"\x30")[0]
                    self.tls_data.serial_numbers.add(int.from_bytes(serial_number, "big"))
                    self.tls_data.cert_len = int.from_bytes(tcp_payload[server_hello_len+17 : server_hello_len+20],"big",)
                    self.tls_data.tmp_len = len(tcp_payload[server_hello_len+20 :])


    def _parse_tls_message(self, pkt: Packet) -> None:
        tcp_layer = pkt.getlayer("TCP")
        # tls handshake messages
        if (pkt.haslayer("TLSClientHello") or pkt.haslayer("TLSServerHello")) and not pkt.haslayer("TLSHelloRequest"):
            # bug in scapy: encrypted handshake message can be interpreted as hello request + client/server hello
            for msg in pkt["TLS"].msg:
                if isinstance(msg, Raw):
                    continue
                self._parse_tls_handshake(msg, tcp_layer)

        elif self.packet_data.timestamp - self.tls_data.server_hello_time < 0.5 and self.packet_data.construct_bg_id2() in self.bg_ids and len(pkt) > 1000:
            # more possible certificate fragments in subsequent packets after server hello
            cert_frag = bytes(tcp_layer[1])
            if self.tls_data.cert_len - self.tls_data.tmp_len > len(cert_frag):
                # when the certificate is bigger than the whole packet
                self.tls_data.tmp_len = len(cert_frag) + self.tls_data.tmp_len
                return
            new_cert_len = int.from_bytes(cert_frag[self.tls_data.cert_len-self.tls_data.tmp_len : self.tls_data.cert_len-self.tls_data.tmp_len+3], "big")
            if new_cert_len < 0x10000:
                # otherwise we probably reached the end of the certificate list
                # extract serial_number of next possible certificate
                serial_number = cert_frag[self.tls_data.cert_len-self.tls_data.tmp_len+18 : self.tls_data.cert_len-self.tls_data.tmp_len+18+20].split(b"\x30")[0]
                self.tls_data.serial_numbers.add(int.from_bytes(serial_number, "big"))
                self.tls_data.tmp_len = len(cert_frag[self.tls_data.cert_len-self.tls_data.tmp_len+3 :])
                self.tls_data.cert_len = new_cert_len


    def _identify_bg_traffic(self, pkt: Packet) -> None:
        self.counter = self.counter + 1
        self.packet_data.timestamp = float(pkt.time)

        if self.config.target_domains or self.config.filter_periodicity:
            dns_msg = pkt.getlayer("DNS")
            if dns_msg and dns_msg.qd:
                self._parse_dns_message(dns_msg)
                return

        tcp_layer = pkt.getlayer("TCP")
        if tcp_layer is None:
            return

        ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
        self.packet_data.src_ip = str(ip_layer.src)
        self.packet_data.dst_ip = str(ip_layer.dst)
        self.packet_data.src_port = str(tcp_layer.sport)
        self.packet_data.dst_port = str(tcp_layer.dport)
        self.old_packet_numbers[(float(pkt.time), float(tcp_layer.seq))] = self.counter

        if self.packet_data.construct_bg_id() in self.bg_ids or self.packet_data.construct_bg_id2() in self.bg_ids:
            return

        if self.packet_data.dst_port == "80":
            # http packets
            http_msg = bytes(tcp_layer[0])[20:]
            self._parse_http_message(http_msg)
            return

        if self.packet_data.dst_port == "443" or self.packet_data.src_port == "443":
            self._parse_tls_message(pkt)


    def _filter_by_bg_ids(self, pkt: Packet) -> None:
        self.counter = self.counter + 1

        ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
        if ip_layer is None:
            # ARP etc is assumed to be background traffic
            self.packet_numbers.add(self.counter)
            return
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        # filter packets with multicast addresses
        if re.search(r"^22[4-9]|23[0-9]$", dst_ip[:3]) or dst_ip.startswith("ff0"):
            self.packet_numbers.add(self.counter)
            return

        tcp_layer = pkt.getlayer("TCP")
        if tcp_layer is None:
            # icmp packets could be related to user-initiated traffic
            icmp_layer = pkt.getlayer("ICMP")
            if icmp_layer:
                if src_ip in self.ips or dst_ip in self.ips:
                    # icmp packet probably belongs to background traffic
                    self.packet_numbers.add(self.counter)
                    return
                ref_src_addr = socket.inet_ntoa(bytes(icmp_layer.payload)[12:16])
                ref_dst_addr = socket.inet_ntoa(bytes(icmp_layer.payload)[16:20])
                if re.search(ref_dst_addr[:2], r"^22[4-9]|23[0-9]$") or (ref_src_addr in self.ips or ref_dst_addr in self.ips):
                    # icmp packet belongs to a previous packet with multicast destination address or background traffic with "normal" addresses
                    self.packet_numbers.add(self.counter)
                    return
            elif pkt.haslayer("IPv6"):
                if ip_layer.fields["nh"] == 58:
                    # icmpv6
                    if bytes(ip_layer.payload)[0] in [135, 136]:
                        # neighbor solicitation/advertisement
                        self.packet_numbers.add(self.counter)
                        return
                    if src_ip in self.ips or dst_ip in self.ips:
                        # icmpv6 packet probably belongs to background traffic
                        self.packet_numbers.add(self.counter)
                        return
                    ref_src_addr = socket.inet_ntop(socket.AF_INET6, bytes(ip_layer.payload)[16:32])
                    ref_dst_addr = socket.inet_ntop(socket.AF_INET6, bytes(ip_layer.payload)[32:48])
                    if ref_dst_addr.startswith("ff0") or (ref_src_addr in self.ips or ref_dst_addr in self.ips):
                        # icmpv6 packet belongs to a previous packet with multicast destination address or background traffic with "normal" addresses
                        self.packet_numbers.add(self.counter)
                        return

            # filter dhcp, ntp etc
            if pkt.haslayer("DHCP") or pkt.haslayer("DHCPv6") or pkt.haslayer("NTP"):
                self.packet_numbers.add(self.counter)
                return
            if pkt.haslayer("DNS") and pkt.getlayer("DNS").qd:
                dns_msg = pkt.getlayer("DNS")
                if dns_msg.qd.qtype == 12:
                    # filter PTR type
                    self.packet_numbers.add(self.counter)
                    return
                domain_name = dns_msg.qd.qname.decode()[:-1]
                if self._is_in_target_domains(domain_name) or domain_name.endswith(".home"):
                    # filter dns traffic associated with a target domain and local network
                    self.packet_numbers.add(self.counter)
                    return

            udp_layer = pkt.getlayer("UDP")
            if udp_layer:
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                if src_port == dst_port == 137 or src_port == dst_port == 138:
                    # filter netbios name service
                    self.packet_numbers.add(self.counter)
                    return

            if self.config.filter_periodicity:
                self.config.tmp_file.write(pkt)
            else:
                self.config.out_file.write(pkt)
            return

        src_port = str(tcp_layer.sport)
        dst_port = str(tcp_layer.dport)
        id1 = (src_ip, src_port, dst_ip, dst_port)
        id2 = (dst_ip, dst_port, src_ip, src_port)

        if id1 in self.bg_ids or id2 in self.bg_ids:
            # packet belongs to background traffic, so don't write it anywhere and return
            self.packet_numbers.add(self.counter)
            return

        if self.config.filter_periodicity:
            self.config.tmp_file.write(pkt)
        else:
            self.config.out_file.write(pkt)


    def _get_remaining_tcp_connections(self) -> set:
        ret = set()
        try:
            sink = PcapReader(self.config.tmp_file.filename)
        except Scapy_Exception:
            return ret
        remaining_ocsp_connections = set()
        for pkt in PcapReader(self.config.tmp_file.filename):
            tcp_layer = pkt.getlayer("TCP")
            if tcp_layer:
                ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                identifier = (src_ip, src_port, dst_ip, dst_port)

                # ocsp traffic, which wasn't filtered, must not be analyzed regarding periodicity, because
                # sometimes foreground ocsp traffic is periodic after the ocsp reuqests/response for a certain time
                if dst_port == 80:
                    http_msg = bytes(tcp_layer[0])[20:]
                    if http_msg.startswith(b"POST") and re.search(b"0[A-Z]0[A-Z]0[A-Z]", http_msg):
                        if identifier in ret:
                            ret.remove(identifier)
                        remaining_ocsp_connections.add(identifier)
                        continue
                if identifier in remaining_ocsp_connections:
                    continue
                if identifier not in self.bg_ids and src_port > dst_port:
                    ret.add(identifier)
        return ret


    def _check_periodicity(self, pcap_reader: PcapReader, between_connections: bool) -> bool:
        packets = list(pcap_reader)
        if len(packets) == 0:
            return False

        first_pkt = packets[0]
        tcp_layer = first_pkt.getlayer("TCP")
        prev_time = float(first_pkt.time)
        periods = []
        if len(packets) > 3:
            for pkt in packets:
                tcp_layer = pkt.getlayer("TCP")
                if pkt.time - prev_time > 5:
                    # inter-packet time > 5 sec. -> save the time
                    periods.append(float(pkt.time - prev_time))
                prev_time = float(pkt.time)

            periods_length = len(periods)
            error = 0
            if periods_length > 2:
                # when there are more than 2 period lengths
                prev_period = periods[0]
                for period in periods[1:]:
                    diff = period - prev_period
                    if abs(diff) > 1:
                        error = error + 1
                    prev_period = period
                # allow a deviation of period length with no more than every 10th packet
                if error / periods_length <= 0.1:
                    return True

        ip_layer = first_pkt.getlayer("IP") or first_pkt.getlayer("IPv6")
        if not between_connections and (ip_layer.src in self.ips or ip_layer.dst in self.ips):
            # check the case, that tcp handshake of bg traffic is not completed or
            # tcp connection is closed immediately after handshake
            ack_allowed = 0
            for pkt in packets:
                tcp_layer = pkt.getlayer("TCP")
                flags = tcp_layer.flags
                if flags == "SA" or flags == "FA":
                    ack_allowed = 1
                    continue
                if "S" in tcp_layer.flags or "F" in tcp_layer.flags or "R" in tcp_layer.flags:
                    continue
                elif ack_allowed and flags == "A":
                    ack_allowed = 0
                    continue
                else:
                    return False
            return True

        return False


    def _get_domain_from_ip(self, ip_addr: str) -> str:
        for domain_name in self.domains_and_ips.keys():
            if ip_addr in self.domains_and_ips[domain_name]:
                return domain_name
        return ""


    def _format_ips(self, ip_addresses: list[str]) -> str:
        ret = "("
        for i, _ in enumerate(ip_addresses):
            ret = ret + "host " + ip_addresses[i]
            if i < len(ip_addresses) - 1:
                ret = ret + " or "
        ret = ret + ")"
        return ret


    def _identify_periodic_traffic(self, remaining_tcp_connections: set) -> None:
        for src_ip, src_port, dst_ip, dst_port in remaining_tcp_connections:
            # consider periodicity within tcp connections
            tcpdump_filter = "tcp and host "+src_ip+" and port "+str(src_port)+" and host "+dst_ip+ " and port "+str(dst_port)
            with PcapReader(
                tcpdump(
                    pktlist=self.config.tmp_file.filename,
                    quiet=True,
                    args=["-w", "-", tcpdump_filter],
                    getfd=True,
                    prog="tcpdump",
                )
            ) as pcap_reader:
                if self._check_periodicity(pcap_reader, between_connections=False):
                    self.remaining_bg_ids.add((src_ip, src_port, dst_ip, dst_port))

        for src_ip, src_port, dst_ip, dst_port in remaining_tcp_connections:
            # consider periodicity between tcp connections with same domain
            domain_name = self._get_domain_from_ip(dst_ip)
            if domain_name != "":
                server_ips = self.domains_and_ips[domain_name]
                ipv4_ips = set()
                ipv6_ips = set()

                for ip in server_ips:
                    if ":" in ip:
                        ipv6_ips.add(ip)
                    else:
                        ipv4_ips.add(ip)

                tcpdump_filter = "tcp and "
                if len(ipv4_ips) > 0:
                    tcpdump_filter = tcpdump_filter+"("+self._format_ips(list(ipv4_ips))+" and tcp[tcpflags] & tcp-syn != 0)"
                    if len(ipv6_ips) > 0:
                        tcpdump_filter = tcpdump_filter+" or ("+self._format_ips(list(ipv6_ips))+" and ip6[13+40]&0x02 != 0)"
                elif len(ipv6_ips) > 0:
                    tcpdump_filter = tcpdump_filter+"("+self._format_ips(list(ipv6_ips))+" and ip6[13+40]&0x02 != 0)"
                with PcapReader(
                    tcpdump(
                        pktlist=self.config.tmp_file.filename,
                        quiet=True,
                        args=["-w", "-", tcpdump_filter],
                        getfd=True,
                        prog="tcpdump",
                    )
                ) as pcap_reader:
                    if self._check_periodicity(pcap_reader, between_connections=True):
                        self.remaining_bg_ids.add((src_ip, src_port, dst_ip, dst_port))
                        self.periodic_domains.add(domain_name)


    def _filter_by_remaining_bg_ids(self, pkt):
        if pkt.haslayer("TCP"):
            tcp_layer = pkt.getlayer("TCP")
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            id1 = (src_ip, src_port, dst_ip, dst_port)
            id2 = (dst_ip, dst_port, src_ip, src_port)
            if id1 in self.remaining_bg_ids or id2 in self.remaining_bg_ids:
                # packet belongs to background traffic, so don't write it anywhere and return
                self.packet_numbers.add(self.old_packet_numbers[(float(pkt.time), float(tcp_layer.seq))])
                return
        elif pkt.haslayer("DNS") and pkt.getlayer("DNS").qd:
            dns_msg = pkt.getlayer("DNS")
            domain_name = dns_msg.qd.qname.decode()[:-1]
            if domain_name in self.periodic_domains:
                self.packet_numbers.add(self.old_packet_numbers[(float(pkt.time), float(dns_msg.id))])
                return

        self.config.out_file.write(pkt)


    def _create_coloring_rule(self) -> None:
        # dump packet numbers of packets belonging to background traffic in file for a wireshark coloring rule
        sorted_numbers = sorted(self.packet_numbers)
        length = len(sorted_numbers)
        old_packet_num = range(1, len(list(rdpcap(self.config.input_filename))))
        # set different wireshark filter depending on number of filtered packets to reduce the filter size
        # wireshark doesnot like too long filter expressions
        coloring_filename = (f"{self.config.tmp_file.filename.rsplit('_tmp.pcap')[-2]}_bg_coloring_rule")
        if length < 4000:
            pn = open(coloring_filename, "w+")
            pn.write("@background traffic@")
            for index, num in enumerate(sorted_numbers):
                pn.write(f"frame.number == {num}")
                if index != length - 1:
                    pn.write(" or ")
            pn.write("@[0,21845,65535][65535,65535,65535]")
            pn.close()

        elif len(old_packet_num) - length < 4000:
            not_filtered = list(set(old_packet_num) - set(sorted_numbers))
            pn = open(coloring_filename, "w+")
            pn.write("@background traffic@")
            for index, num in enumerate(not_filtered):
                pn.write(f"frame.number != {num}")
                if index != len(not_filtered) - 1:
                    pn.write(" and ")
            pn.write("@[0,21845,65535][65535,65535,65535]")
            pn.close()


    def run(self):
        try:
            sniff(offline=self.config.input_filename, prn=self._identify_bg_traffic)
            self.counter = 0
            sniff(offline=self.config.input_filename, prn=self._filter_by_bg_ids)

            if self.config.filter_periodicity:
                self.config.tmp_file.close()
                remaining_tcp_connections = self._get_remaining_tcp_connections()
                if len(remaining_tcp_connections) > 0:
                    self._identify_periodic_traffic(remaining_tcp_connections)
                    sniff(offline=self.config.tmp_file.filename,prn=self._filter_by_remaining_bg_ids)
        except Exception as e:
            print(f"An Exception occured:")
            print(e)
            os.remove(self.config.tmp_file.filename)
            self.config.out_file.close()
            os.remove(self.config.out_file.filename)
            exit(3)

        self.config.out_file.close()

        if self.config.export_coloring_rule:
            self._create_coloring_rule()

        os.remove(self.config.tmp_file.filename)



def parse_commandline():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--file",
        default=None,
        help="input capture filename",
        required=True
    )
    parser.add_argument(
        "-t",
        "--targets",
        default=None,
        help="file with target domains, one domain per line",
        required=False
    )
    parser.add_argument(
        "-j",
        "--ja3",
        default=None,
        help="file with pairs of ja3/ja3s hashes like the file 'ja3_ja3s_hashes'",
        required=False
    )
    parser.add_argument(
        "--filter-periodicity",
        default=False,
        action="store_true",
        help="also filter periodic tcp connections",
        required=False
    )
    parser.add_argument(
        "--export-rule",
        default=False,
        action="store_true",
        help="export wireshark coloring rule to color detected background traffic",
        required=False
    )

    args = parser.parse_args()
    input_file = args.file
    targets_file = args.targets
    ja3_file = args.ja3
    filter_periodicity = args.filter_periodicity
    export_rule = args.export_rule

    if targets_file is None and ja3_file is None:
        print("-t/--targets and/or -j/--ja3 must be set!\n")
        parser.print_help()
        exit(1)

    if "." in input_file:
        chunk = input_file.rsplit(".")[-2]
    else:
        chunk = input_file

    if "/" in chunk:
        chunk = chunk.rsplit("/")[-1]

    try:
        if targets_file:
            with open(targets_file, "r") as td:
                target_domains = [line.replace("\n", "") for line in td]
        else:
            target_domains = list()
        if ja3_file:
            with open(ja3_file, "r") as nd:
                target_hashes = [tuple(line.replace("\n", "").split(", ")) for line in nd]
        else:
            target_hashes = list()
    except OSError:
        print("Failed to open passed file(s)")
        exit(2)

    tmp_filename = f"{chunk}_tmp.pcap"
    if os.path.isfile(tmp_filename):
        os.remove(tmp_filename)
    pcap_tmp = PcapWriter(f"{chunk}_tmp.pcap", append=True, sync=True)
    out_filename = f"{chunk}_cleaned.pcap"
    if os.path.isfile(out_filename):
        os.remove(out_filename)
    pcap_out = PcapWriter(out_filename, append=True, sync=True)

    load_layer("tls")

    return Config(input_file, target_domains, target_hashes, filter_periodicity, export_rule, pcap_tmp, pcap_out)


def main():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    config = parse_commandline()

    pcap_cleaner = PcapCleaner(config)
    pcap_cleaner.run()


if __name__ == "__main__":
    main()
