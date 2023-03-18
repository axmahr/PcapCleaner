#! /usr/bin/env python3

import logging
import hashlib
import argparse
import collections.abc
from scapy.all import sniff, load_layer

domains = set()
hashes = dict()

def get_attr(obj, attr, default=""):
        value = getattr(obj, attr, default)
        if value is None:
            value = default
        return value


def concat(data):
    result = []
    for i, d in enumerate(data):
        if isinstance(d, collections.abc.Iterable):
            result.append("-".join(map(str, d)))
        else:
            result.append(str(d))
    return ",".join(result)


def calculate_ja3(msg, is_client):
    try:
       tls_version = msg.version
    except AttributeError:
       return

    cipher = get_attr(msg, "ciphers" if is_client else "cipher")
    exts = get_attr(msg, "ext")
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
                ec_point_formats = get_attr(exts[loc], "ecpl")
            try:
                loc = extensions_type.index(10)
            except IndexError:
                elliptic_curves = []
            except ValueError:
                ec_point_formats = []
            else:
                elliptic_curves = get_attr(exts[loc], "groups")
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

    return hashlib.md5(concat(value).encode("utf8")).hexdigest()


def extract_features(pkt):
    dns_msg = pkt.getlayer("DNS")
    if dns_msg:
        if dns_msg.qd and dns_msg.an:
            domains.add(dns_msg.qd.qname.decode()[:-1])

    tcp_layer = pkt.getlayer("TCP")
    if tcp_layer is None:
        return
    src_port = str(tcp_layer.sport)
    dst_port = str(tcp_layer.dport)
    if dst_port == "80":
         http_msg = bytes(tcp_layer[0])[20:]
         if http_msg.startswith((b"GET", b"HEAD")):
            domains.add(http_msg.decode("utf-8").strip("\r\n").rsplit("Host: ")[1].split("\r\n")[0])
    if src_port != "443" and dst_port != "443":
        return
    ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
            
    client_hello = pkt.getlayer("TLSClientHello")
    if client_hello :
        sni = client_hello["TLS_Ext_ServerName"]
        if sni:
            domains.add(sni.servernames[0].servername.decode("utf-8"))
        hashes[(src_ip, src_port, dst_ip, dst_port)] = [calculate_ja3(client_hello, is_client=True), ""]
    server_hello = pkt.getlayer("TLSServerHello")
    if server_hello and (dst_ip, dst_port, src_ip, src_port) in hashes.keys():
        hashes[(dst_ip, dst_port, src_ip, src_port)][1] = calculate_ja3(server_hello, is_client=False)



logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
parser = argparse.ArgumentParser()
parser.add_argument(
    "-f", "--file", default=None,
    help="input capture filename",
    required=True
)
args = parser.parse_args()
input_file = args.file
load_layer("tls")
sniff(offline=input_file, prn=extract_features)

if "." in input_file:
        chunk = input_file.rsplit(".")[-2]
else:
    chunk = input_file

if "/" in chunk:
    chunk = chunk.rsplit("/")[-1]

with open(f"{chunk}_domains.txt", "w+") as domains_file:
        domains_file.writelines("\n".join(domains))
with open(f"{chunk}_hashes.txt", "w+") as hashes_file:
        hashes_file.writelines(set([f'{hash_pair[0]}, {hash_pair[1]}\n' for hash_pair in hashes.values()]))

