import datetime

import pandas as pd  # Pandas - Create and Manipulate DataFrames
import paramiko
from scapy.all import *  # Packet manipulation
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

NUM_OF_PACK_TO_SNIFF = 4
PSW = "4551"
USRNANE = "gal"
HOST_IP = "192.168.43.121"  # for ssh connection
SRC_IP = "192.168.1.2"  # "192.168.3.2", "192.168.2.2" change for diff node
SRC_PATH = './my_csv.csv'
DST_PATH = './Downloads/my_csv_4000_1.csv'  # change for diff node


def extract_time(rx):
    """Function  gets epoch from pcap transforms the delivery time .
    Returns datetime"""
    try:
        return datetime.fromtimestamp(rx).strftime('%Y-%m-%d %H:%M:%S:%f')
    except IndexError:
        return "0"


def extract_ttl(snff):
    """Function that extracts the ttl from the pcap sniffing.
    Returns int number sec"""
    try:  # In the case we encounter an IP layer
        return [i[IP].ttl for i, b in snff][0]
    except IndexError:  # if there is no IP layer, no dst, then dst = 0.0.0.0
        return '0'


def extra_src(snff):
    """Function that extracts the src from the pcap sniffing.
    Returns str """
    try:  # In the case we encounter an IP layer
        return [i[IP].src for i, b in snff][0]
    except IndexError:  # if there is no IP layer, no src, then src = 0.0.0.0
        return '0.0.0.0'


def extract_dst(snff):
    """Function that extracts the dst from the pcap sniffing.
    Returns str"""
    try:  # In the case we encounter an IP layer
        return [i[IP].dst for i, b in snff][0]
    except IndexError:  # if there is no IP layer, no dst, then dst = 0.0.0.0
        return '0.0.0.0'


def build_dataframe(srcs=[], dsts=[], ttls=[], dst_time=[], delay=[], count=NUM_OF_PACK_TO_SNIFF):
    """Build the dataframe based on the list extracted before.
    returns pandas dataframe with
    columns = srcs, dsts, ttls,dst_time, delay"""
    if dsts is None:
        dsts = []
    if srcs is None:
        srcs = []
    if not srcs:
        srcs = ['NaN' for i in range(count)]
    if not dsts:
        dsts = ['NaN' for i in range(count)]
    if not ttls:
        ttls = ['NaN' for i in range(count)]
    if not dst_time:
        dst_time = ['NaN' for i in range(count)]
    if not delay:
        delay = ['NaN' for i in range(count)]

    return pd.DataFrame(list(zip(srcs, dsts, ttls, dst_time, delay)),
                        columns=['srcs', 'dsts', 'ttls', 'dst_time', 'delay'])


def build_csv_file_with_name(df, src_path=SRC_PATH, dst_path=DST_PATH):
    """
    Transforms the df into csv file and sends it with SFTP client to remote host

    """

    df.to_csv(src_path, index=False)
    print("df is built")
    print('open ssh...')
    s = paramiko.SSHClient()
    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    s.connect(HOST_IP, 22, username=USRNANE, password=PSW, timeout=15, allow_agent=False)
    sftp = s.open_sftp()
    print('open sftp...')
    sftp.put(src_path, dst_path)
    print("file{} is sent successfully".format(dst_path))


def collect_the_data_for_one_host(host, src=SRC_IP):
    """ The function sends and recives packeges for ICMP for ONE HOST
    collects all data for only one ping and only one host ip"""

    packet = Ether() / IP(src=src, dst=host) / ICMP()
    try:
        pcap, uncapch = srp(packet, timeout=2, verbose=1)
        # if there is no layer connection
        rx = pcap[0][1]
        tx = pcap[0][0]
        delta = abs((rx.time - tx.sent_time) * 1000)
        srcs = extra_src(pcap)
        dsts = extract_dst(pcap)
        ttls = extract_ttl(pcap)
        dst_time = extract_time(rx.time)
        return delta, srcs, dsts, ttls, dst_time
    except IndexError:
        rx = uncapch[0][1]
        tx = uncapch[0][0]
        delta = abs((rx.time - tx.sent_time) * 1000)
        srcs = src
        dsts = host
        ttls = extract_ttl(pcap)
        dst_time = extract_time(rx.time)
        return delta, srcs, dsts, ttls, dst_time


def main(num=NUM_OF_PACK_TO_SNIFF):
    """The function creates lists with data for given n lines,
    builds the dataFrame, csv file
    and sends csv to remote server with ssh """
    print("Let's collect the data for {} pings from host {}!....".format(NUM_OF_PACK_TO_SNIFF, SRC_IP))
    delay = []
    srcs = []
    dsts = []
    ttls = []
    dst_time = []
    n = 0
    while n < num:
        for i in (['2', '3']):  # change for diff node ['1', '3'], ['1', '2']
            delay.append(collect_the_data_for_one_host('192.168.{}.2'.format(i))[0])
            srcs.append(collect_the_data_for_one_host('192.168.{}.2'.format(i))[1])
            dsts.append(collect_the_data_for_one_host('192.168.{}.2'.format(i))[2])
            ttls.append(collect_the_data_for_one_host('192.168.{}.2'.format(i))[3])
            dst_time.append(collect_the_data_for_one_host('192.168.{}.2'.format(i))[4])
            n += 1

    df = build_dataframe(srcs, dsts, ttls, dst_time, delay)

    build_csv_file_with_name(df, SRC_PATH, DST_PATH)


if __name__ == "__main__":
    main(NUM_OF_PACK_TO_SNIFF)
