#!/bin/env python3
from bcc import BPF
import time
import socket
import os
from ipaddress import IPv4Address
import netifaces
import argparse
import json
import math

INDEX_IP_SRC = 0
INDEX_IP_DST = 1
INDEX_PORT_SRC = 2
INDEX_PORT_DST = 3
INDEX_PROTOCOL = 4

CONFIG_FILE_NAME = "config.json"


# define BPF program
bpf_text = """
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>


#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1


BPF_ARRAY(packet_count, u64, 256);
BPF_ARRAY(packet_size, u64, 256);
BPF_ARRAY(packet_size_goodput, u64, 256);


BPF_HASH(prev_time_jitter_hash, int, u64, 256);
BPF_HASH(jitter_index_hash, int, int, 256);

BPF_ARRAY(jitter_values_tcp, u64, 256);
BPF_ARRAY(jitter_values_udp, u64, 256);
BPF_ARRAY(jitter_values_icmp, u64, 256);


int count_packets(struct __sk_buff *skb) {
    int zero = 0;
    int one = 1;

    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    int protocol = ip->nextp;
    
    // size of ip packet
    int size = ip->tlen;

    // packet without ip header
    size -= ip->hlen;
    int size_goodput = size;
    
    u32 daddr, saddr;
    saddr = ip->src;
    daddr = ip->dst;

    u16 sport, dport;
    if (protocol == IPPROTO_UDP) {
        struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
        sport = udp->sport;
        dport = udp->dport;
        size_goodput -= 8;
    } else if (protocol == IPPROTO_TCP) {
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
        sport = tcp->src_port;
        dport = tcp->dst_port;
        size_goodput -= tcp->offset;
    }


    FILTER_incoming

    FILTER_RULES


    // Throughput measurement
    u64 *packet_counter = packet_count.lookup(&protocol);

    u64 *old_size = packet_size.lookup(&protocol);
    u64 *old_size_goodput = packet_size_goodput.lookup(&protocol);

    u64 new_size = size;
    u64 new_size_goodput = size_goodput;
    

    if (old_size)
        new_size += *old_size;

    if (old_size_goodput)
        new_size_goodput += *old_size_goodput;


    if (packet_counter) {
        packet_count.increment(protocol);
        packet_size.update(&protocol, &new_size);
        packet_size_goodput.update(&protocol, &new_size_goodput);
    }

    // Jitter measurement
    u64 current_time_jitter = 0;
    current_time_jitter = bpf_ktime_get_ns();

    u64 *prev_time_jitter = NULL;
    if ((prev_time_jitter = prev_time_jitter_hash.lookup(&protocol))) {
        prev_time_jitter_hash.delete(&protocol);
    } else {
        prev_time_jitter_hash.update(&protocol, &current_time_jitter);
    }


    int *jitter_index = NULL;
    jitter_index = jitter_index_hash.lookup(&protocol);
    if (!jitter_index) {
        jitter_index_hash.update(&protocol, &zero);
    }
    

    if (prev_time_jitter) {
        u64 interval_jitter = INTERVAL_JITTER;
        u64 tmp_jitter = current_time_jitter - *prev_time_jitter - interval_jitter;
        
        prev_time_jitter_hash.update(&protocol, &current_time_jitter);
        
        jitter_index = jitter_index_hash.lookup(&protocol);
        if (jitter_index) {
            if (protocol == PROTO_TCP) {
                jitter_values_tcp.update(jitter_index, &tmp_jitter);
            } else if (protocol == PROTO_UDP) {
                jitter_values_udp.update(jitter_index, &tmp_jitter);
            } else if (protocol == PROTO_ICMP) {
                jitter_values_icmp.update(jitter_index, &tmp_jitter);
            }

            // prevent index out of bounds
            if (*jitter_index == 255) {
                jitter_index_hash.update(&protocol, &zero);
            } else {
                jitter_index_hash.increment(protocol);
            }
        }    
    }
    
    return 0;
}
"""

# -----------------------------------------------------------------------------


# help function
def prog_help():
    print("For help write: sudo python3 monitor.py -h")
    exit(1)


# -----------------------------------------------------------------------------


def str_to_list(text):
    return list(map(str.strip, text.strip('][').replace('"', '').split(',')))


# -----------------------------------------------------------------------------


# This function gives me the ip address for a given interface
def get_ip(interface):
    ip = None
    try:
        ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except ValueError:
        print("Error: You must specify a valid interface name.")
        exit(0)
    except KeyError:
        print("Error: The interface must have an assigned IP address")
        exit(0)
    return ip


# -----------------------------------------------------------------------------


# add optional arguments for program
def optional_args():
    parser = argparse.ArgumentParser(description='Compute throughput and \
                                     jitter for each TCP, UDP, ICMP flow')

    parser.add_argument('-i', dest='INTERFACES', help='specify the interfaces \
                        on which to do measurements (i.e. ens33 or ens33,lo)')
    parser.add_argument('-t', dest='INTERVAL_throughput', default=1, help='specify \
                        the interval in seconds on which to do throughput measurement')
    parser.add_argument('-b', action='store_true', default=False, dest='b_B_SWITCH',
                        help='display the throughput in bits/second format')
    parser.add_argument('-B', action='store_false', default=False, dest='b_B_SWITCH',
                        help='display the throughput in Bytes/second format')
    parser.add_argument('-j', dest='INTERVAL_JITTER', default=0, help='specify \
                        the transmission interval in miliseconds between packets')

    return parser


# -----------------------------------------------------------------------------


# function for take the arguments from command line 
def take_args():
    parser = optional_args()

    # take the arguments of the program
    results = parser.parse_args()

    # see the choice of display format
    # if True then bits/sec;    if False then Bytes/sec
    # default Bytes/sec
    b_B_SWITCH = results.b_B_SWITCH

    # take interfaces given as parameters
    if results.INTERFACES is None:
        INTERFACES = netifaces.interfaces()
    else:
        INTERFACES = results.INTERFACES.split(",")

    # take throughput interval measurement given as parameter also
    INTERVAL_throughput = float(results.INTERVAL_throughput)

    # take the interval between packets transmission (for jitter measurement)
    INTERVAL_JITTER = float(results.INTERVAL_JITTER)

    rules_json = None
    with open(CONFIG_FILE_NAME) as json_file:
        rules_json = json.load(json_file)

    return b_B_SWITCH, INTERFACES, INTERVAL_throughput, rules_json, INTERVAL_JITTER


# -----------------------------------------------------------------------------


# function for printing throughput/goodput in bits/sec or Bytes/sec format
def print_throughput_goodput(protocol, throughput):
    if b_B_SWITCH:
        # bits/sec
        throughput = throughput * 8  # transform in bits
        if throughput >= (1024 ** 4):
            print(protocol + " bitrate [Tbits/sec]:  %.4f" % (throughput / (1024 ** 4)))
        elif throughput >= (1024 ** 3):
            print(protocol + " bitrate [Gbits/sec]:  %.4f" % (throughput / (1024 ** 3)))
        elif throughput >= (1024 ** 2):
            print(protocol + " bitrate [Mbits/sec]:  %.4f" % (throughput / (1024 ** 2)))
        elif throughput >= 1024:
            print(protocol + " bitrate [Kbits/sec]:  %.4f" % (throughput / 1024))
        else:
            print(protocol + " bitrate [bits/sec]:  %.4f" % throughput)
    else:
        # Bytes/sec
        if throughput >= (1024 ** 4):
            print(protocol + " bitrate [TBytes/sec]:  %.4f" % (throughput / (1024 ** 4)))
        elif throughput >= (1024 ** 3):
            print(protocol + " bitrate [GBytes/sec]:  %.4f" % (throughput / (1024 ** 3)))
        elif throughput >= (1024 ** 2):
            print(protocol + " bitrate [MBytes/sec]:  %.4f" % (throughput / (1024 ** 2)))
        elif throughput >= 1024:
            print(protocol + " bitrate [KBytes/sec]:  %.4f" % (throughput / 1024))
        else:
            print(protocol + " bitrate [Bytes/sec]:  %.4f" % throughput)


# -----------------------------------------------------------------------------


# filter rule to leave only the INCOMING packets from all the interfaces
def f_filter_incoming(bpf_text):
    FILTER_incoming = "if ("

    for interface in INTERFACES:
        if "daddr" in FILTER_incoming:
            FILTER_incoming += " && "

        FILTER_incoming += "(daddr != %s)" % \
                           str(int(IPv4Address(get_ip(interface))))

    FILTER_incoming += ") {return 0;}"

    return bpf_text.replace('FILTER_incoming', FILTER_incoming)


# -----------------------------------------------------------------------------


# function for filtering by IPs, ports and protocol
def f_filter(bpf_text, rules_json):
    text = "if (!("

    for rule in rules_json["RULES"]:
        rule = rule.split()

        if len(text) > len("if (!("):
            text += " || "

        rule_data = []
        for i in range(5):
            rule_data.append([])

        for index in [INDEX_IP_SRC, INDEX_IP_DST, INDEX_PORT_SRC,
                      INDEX_PORT_DST, INDEX_PROTOCOL]:
            if "[" in rule[index]:
                rule_data[index] = str_to_list(rule[index])
            elif "-" != rule[index]:
                rule_data[index].append(rule[index])

        ips_src = rule_data[INDEX_IP_SRC]
        ips_dst = rule_data[INDEX_IP_DST]
        ports_src = rule_data[INDEX_PORT_SRC]
        ports_dst = rule_data[INDEX_PORT_DST]
        protocols = rule_data[INDEX_PROTOCOL]

        txt_rule = "("

        ip_src_txt = "("
        for ip in ips_src:
            if ip_src_txt != "(":
                ip_src_txt += " || "
            ip_src_txt += "saddr == %s" % str(int(IPv4Address(ip)))
        ip_src_txt += ")"

        ip_dst_txt = "("
        for ip in ips_dst:
            if ip_dst_txt != "(":
                ip_dst_txt += " || "
            ip_dst_txt += "daddr == %s" % str(int(IPv4Address(ip)))
        ip_dst_txt += ")"

        port_src_txt = "("
        for port in ports_src:
            if port_src_txt != "(":
                port_src_txt += " || "
            port_src_txt += "sport == %s" % str(port)
        port_src_txt += ")"

        port_dst_txt = "("
        for port in ports_dst:
            if port_dst_txt != "(":
                port_dst_txt += " || "
            port_dst_txt += "dport == %s" % str(port)
        port_dst_txt += ")"

        protocol_txt = "("
        for protocol in protocols:
            if protocol_txt != "(":
                protocol_txt += " || "

            protocol_txt += "protocol == IPPROTO_%s" % str(protocol)
        protocol_txt += ")"

        if ip_src_txt != "()":
            txt_rule += ip_src_txt
        
        if ip_dst_txt != "()":
            if len(ips_src) != 0:
                txt_rule += " && "
            txt_rule += ip_dst_txt

        if port_src_txt != "()":
            if (len(ips_src) + len(ips_dst)) != 0:
                txt_rule += " && "
            txt_rule += port_src_txt

        if port_dst_txt != "()":
            if (len(ips_src) + len(ips_dst) + len(ports_src)) != 0:
                txt_rule += " && "
            txt_rule += port_dst_txt

        if protocol_txt != "()":
            if (len(ips_src) + len(ips_dst) + len(ports_src) + len(ports_dst)) != 0:
                txt_rule += " && "
            txt_rule += protocol_txt

        txt_rule += ")"

        text += txt_rule

    text += ")) {return 0;}"

    if (len(ips_src) + len(ips_dst) + len(ports_src) +
            len(ports_dst) + len(protocols)) == 0:
        text = ""

    return bpf_text.replace("FILTER_RULES", text)


# -----------------------------------------------------------------------------


def compute_throughput_goodput(proto, count, initial_time, size_per_interval,
                               total_size, prev_total_size, prev_throughput):
    index = 0

    if proto == "ICMP":
        index = socket.IPPROTO_ICMP
    elif proto == "TCP":
        index = socket.IPPROTO_TCP
    elif proto == "UDP":
        index = socket.IPPROTO_UDP

    if count[index] != 0 and initial_time[index] == 0:
        initial_time[index] = time.time()
    else:
        if count[index] != 0 and initial_time[index] != 0:

            if time.time() - initial_time[index] >= INTERVAL_throughput:
                size_per_interval[index] = total_size[index] - \
                                           prev_total_size[index]
                prev_total_size[index] = total_size[index]

                throughput = size_per_interval[index] / (time.time() - initial_time[index])
                prev_throughput[index] = throughput

                print_throughput_goodput(proto, throughput)

                initial_time[index] = time.time()
            else:
                print_throughput_goodput(proto, prev_throughput[index])


# -----------------------------------------------------------------------------


def compute_jitter(proto, jitter_values):
    index = 0

    if proto == "ICMP":
        index = socket.IPPROTO_ICMP
    elif proto == "TCP":
        index = socket.IPPROTO_TCP
    elif proto == "UDP":
        index = socket.IPPROTO_UDP

    avg_ns = 0
    for k, v in jitter_values[index].items():
        avg_ns += v.value

    avg_ns /= len(jitter_values[index].items())

    stddev = 0
    for k, v in jitter_values[index].items():
        stddev += (v.value - avg_ns)**2

    stddev = math.sqrt(stddev / (len(jitter_values[index].items()) - 1))
    stddev /= 1000000

    print("Jitter " + proto + ": %.4f ms" % stddev)


# -----------------------------------------------------------------------------


(b_B_SWITCH, INTERFACES, INTERVAL_throughput, rules_json, INTERVAL_JITTER) = take_args()

# apply filters
INTERVAL_JITTER_ns = INTERVAL_JITTER * 1000000
bpf_text = bpf_text.replace('INTERVAL_JITTER', str(int(INTERVAL_JITTER_ns)))

bpf_text = f_filter_incoming(bpf_text)

bpf_text = f_filter(bpf_text, rules_json)


# load bpf code
bpf = BPF(text=bpf_text)
ffilter = bpf.load_func("count_packets", BPF.SOCKET_FILTER)

for interface in INTERFACES:
    BPF.attach_raw_socket(ffilter, interface)

# dictionary for initial time for TCP, UDP, ICMP
initial_time = {socket.IPPROTO_TCP: 0,
                socket.IPPROTO_UDP: 0,
                socket.IPPROTO_ICMP: 0}

# dictionary for initial time for TCP, UDP, ICMP -> GOODPUT
initial_time_goodput = {socket.IPPROTO_TCP: 0,
                        socket.IPPROTO_UDP: 0,
                        socket.IPPROTO_ICMP: 0}

# dictionary for time spent since the first received packet for TCP, UDP, ICMP
current_time_spent = {socket.IPPROTO_TCP: 0,
                      socket.IPPROTO_UDP: 0,
                      socket.IPPROTO_ICMP: 0}

# dictionary for total size on last throughput measurement
prev_total_size = {socket.IPPROTO_TCP: 0,
                   socket.IPPROTO_UDP: 0,
                   socket.IPPROTO_ICMP: 0}

# dictionary for total size on last goodput measurement
prev_total_size_goodput = {socket.IPPROTO_TCP: 0,
                           socket.IPPROTO_UDP: 0,
                           socket.IPPROTO_ICMP: 0}

# dictionary for throughput on last measurement
prev_throughput = {socket.IPPROTO_TCP: 0,
                   socket.IPPROTO_UDP: 0,
                   socket.IPPROTO_ICMP: 0}
                
# dictionary for goodput on last measurement
prev_goodput = {socket.IPPROTO_TCP: 0,
                socket.IPPROTO_UDP: 0,
                socket.IPPROTO_ICMP: 0}

# dictionary for jitter
jitter_values = {socket.IPPROTO_TCP: None,
                 socket.IPPROTO_UDP: None,
                 socket.IPPROTO_ICMP: None}


# -----------------------------------------------------------------------------


try:
    while True:
        count = {socket.IPPROTO_TCP: bpf["packet_count"][socket.IPPROTO_TCP].value,
                 socket.IPPROTO_UDP: bpf["packet_count"][socket.IPPROTO_UDP].value,
                 socket.IPPROTO_ICMP: bpf["packet_count"][socket.IPPROTO_ICMP].value}

        total_size = {socket.IPPROTO_TCP: bpf["packet_size"][socket.IPPROTO_TCP].value,
                      socket.IPPROTO_UDP: bpf["packet_size"][socket.IPPROTO_UDP].value,
                      socket.IPPROTO_ICMP: bpf["packet_size"][socket.IPPROTO_ICMP].value}

        total_size_goodput = {socket.IPPROTO_TCP: bpf["packet_size_goodput"][socket.IPPROTO_TCP].value,
                              socket.IPPROTO_UDP: bpf["packet_size_goodput"][socket.IPPROTO_UDP].value,
                              socket.IPPROTO_ICMP: bpf["packet_size_goodput"][socket.IPPROTO_ICMP].value}

        size_per_interval = {socket.IPPROTO_TCP: 0,
                             socket.IPPROTO_UDP: 0,
                             socket.IPPROTO_ICMP: 0}

        size_per_interval_goodput = {socket.IPPROTO_TCP: 0,
                                     socket.IPPROTO_UDP: 0,
                                     socket.IPPROTO_ICMP: 0}

        # clear the console
        os.system('clear')

        # jitter measurement
        jitter_values[socket.IPPROTO_TCP] = bpf.get_table('jitter_values_tcp')
        jitter_values[socket.IPPROTO_UDP] = bpf.get_table('jitter_values_udp')
        jitter_values[socket.IPPROTO_ICMP] = bpf.get_table('jitter_values_icmp')

        compute_jitter("TCP", jitter_values)
        compute_jitter("UDP", jitter_values)
        compute_jitter("ICMP", jitter_values)
        print()

        # Throughput measurement
        print("THROUGHPUT measurement on " + ", ".join(INTERFACES) +
              " each " + str(INTERVAL_throughput) + " seconds:")

        compute_throughput_goodput("TCP", count, initial_time, size_per_interval,
                                   total_size, prev_total_size, prev_throughput)
        compute_throughput_goodput("UDP", count, initial_time, size_per_interval,
                                   total_size, prev_total_size, prev_throughput)
        compute_throughput_goodput("ICMP", count, initial_time, size_per_interval,
                                   total_size, prev_total_size, prev_throughput)
        print()

        # Goodput measurement
        print("GOODPUT measurement on " + ", ".join(INTERFACES) +
              " each " + str(INTERVAL_throughput) + " seconds:")

        compute_throughput_goodput("TCP", count, initial_time_goodput, 
                                   size_per_interval_goodput, total_size_goodput, 
                                   prev_total_size_goodput, prev_goodput)
        compute_throughput_goodput("UDP", count, initial_time_goodput, 
                                   size_per_interval_goodput, total_size_goodput, 
                                   prev_total_size_goodput, prev_goodput)
        compute_throughput_goodput("ICMP", count, initial_time_goodput, 
                                   size_per_interval_goodput, total_size_goodput, 
                                   prev_total_size_goodput, prev_goodput)

        time.sleep(INTERVAL_throughput)

except KeyboardInterrupt:
    pass
