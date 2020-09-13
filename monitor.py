from bcc import BPF
import time
import socket
import os
from ipaddress import IPv4Address
import netifaces
import argparse
import json
import math
import ctypes
import prometheus_client as prom
import socket


INDEX_IP_SRC = 0
INDEX_IP_DST = 1

INDEX_PORT_SRC = 2
INDEX_PORT_DST = 3

INDEX_PROTOCOL = 4

JITTER_ARRAY_SIZE = 2048

# if we have >2 seconds jitter then the flow probably stopped
JITTER_FLOW_STOPPED = 2

CONFIG_FILE_NAME = "config.json"

gauges_dict = {
    "TCP": {
        "throughput": prom.Gauge('tcp_throughput', 'Throughput TCP (ms)'),
        "goodput": prom.Gauge('tcp_goodput', 'Goodput TCP (ms)'),
        "jitter": {
            "avg": prom.Gauge('tcp_jitter_avg', 'Average inter-arrival TCP (ms)'),
            "stddev": prom.Gauge('tcp_jitter_stddev', 'Jitter/STDDEV TCP (ms)')
        },
        "pkt_drop": {
            "seq_num": prom.Gauge('tcp_seq_num', 'Last sequence number TCP'),
            "count": prom.Gauge('tcp_count', 'Number of TCP packets'),
            "reverse_err": prom.Gauge('tcp_reverse_err', 'Number of reverse errors TCP'),
            "small_err": prom.Gauge('tcp_small_err', 'Number of small errors TCP'),
            "big_err": prom.Gauge('tcp_big_err', 'Number of big errors TCP'),
            "total_err": prom.Gauge('tcp_total_err', 'Number of total errors TCP')
        }
    },
    "UDP": {
        "throughput": prom.Gauge('udp_throughput', 'Throughput UDP (ms)'),
        "goodput": prom.Gauge('udp_goodput', 'Goodput UDP (ms)'),
        "jitter": {
            "avg": prom.Gauge('udp_jitter_avg', 'Average inter-arrival UDP (ms)'),
            "stddev": prom.Gauge('udp_jitter_stddev', 'Jitter/STDDEV UDP (ms)')
        },
        "pkt_drop": {
            "seq_num": prom.Gauge('udp_seq_num', 'Last sequence number UDP'),
            "count": prom.Gauge('udp_count', 'Number of UDP packets'),
            "reverse_err": prom.Gauge('udp_reverse_err', 'Number of reverse errors UDP'),
            "small_err": prom.Gauge('udp_small_err', 'Number of small errors UDP'),
            "big_err": prom.Gauge('udp_big_err', 'Number of big errors UDP'),
            "total_err": prom.Gauge('udp_total_err', 'Number of total errors UDP')
        }
    },
    "ICMP": {
        "throughput": prom.Gauge('icmp_throughput', 'Throughput ICMP (ms)'),
        "goodput": prom.Gauge('icmp_goodput', 'Goodput ICMP (ms)'),
        "jitter": {
            "avg": prom.Gauge('icmp_jitter_avg', 'Average inter-arrival ICMP (ms)'),
            "stddev": prom.Gauge('icmp_jitter_stddev', 'Jitter/STDDEV ICMP (ms)')
        },
        "pkt_drop": {
            "seq_num": prom.Gauge('icmp_seq_num', 'Last sequence number ICMP'),
            "count": prom.Gauge('icmp_count', 'Number of ICMP packets'),
            "reverse_err": prom.Gauge('icmp_reverse_err', 'Number of reverse errors ICMP'),
            "small_err": prom.Gauge('icmp_small_err', 'Number of small errors ICMP'),
            "big_err": prom.Gauge('icmp_big_err', 'Number of big errors ICMP'),
            "total_err": prom.Gauge('icmp_total_err', 'Number of total errors ICMP')
        }
    }
}



# define BPF program
bpf_text = """
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ptrace.h>


#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define JITTER_ARRAY_SIZE 2048

#define PATTERN FILTER_PATTERN
#define OFFSET FILTER_OFFSET
#define SEQ_THRESHOLD FILTER_THRESHOLD


// structure for packet loss related statistics
struct seq_memory {
    u32 seq_num;
    u32 count;
    u32 reverse_err;
    u32 small_err;
    u32 big_err;
};

BPF_ARRAY(packet_count, u64, 256);
BPF_ARRAY(bytes_sent, u64, 256);
BPF_ARRAY(bytes_sent_no_headers, u64, 256);

BPF_HASH(prev_time_jitter_hash, int, u64, 256);
BPF_HASH(jitter_index_hash, int, int, 256);

BPF_ARRAY(jitter_values_tcp, u64, JITTER_ARRAY_SIZE);
BPF_ARRAY(jitter_values_udp, u64, JITTER_ARRAY_SIZE);
BPF_ARRAY(jitter_values_icmp, u64, JITTER_ARRAY_SIZE);

// map with packet loss related statistics for each protocol
BPF_HASH(seq_hash, int, struct seq_memory, 4);


int count_packets(struct __sk_buff *skb) {
    int zero = 0;
    int one = 1;

    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    struct tcp_t *tcp;
    struct udp_t *udp;
    struct icmp_t *icmp;

    int protocol = ip->nextp;

    // size of ip packet
    u64 size_goodput = ip->tlen;

    // size of the entire packet including ethernet header
    u64 size = skb->len;

    // ip->hlen is the number of 32-bit words in ip header
    // << 2 to get the length in bytes
    u32 ip_header_length = ip->hlen << 2;

    // packet without ip header
    size_goodput -= ip_header_length;


    u32 daddr, saddr;
    saddr = ip->src;
    daddr = ip->dst;

    u16 sport, dport;
    if (protocol == IPPROTO_UDP) {
        udp = cursor_advance(cursor, sizeof(*udp));
        sport = udp->sport;
        dport = udp->dport;
        size_goodput -= 8;

    } else if (protocol == IPPROTO_TCP) {
        tcp = cursor_advance(cursor, sizeof(*tcp));
        sport = tcp->src_port;
        dport = tcp->dst_port;

        // tcp->offset represents the number of 32-bit words in tcp header
        // << 2 to get the length in bytes
        size_goodput -= (tcp->offset << 2);

    } else if (protocol == IPPROTO_ICMP) {
        icmp = cursor_advance(cursor, sizeof(*icmp));
        size_goodput -= 8;
    }


    FILTER_OUTCOMING

    FILTER_RULES


    // Throughput measurement
    u64 *packet_counter = packet_count.lookup(&protocol);

    u64 *old_size = bytes_sent.lookup(&protocol);
    u64 *old_size_goodput = bytes_sent_no_headers.lookup(&protocol);

    u64 new_size = size;
    u64 new_size_goodput = size_goodput;

    if (old_size)
        new_size += *old_size;

    if (old_size_goodput)
        new_size_goodput += *old_size_goodput;

    if (packet_counter) {
        packet_count.increment(protocol);
        bytes_sent.update(&protocol, &new_size);
        bytes_sent_no_headers.update(&protocol, &new_size_goodput);
    }


    // Jitter measurement
    u64 current_time_jitter = bpf_ktime_get_ns();

    u64 *prev_time_jitter = prev_time_jitter_hash.lookup(&protocol);
    if ((prev_time_jitter != NULL)) {
        prev_time_jitter_hash.delete(&protocol);
    } else {
        prev_time_jitter_hash.update(&protocol, &current_time_jitter);
    }


    int *jitter_index = jitter_index_hash.lookup(&protocol);
    if (!jitter_index) {
        jitter_index_hash.update(&protocol, &zero);
    }


    if (prev_time_jitter) {
        u64 interval_jitter = INTERVAL_JITTER;
        u64 tmp_jitter = current_time_jitter - *prev_time_jitter - INTERVAL_JITTER;

        prev_time_jitter_hash.update(&protocol, &current_time_jitter);

        jitter_index = jitter_index_hash.lookup(&protocol);
        if (jitter_index) {
            if (*jitter_index >= JITTER_ARRAY_SIZE) {
                jitter_index_hash.update(&protocol, &zero);
            }

            if (protocol == PROTO_TCP) {
                jitter_values_tcp.update(jitter_index, &tmp_jitter);
            } else if (protocol == PROTO_UDP) {
                jitter_values_udp.update(jitter_index, &tmp_jitter);
            } else if (protocol == PROTO_ICMP) {
                jitter_values_icmp.update(jitter_index, &tmp_jitter);
            }

            jitter_index_hash.increment(protocol);
        }
    }


    // Packet loss
    if (PATTERN == -1 && OFFSET == -1)
        return 0;

    struct seq_memory *p_seq_hash = seq_hash.lookup(&protocol);
    if (!p_seq_hash) {
        struct seq_memory seq_struct = {0, 0, 0, 0, 0};
        seq_hash.update(&protocol, &seq_struct);
    }

    p_seq_hash = seq_hash.lookup(&protocol);

    if (p_seq_hash){
        int diff;
        u32 seq_num = 0;

        u32 pattern = PATTERN;
        u32 offset = OFFSET;

        p_seq_hash->count++;

        if (protocol == PROTO_TCP) {
            seq_num = tcp->seq_num;

        } else if (protocol == PROTO_UDP || protocol == PROTO_ICMP) {
            u32 payload_offset = ETH_HLEN + ip_header_length + 8;

            if (pattern != -1) {
                u32 test_pattern;

                // search for given pattern in first 5000 bytes of data
                for (int i = 0; i < 5000; i++) {
                    test_pattern = load_word(skb, payload_offset + i);

                    // if pattern found then take the sequence number from given offset
                    if (test_pattern == pattern) {
                        seq_num = load_word(skb, payload_offset + i + offset);
                        break;
                    }
                }
            } else {
                seq_num = load_word(skb, payload_offset + offset);
            }
        }

        diff = seq_num - p_seq_hash->seq_num;

        if (p_seq_hash->count > 1 && diff != 1) {
            if (diff < 0) {
                p_seq_hash->reverse_err++;
            } else if (diff > SEQ_THRESHOLD) {
                p_seq_hash->big_err++;
            } else {
                p_seq_hash->small_err++;
            }
        }

        p_seq_hash->seq_num = seq_num;

        seq_hash.delete(&protocol);
        seq_hash.update(&protocol, p_seq_hash);
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
        return "NO_IP"
        # print("Error: The interface must have an assigned IP address")
        # exit(0)
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
    parser.add_argument('-b', action='store_true', default=False, dest='MEASURE_IN_BITS_PER_SEC',
                        help='display the throughput in bits/second format')
    parser.add_argument('-j', dest='INTERVAL_JITTER', default=0, help='specify \
                        the transmission interval in miliseconds between packets')
    parser.add_argument('-test_throughput', action='store_true', default=False, help='activate \
                        it for throughput acceptance test (used in test script)')
    parser.add_argument('-test_jitter', action='store_true', default=False, help='activate \
                        it for jitter acceptance test (used in test script)')
    parser.add_argument('-packet_loss', action='store_true', default=False, help='activate \
                        it for packet loss acceptance test (used in test script)')
    parser.add_argument('-server_port', dest='SERVER_PORT', default=8080, help='port \
                        of the server in which monitor data is published')
    parser.add_argument('-conf', dest='JSON_PATH', default="config.json", help='path to config.json file')

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
    MEASURE_IN_BITS_PER_SEC = results.MEASURE_IN_BITS_PER_SEC

    # take interfaces given as parameters
    if results.INTERFACES is None:
        INTERFACES = netifaces.interfaces()
    else:
        INTERFACES = results.INTERFACES.split(",")

    # take throughput interval measurement given as parameter also
    INTERVAL_throughput = float(results.INTERVAL_throughput)

    # take the interval between packets transmission (for jitter measurement)
    INTERVAL_JITTER = float(results.INTERVAL_JITTER)

    # take the filters from json
    CONFIG_FILE_NAME = results.JSON_PATH

    rules_json = None
    with open(CONFIG_FILE_NAME) as json_file:
        rules_json = json.load(json_file)

    # throughput test enable
    TEST_THROUGHPUT = results.test_throughput

    # jitter test enable
    TEST_JITTER = results.test_jitter

    # packet loss statistics enable
    PACKET_LOSS = results.packet_loss

    # server port
    SERVER_PORT = int(results.SERVER_PORT)


    return MEASURE_IN_BITS_PER_SEC, INTERFACES, INTERVAL_throughput, \
        rules_json, INTERVAL_JITTER, TEST_THROUGHPUT, TEST_JITTER, PACKET_LOSS, SERVER_PORT


# -----------------------------------------------------------------------------


def aux_print_rate(protocol, throughput, measure_unit):
    if throughput >= (1024 ** 4):
        print(protocol + " bitrate [T" + measure_unit + "/sec]:  %.4f"
              % (throughput / (1024 ** 4)), flush=True)
    elif throughput >= (1024 ** 3):
        print(protocol + " bitrate [G" + measure_unit + "/sec]:  %.4f"
              % (throughput / (1024 ** 3)), flush=True)
    elif throughput >= (1024 ** 2):
        print(protocol + " bitrate [M" + measure_unit + "/sec]:  %.4f"
              % (throughput / (1024 ** 2)), flush=True)
    elif throughput >= 1024:
        print(protocol + " bitrate [K" + measure_unit + "/sec]:  %.4f"
              % (throughput / 1024), flush=True)
    else:
        print(protocol + " bitrate [" + measure_unit + "/sec]:  %.4f"
              % throughput, flush=True)


# -----------------------------------------------------------------------------


# function for printing throughput/goodput in bits/sec or Bytes/sec format
def print_rate(protocol, throughput):
    if MEASURE_IN_BITS_PER_SEC:
        # bits/sec
        throughput = throughput * 8  # transform in bits
        aux_print_rate(protocol, throughput, 'bits')
    else:
        # Bytes/sec
        aux_print_rate(protocol, throughput, 'Bytes')


# -----------------------------------------------------------------------------


# filter rule to leave only the INCOMING packets from all the interfaces
def f_filter_outcoming(bpf_text):
    FILTER_outcoming = ""
    ips = 0

    for interface in INTERFACES:
        ip = get_ip(interface)
        if str(ip) == "NO_IP":
            continue

        ips += 1

        if "saddr" in FILTER_outcoming:
            FILTER_outcoming += " && "

        FILTER_outcoming = FILTER_outcoming + "(saddr == {})".format(int(IPv4Address(ip)))

    if ips == 0:
        FILTER_outcoming = ""
    elif ips == 1:
        FILTER_outcoming = "if " + FILTER_outcoming
        FILTER_outcoming += " {return 0;}"
    else:
        FILTER_outcoming = "if (" + FILTER_outcoming
        FILTER_outcoming += ") {return 0;}"

    return bpf_text.replace('FILTER_OUTCOMING', FILTER_outcoming)


# -----------------------------------------------------------------------------


# function for filtering by IPs, ports and protocol
def f_filter(bpf_text, rules_json):
    ips_src = []
    ips_dst = []
    ports_src = []
    ports_dst = []
    protocols = []

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


def filter_packet_loss(bpf_text, PACKET_LOSS):
    # if PACKET_LOSS:
    # pattern is given in hex
    PATTERN = rules_json["PATTERN"]
    PATTERN = int(PATTERN, 16)
    OFFSET = rules_json["OFFSET"]
    SEQ_THRESHOLD = rules_json["SEQUENCE_THRESHOLD"]

    bpf_text = bpf_text.replace('FILTER_PATTERN', str(PATTERN))

    bpf_text = bpf_text.replace('FILTER_OFFSET', str(OFFSET))

    bpf_text = bpf_text.replace('FILTER_THRESHOLD', str(SEQ_THRESHOLD))

    return bpf_text


# -----------------------------------------------------------------------------


def compute_throughput_goodput(proto, count, initial_time, size_per_interval,
                               total_size, prev_total_size, prev_throughput):
    index = 0
    throughput = 0

    if proto == "ICMP":
        index = socket.IPPROTO_ICMP
    elif proto == "TCP":
        index = socket.IPPROTO_TCP
    elif proto == "UDP":
        index = socket.IPPROTO_UDP

    if count[index] != 0 and initial_time[index] == 0:
        initial_time[index] = time.time()
        print_rate(proto, 0.0000)
    else:
        current_time = time.time()

        if count[index] != 0 and initial_time[index] != 0:
            if current_time - initial_time[index] >= INTERVAL_throughput:
                size_per_interval[index] = total_size[index] - \
                                           prev_total_size[index]
                prev_total_size[index] = total_size[index]

                throughput = size_per_interval[index] / \
                    (current_time - initial_time[index])
                prev_throughput[index] = throughput

                print_rate(proto, throughput)

                initial_time[index] = current_time
            else:
                print_rate(proto, prev_throughput[index])
        else:
            print_rate(proto, 0.0000)

    # return throughput in Bytes
    return throughput

# -----------------------------------------------------------------------------


def compute_jitter(proto, jitter_values, jitter_index, bpf):
    proto_value = 0

    if proto == "ICMP":
        proto_value = socket.IPPROTO_ICMP
    elif proto == "TCP":
        proto_value = socket.IPPROTO_TCP
    elif proto == "UDP":
        proto_value = socket.IPPROTO_UDP

    j_index = None
    for k, v in jitter_index.items():
        if k.value == proto_value:
            j_index = v.value
            break

    # get data first and erase everithing from BPF structures
    data = jitter_values[proto_value].values()

    for i in range(JITTER_ARRAY_SIZE):
        bpf['jitter_values_{}'.format(proto.lower())][ctypes.c_int(i)] = ctypes.c_uint64(0)

    bpf['jitter_index_hash'][ctypes.c_int(proto_value)] = ctypes.c_int(0)

    # sort data from oldest to newest
    data = list(map(lambda t: t.value, data))

    if sum(data[j_index:]) == 0:
        data = data[:j_index]
    else:
        data = data[j_index:] + data[:j_index]

    data = list(filter(lambda a: a != 0, data))

    # find the last biggest jitter value and take only the values after it
    jitter_threshold_ns = JITTER_FLOW_STOPPED * 10**9

    def find_indices(lst, condition):
        return [i for i, elem in enumerate(lst) if condition(elem)]

    big_jitter_values_indices = find_indices(data, lambda e: e >= jitter_threshold_ns)
    if len(big_jitter_values_indices) > 0:
        data = data[big_jitter_values_indices[-1] + 1:]

    # compute standard deviation
    avg_ns = 0
    stddev = 0

    if len(data) > 1:
        avg_ns = sum(data) / len(data)

        for v in data:
            stddev += (v - avg_ns)**2

        stddev = math.sqrt(stddev / (len(data) - 1))

        stddev /= 10**6
        avg_ns /= 10**6

    print("Jitter[STDDEV] " + proto + ": %.4f ms" % stddev, flush=True)
    print("Average " + proto + ": %.4f ms" % avg_ns, flush=True)
    print("", flush=True)

    return avg_ns, stddev

def convert_display_dict(DISPLAY):
    for key in DISPLAY.keys():
        DISPLAY[key] = DISPLAY[key] == "True"
    return DISPLAY

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

# -----------------------------------------------------------------------------


(MEASURE_IN_BITS_PER_SEC, INTERFACES, INTERVAL_throughput, rules_json,
    INTERVAL_JITTER, TEST_THROUGHPUT, TEST_JITTER, PACKET_LOSS, SERVER_PORT) = take_args()

MONITOR_SERVER = rules_json["MONITOR_SERVER"] == "True"
DISPLAY = rules_json["DISPLAY"]
DISPLAY = convert_display_dict(DISPLAY)

if MONITOR_SERVER:
    if is_port_in_use(SERVER_PORT):
        print("Port {} already in use...".format(SERVER_PORT))
        print("Please choose another port")
        exit(-1)   
    else:
        prom.start_http_server(SERVER_PORT)

# apply filters
INTERVAL_JITTER_ns = INTERVAL_JITTER * 10**6
bpf_text = bpf_text.replace('INTERVAL_JITTER', str(int(INTERVAL_JITTER_ns)))

bpf_text = f_filter_outcoming(bpf_text)

bpf_text = f_filter(bpf_text, rules_json)

bpf_text = filter_packet_loss(bpf_text, PACKET_LOSS)


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

prev_time = time.time()
try:
    while True:
        if (time.time() - prev_time) < INTERVAL_throughput:
            continue

        prev_time = time.time()

        count = {socket.IPPROTO_TCP: bpf["packet_count"][socket.IPPROTO_TCP].value,
                 socket.IPPROTO_UDP: bpf["packet_count"][socket.IPPROTO_UDP].value,
                 socket.IPPROTO_ICMP: bpf["packet_count"][socket.IPPROTO_ICMP].value}

        total_size = {socket.IPPROTO_TCP: bpf["bytes_sent"][socket.IPPROTO_TCP].value,
                      socket.IPPROTO_UDP: bpf["bytes_sent"][socket.IPPROTO_UDP].value,
                      socket.IPPROTO_ICMP: bpf["bytes_sent"][socket.IPPROTO_ICMP].value}

        total_size_goodput = {socket.IPPROTO_TCP: bpf["bytes_sent_no_headers"][socket.IPPROTO_TCP].value,
                              socket.IPPROTO_UDP: bpf["bytes_sent_no_headers"][socket.IPPROTO_UDP].value,
                              socket.IPPROTO_ICMP: bpf["bytes_sent_no_headers"][socket.IPPROTO_ICMP].value}

        size_per_interval = {socket.IPPROTO_TCP: 0,
                             socket.IPPROTO_UDP: 0,
                             socket.IPPROTO_ICMP: 0}

        size_per_interval_goodput = {socket.IPPROTO_TCP: 0,
                                     socket.IPPROTO_UDP: 0,
                                     socket.IPPROTO_ICMP: 0}

        # clear the console
        if TEST_THROUGHPUT is False and TEST_JITTER is False:
            os.system('clear')

        if DISPLAY["Jitter"]:
            # jitter measurement
            jitter_values[socket.IPPROTO_TCP] = bpf.get_table('jitter_values_tcp')
            jitter_values[socket.IPPROTO_UDP] = bpf.get_table('jitter_values_udp')
            jitter_values[socket.IPPROTO_ICMP] = bpf.get_table('jitter_values_icmp')

            jitter_index = bpf.get_table('jitter_index_hash')

            if TEST_THROUGHPUT is False and PACKET_LOSS is False:
                avg_tcp, stddev_tcp = compute_jitter("TCP", jitter_values, jitter_index, bpf)
                avg_udp, stddev_udp = compute_jitter("UDP", jitter_values, jitter_index, bpf)
                avg_icmp, stddev_icmp = compute_jitter("ICMP", jitter_values, jitter_index, bpf)

                if MONITOR_SERVER:
                    gauges_dict['TCP']['jitter']['avg'].set(avg_tcp)
                    gauges_dict['TCP']['jitter']['stddev'].set(stddev_tcp)
                    gauges_dict['UDP']['jitter']['avg'].set(avg_udp)
                    gauges_dict['UDP']['jitter']['stddev'].set(stddev_udp)
                    gauges_dict['ICMP']['jitter']['avg'].set(avg_icmp)
                    gauges_dict['ICMP']['jitter']['stddev'].set(stddev_icmp)

                print()


        # Throughput measurement
        if DISPLAY["Throughput"]:
            if TEST_JITTER is False:
                print("THROUGHPUT measurement on " + ", ".join(INTERFACES) +
                    " each " + str(INTERVAL_throughput) + " seconds:")

                throughput_tcp = compute_throughput_goodput("TCP", count, initial_time, size_per_interval,
                                        total_size, prev_total_size, prev_throughput)
                throughput_udp = compute_throughput_goodput("UDP", count, initial_time, size_per_interval,
                                        total_size, prev_total_size, prev_throughput)
                throughput_icmp = compute_throughput_goodput("ICMP", count, initial_time, size_per_interval,
                                        total_size, prev_total_size, prev_throughput)

                if MONITOR_SERVER:
                    gauges_dict['TCP']['throughput'].set(throughput_tcp)
                    gauges_dict['UDP']['throughput'].set(throughput_udp)
                    gauges_dict['ICMP']['throughput'].set(throughput_icmp)

                print()


        # Goodput measurement
        if DISPLAY["Goodput"]:
            if TEST_THROUGHPUT is False and TEST_JITTER is False and PACKET_LOSS is False:
                print("GOODPUT measurement on " + ", ".join(INTERFACES) +
                    " each " + str(INTERVAL_throughput) + " seconds:")

                goodput_tcp = compute_throughput_goodput("TCP", count, initial_time_goodput,
                                        size_per_interval_goodput, total_size_goodput,
                                        prev_total_size_goodput, prev_goodput)
                goodput_udp = compute_throughput_goodput("UDP", count, initial_time_goodput,
                                        size_per_interval_goodput, total_size_goodput,
                                        prev_total_size_goodput, prev_goodput)
                goodput_icmp = compute_throughput_goodput("ICMP", count, initial_time_goodput,
                                        size_per_interval_goodput, total_size_goodput,
                                        prev_total_size_goodput, prev_goodput)

                if MONITOR_SERVER:
                    gauges_dict['TCP']['goodput'].set(goodput_tcp)
                    gauges_dict['UDP']['goodput'].set(goodput_udp)
                    gauges_dict['ICMP']['goodput'].set(goodput_icmp)


        # Packet loss
        if DISPLAY["SEQ_ERRORS"]:
            if TEST_THROUGHPUT is False and TEST_JITTER is False:
                seq_hash = bpf.get_table('seq_hash')

                for proto, seq_mem in seq_hash.items():
                    proto = proto.value

                    total_sequence_errors = seq_mem.reverse_err + seq_mem.small_err + \
                        seq_mem.big_err

                    if proto == socket.IPPROTO_TCP:
                        print("TCP")
                        if MONITOR_SERVER:
                            gauges_dict['TCP']['pkt_drop']['seq_num'].set(seq_mem.seq_num)
                            gauges_dict['TCP']['pkt_drop']['count'].set(seq_mem.count)
                            gauges_dict['TCP']['pkt_drop']['reverse_err'].set(seq_mem.reverse_err)
                            gauges_dict['TCP']['pkt_drop']['small_err'].set(seq_mem.small_err)
                            gauges_dict['TCP']['pkt_drop']['big_err'].set(seq_mem.big_err)
                            gauges_dict['TCP']['pkt_drop']['total_err'].set(total_sequence_errors)

                    elif proto == socket.IPPROTO_UDP:
                        print("UDP")
                        if MONITOR_SERVER:
                            gauges_dict['UDP']['pkt_drop']['seq_num'].set(seq_mem.seq_num)
                            gauges_dict['UDP']['pkt_drop']['count'].set(seq_mem.count)
                            gauges_dict['UDP']['pkt_drop']['reverse_err'].set(seq_mem.reverse_err)
                            gauges_dict['UDP']['pkt_drop']['small_err'].set(seq_mem.small_err)
                            gauges_dict['UDP']['pkt_drop']['big_err'].set(seq_mem.big_err)
                            gauges_dict['UDP']['pkt_drop']['total_err'].set(total_sequence_errors)

                    elif proto == socket.IPPROTO_ICMP:
                        print("ICMP")
                        if MONITOR_SERVER:
                            gauges_dict['ICMP']['pkt_drop']['seq_num'].set(seq_mem.seq_num)
                            gauges_dict['ICMP']['pkt_drop']['count'].set(seq_mem.count)
                            gauges_dict['ICMP']['pkt_drop']['reverse_err'].set(seq_mem.reverse_err)
                            gauges_dict['ICMP']['pkt_drop']['small_err'].set(seq_mem.small_err)
                            gauges_dict['ICMP']['pkt_drop']['big_err'].set(seq_mem.big_err)
                            gauges_dict['ICMP']['pkt_drop']['total_err'].set(total_sequence_errors)

                    print("\tseq_num: " + str(seq_mem.seq_num) + "\n\tcount: " +
                        str(seq_mem.count) + "\n\treverse_err: " + str(seq_mem.reverse_err) +
                        "\n\tsmall_err: " + str(seq_mem.small_err) + "\n\tbig_err: " +
                        str(seq_mem.big_err) + "\n\ttotal_sequence_errors: " +
                        str(total_sequence_errors))


except KeyboardInterrupt:
    pass
