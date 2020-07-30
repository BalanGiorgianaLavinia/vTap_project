#!/bin/env python3
from bcc import BPF
import time, socket, sys, os
from ipaddress import ip_address, IPv4Address
import netifaces
import argparse

# help function
def help():
    # print("execute: {0} -i <net_interface>".format(sys.argv[0]))
    # print("e.g.: {0} -i eno1\n".format(sys.argv[0]))
    print("For help write: sudo python3 monitor.py -h")
    exit(1)

# add optional arguments for program
parser = argparse.ArgumentParser(description='Compute throughput for each TCP, UDP, ICMP flow')
parser.add_argument('-i', dest='INTERFACES', help='specify the interfaces on which to measure throughput (i.e. ens33 or ens33,lo)')
parser.add_argument('-t', dest='INTERVAL', default=1, help='specify the interval in seconds on which to do throughput measurement')
parser.add_argument('-b', action='store_true', default=False, dest='b_B_SWITCH', help='display the throughput in bits/second format')
parser.add_argument('-B', action='store_false', default=False, dest='b_B_SWITCH', help='display the throughput in Bytes/second format')

# take the arguments of the program
results = parser.parse_args()

# see the choice of display format
# if True then bits/sec;    if False then Bytes/sec
# default Bytes/sec
b_B_SWITCH = results.b_B_SWITCH


# take interfaces given as parameters
if (results.INTERFACES is None):
    help()

INTERFACES = results.INTERFACES.split(",")
if len(INTERFACES) == 0:
    help()


# take interval given as parameter also
INTERVAL = float(results.INTERVAL)


# This function gives me the ip address for a given interface
def getIp(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']



# function for printing calculated throughput in format B/KB/MB/GB
# def print_throughput(protocol, throughput):
#     if (throughput > (1024 * 1024 * 1024)):
#         print(protocol + ": %.4f" % (throughput/1024/1024/1024) + " [GBytes/second]")
#     elif (throughput > (1024 * 1024)):
#         print(protocol + ":\t %.4f" % (throughput/1024/1024) + " [MBytes/second]")
#     elif (throughput > 1024):
#         print(protocol + ":\t %.4f" % (throughput/1024) + " [KBytes/second]")
#     else:
#         print(protocol + ":\t %.4f" % (throughput) + " [Bytes/second]")


# function for printing throughput in bits/sec or Bytes/sec format
def print_throughput(protocol, throughput):
    if (b_B_SWITCH == False):
        print(protocol + " bitrate [Bytes/sec]:  %.4f" % throughput)
    else:
        print(protocol + " bitrate [bits/sec]:  %.4f" % (throughput*8))
        



# define BPF program
bpf_text = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>

BPF_ARRAY(packet_count, u64, 256);
BPF_ARRAY(packet_size, u64, 256);

// BPF_HASH(data_map, u32, u32, 256);


int count_packets(struct __sk_buff *skb) {
    int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    int size = load_half(skb, ETH_HLEN + offsetof(struct iphdr, tot_len));
    size -= sizeof(struct iphdr);

    u32 daddr, saddr;
    saddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
    daddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));

    // if (data_map.lookup(&saddr)) {
    //     data_map.delete(&saddr);
    // }
    // data_map.update(&saddr, &daddr);


    u64 *value = packet_count.lookup(&index);
    u64 *old_size = packet_size.lookup(&index);
    u64 new_size = size;

    if (old_size)
        new_size += *old_size;


    // filter incoming packets
    FILTER


    if (value) {
        packet_count.increment(index);
        packet_size.update(&index, &new_size);
    }
           
    return 0;
}
"""


# filter rule to leave only the incoming packets from all the interfaces
FILTER = "if ("

for interface in INTERFACES:
    if "daddr" in FILTER:
        FILTER += " && "
    
    FILTER += "(daddr != %s)" % str(int(IPv4Address(getIp(interface))))

FILTER += ") {return 0;}"

bpf_text = bpf_text.replace('FILTER', FILTER)



# load bpf code
bpf = BPF(text=bpf_text)
ffilter = bpf.load_func("count_packets", BPF.SOCKET_FILTER)

for interface in INTERFACES:
    BPF.attach_raw_socket(ffilter, interface)



# this code was for printing source->destination addresses for each packet
# packets_dict = bpf.get_table('data_map')
# time.sleep(5)
# for k, v in packets_dict.items():
#     print(str(ip_address(k.value)) + " -> " + str(ip_address(v.value)))
# exit(0)


# dictionary for initial time for TCP, UDP, ICMP
initial_time = {socket.IPPROTO_TCP: 0,
                socket.IPPROTO_UDP: 0,
                socket.IPPROTO_ICMP: 0}

# time_start_throughputAll = 0
# current_time_all = 0

# dictionary for time spent since the first received packet for TCP, UDP, ICMP
current_time_spent = {socket.IPPROTO_TCP: 0,
                    socket.IPPROTO_UDP: 0,
                    socket.IPPROTO_ICMP: 0}


prev_totalSize_ICMP = 0
prev_totalSize_TCP = 0
prev_totalSize_UDP = 0

prev_throughput_TCP = 0
prev_throughput_UDP = 0
prev_throughput_ICMP = 0


try:
    while True:
        count_TCP = bpf["packet_count"][socket.IPPROTO_TCP].value
        count_UDP = bpf["packet_count"][socket.IPPROTO_UDP].value
        count_ICMP = bpf["packet_count"][socket.IPPROTO_ICMP].value

        totalSize_TCP = bpf["packet_size"][socket.IPPROTO_TCP].value
        totalSize_UDP = bpf["packet_size"][socket.IPPROTO_UDP].value
        totalSize_ICMP = bpf["packet_size"][socket.IPPROTO_ICMP].value       


        # clear the console
        os.system('cls||clear')

        print("Throughput measurement on " + ", ".join(INTERFACES) + " each " + str(INTERVAL) + " seconds:\n")


        # print("\nTCP: {0}, UDP: {1}, ICMP: {2}".
        #         format(count_TCP, count_UDP, count_ICMP))
        # print("SIZE_TCP: {0}, SIZE_UDP: {1}, SIZE_ICMP: {2}".
        #         format(totalSize_TCP, totalSize_UDP, totalSize_ICMP))

#-------------------------------ICMP Throughput--------------------------------
        if (count_ICMP != 0 and initial_time[socket.IPPROTO_ICMP] == 0):
            initial_time[socket.IPPROTO_ICMP] = time.time()
        else:
            if (count_ICMP != 0 and initial_time[socket.IPPROTO_ICMP] != 0):
            
                if (time.time() - initial_time[socket.IPPROTO_ICMP] >= INTERVAL):
                    size_per_interval_ICMP = totalSize_ICMP - prev_totalSize_ICMP
                    prev_totalSize_ICMP = totalSize_ICMP

                    throughput_ICMP = size_per_interval_ICMP / (time.time() - initial_time[socket.IPPROTO_ICMP])
                    prev_throughput_ICMP = throughput_ICMP

                    print_throughput("ICMP", throughput_ICMP)

                    initial_time[socket.IPPROTO_ICMP] = time.time()
                else:
                    print_throughput("ICMP", prev_throughput_ICMP)

            # if (count_ICMP != 0):
                # throughput_ICMP = totalSize_ICMP #/ \
                #                     # current_time_spent[socket.IPPROTO_ICMP]
                # print_throughput("ICMP", throughput_ICMP)


#-------------------------------TCP Throughput---------------------------------
        if (count_TCP != 0 and initial_time[socket.IPPROTO_TCP] == 0):
            initial_time[socket.IPPROTO_TCP] = time.time()
        else:
            if (count_TCP != 0 and initial_time[socket.IPPROTO_TCP] != 0):
               
                if (time.time() - initial_time[socket.IPPROTO_TCP] >= INTERVAL):
                    size_per_interval_TCP = totalSize_TCP - prev_totalSize_TCP
                    prev_totalSize_TCP= totalSize_TCP

                    throughput_TCP = size_per_interval_TCP / (time.time() - initial_time[socket.IPPROTO_TCP])
                    prev_throughput_TCP = throughput_TCP

                    print_throughput("TCP", throughput_TCP)

                    initial_time[socket.IPPROTO_TCP] = time.time()
                else:
                    print_throughput("TCP", prev_throughput_TCP)

        # if (count_TCP != 0 and initial_time[socket.IPPROTO_TCP] == 0):
        #     initial_time[socket.IPPROTO_TCP] = time.time()
        # else:
            # if (count_TCP != 0 and initial_time[socket.IPPROTO_TCP] != 0):
            #     current_time_spent[socket.IPPROTO_TCP] = time.time() - \
            #                                     initial_time[socket.IPPROTO_TCP]
            #     print("\nCurrent time since the first TCP transmission: %.4f" %
            #                         current_time_spent[socket.IPPROTO_TCP] + " [seconds]")


            # if (count_TCP != 0):
                # throughput_TCP = totalSize_TCP / \
                                    # current_time_spent[socket.IPPROTO_TCP]
                # print_throughput("TCP", throughput_TCP)


#-------------------------------UDP Throughput---------------------------------
        if (count_UDP!= 0 and initial_time[socket.IPPROTO_UDP] == 0):
            initial_time[socket.IPPROTO_UDP] = time.time()
        else:
            if (count_UDP != 0 and initial_time[socket.IPPROTO_UDP] != 0):
 
                if (time.time() - initial_time[socket.IPPROTO_UDP] >= INTERVAL):
                    size_per_interval_UDP = totalSize_UDP - prev_totalSize_UDP
                    prev_totalSize_UDP= totalSize_UDP

                    throughput_UDP = size_per_interval_UDP / (time.time() - initial_time[socket.IPPROTO_UDP])
                    prev_throughput_UDP = throughput_UDP

                    print_throughput("UDP", throughput_UDP)

                    initial_time[socket.IPPROTO_UDP] = time.time()
                else:
                    print_throughput("UDP", prev_throughput_UDP)

        # if (count_UDP != 0 and initial_time[socket.IPPROTO_UDP] == 0):
        #     initial_time[socket.IPPROTO_UDP] = time.time()
        # else:
            # if (count_UDP != 0 and initial_time[socket.IPPROTO_UDP] != 0):
            #     current_time_spent[socket.IPPROTO_UDP] = time.time() - \
            #                                     initial_time[socket.IPPROTO_UDP]
            #     print("\nCurrent time since the first UDP transmission: %.4f" %
            #                         current_time_spent[socket.IPPROTO_UDP] + " [seconds]")


            # if (count_UDP != 0):
            #     throughput_UDP = totalSize_UDP #/ \
            #                         # current_time_spent[socket.IPPROTO_UDP]
            #     print_throughput("UDP", throughput_UDP)


#-------------------------------TOTAL Throughput-------------------------------
        # if ((count_TCP != 0 or count_UDP != 0 or count_ICMP != 0) and 
        #         time_start_throughputAll == 0):
        #         time_start_throughputAll = time.time()
        # else:
        #     if ((count_TCP != 0 or count_UDP != 0 or count_ICMP != 0) and 
        #             time_start_throughputAll != 0):
        #             current_time_all = time.time() - time_start_throughputAll
        #             print("\nCurrent time since the first transmission: %.4f" %
        #                             current_time_all + " [seconds]")

        #     if (count_TCP != 0 or count_UDP != 0 or count_ICMP != 0):
        #         throughput_all = (totalSize_ICMP + totalSize_TCP + totalSize_UDP) / \
        #                             current_time_all
        #         print_throughput("ALL", throughput_all)


        time.sleep(INTERVAL)
        
except KeyboardInterrupt:
    pass


#Throughput(bits/sec)= (number of received bits)/Total Time spent in delivering that amount of data.