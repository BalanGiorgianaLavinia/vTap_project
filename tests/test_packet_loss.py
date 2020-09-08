#!/usr/bin/env python3
import subprocess
import sys
import os
import signal
import numpy as np
import time

def kill_process(cmd):
    output = subprocess.check_output("ps aux | grep \"%s\" | awk '{print $2}'" % cmd, \
                                     stderr=subprocess.STDOUT,\
                                     shell=True)

    output = output.decode('UTF-8')
    output = output.split()
    output = list(map(lambda x: int(x), output))
    for pid in output:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

kill_process("trafgen")

# run veth.sh
os.system('./veth.sh > /dev/null 2>&1')

os.chdir("../")


print("This script will run monitor.py and trafgen with different configuration " + \
      "files for packets")
input("Please press ENTER when you want to continue")

input("Packet loss related statistics displayed by monitor.py will be as follows: ")
input("\tseq_num: current sequence number")
input("\n\tcount: current number of received packets")
input("\n\treverse_err: counter which is incremented when the current sequence " + \
      "\n\t\tnumber is smaller than the previous one")
input("\n\tsmall_err: counter which is incremented when the current sequence number " + \
      "\n\t\tis greater than the previous one, but the difference between them is smaller " + \
      "\n\t\tthan a sequence threshold, given in json file, or equal with 2 by default")
input("\n\tbig_err: counter which is incremented when the current sequence number " + \
      "\n\t\tis greater than the previous one and the difference between them is greater " + \
      "\n\t\tthan a sequence threshold, given in json file, or equal with 2 by default")
input("\n\ttotal_seq_err: all errors")

##########################################################################################
os.system("clear")
print("Start monitor.py...")
monitor = subprocess.Popen('gnome-terminal -- python3 monitor.py -i veth1 -packet_loss', 
                           shell=True)

time.sleep(2)
os.system("clear")
print("\n\tNow generate TCP packets with sequence numbers from 0 to 7 one by one ")
time.sleep(4)

print("\n\tYou will see that after received each 8 packets (the sequence number resets)" + \
      " \nreverse_err will be incremented because of the packets with sequence number 0 " + \
      "received \nafter the sequence number 7")
time.sleep(12)

print("\nip netns exec test trafgen --dev veth0 --conf tcp_packet.cfg --rate 1pps ")
time.sleep(2)
proc_trafgen = subprocess.Popen("ip netns exec test trafgen --dev veth0 " + \
                                "--conf tcp_packet.cfg --rate 1pps > /dev/null",
                                shell=True)

time.sleep(18)

print("Closing monitor...")
time.sleep(2)
kill_process("monitor.py")
kill_process("trafgen")

os.kill(monitor.pid, signal.SIGINT)

##########################################################################################
os.system("clear")
print("Start monitor.py again...")
monitor = subprocess.Popen('gnome-terminal -- python3 monitor.py -i veth1 -packet_loss', 
                           shell=True)

time.sleep(2)
os.system("clear")
print("\nGenerate TCP packets with sequence numbers from 0 to 15 from 3 to 3 ")
time.sleep(4)

print("\n\tAnother thing You will see in this case is that the number of big errors " + \
      "\nwill be incremented because of the difference between consecutive " + \
      "\nsequence numbers (which is 3) is greater than the sequence threshold (2)")
time.sleep(12)

print("\nip netns exec test trafgen --dev veth0 --conf tcp_packet1.cfg --rate 1pps ")
time.sleep(2)
proc_trafgen = subprocess.Popen("ip netns exec test trafgen --dev veth0 " + \
                                "--conf tcp_packet1.cfg --rate 1pps > /dev/null",
                                shell=True)

time.sleep(18)

print("Closing monitor...")
time.sleep(2)
kill_process("monitor.py")
kill_process("trafgen")

os.kill(monitor.pid, signal.SIGINT)

##########################################################################################
os.system("clear")
print("Start monitor.py again...")
monitor = subprocess.Popen('gnome-terminal -- python3 monitor.py -i veth1 -packet_loss', 
                           shell=True)
time.sleep(2)
os.system("clear")
print("\n\tIn case of UDP/ICMP packets we introduce the sequence number into " + \
      "\nthe packet payload...So, we need to give to the program an offset " + \
      "\nor a pattern and an offset where the program will search for sequence number")
time.sleep(12)

print("\n\tThis is the configuration used for this case:")
print("cat udp_packet.cfg:")
os.system("cat udp_packet.cfg")
time.sleep(12)

print("\n\n\tAs you can see I put into the payload the pattern E7A5 C318 and the sequence " + \
      "\nnumber after this pattern, which means the seq number is at offset 4 " + \
      "\nrelative to the beginning of the pattern")
time.sleep(12)

print("\n\tThe pattern and the offset are given in json: ")
print("cat config.json: ")
os.system("cat config.json")
time.sleep(5)

print("\n\n\tNow let's generate the UDP flow and see that the program will found " + \
      "\nthe sequence number 35 given after that pattern")
time.sleep(8)
print("\tip netns exec test trafgen --dev veth0 --conf udp_packet.cfg --rate 1pps")
time.sleep(2)
proc_trafgen = subprocess.Popen("ip netns exec test trafgen --dev veth0 " + \
                                "--conf udp_packet.cfg --rate 1pps > /dev/null",
                                shell=True)

time.sleep(12)

print("\nClosing monitor...")
time.sleep(2)
kill_process("monitor.py")
kill_process("trafgen")

os.kill(monitor.pid, signal.SIGINT)