# ***Monitoring tool using eBPF*** #
This tool monitors TCP, UDP and ICMP incoming packets on multiple given interfaces.

Current version displays THROUGHPUT, GOODPUT, JITTER and PACKET LOSS statistics for each flow. 

## Throughput and Goodput
The measurements are displayed in Bytes/second by default. You can choose to dispay them in bits/second with "-b" parameter.

## Jitter
The program displays the average inter-arrival time and the jitter calculated as standard deviation in miliseconds.
If a greater than 2 seconds inter-arrival time is found then this means that the flow probably stopped and the jitter is resetted and calculated for the next packets. 

## Packet Loss
You need to put *"-packet_loss"* parameter for program to display packet loss related statistics second by second such as: current sequence number, total number of received packets from the beginning of the program, number of reverse errors (how many packets with smaller seq number than the current one are received), small and big errors (number of packets for which the difference between its seq numbers and the previous one is smaller or greater than a sequence threshold). You can give the sequence threshold in **config.json**.

For UDP and ICMP packets you can give to the program a 32-bit offset relative to the beginning of the packet payload (effective data) or a 32-bit pattern (in packet payload, too; this should be given if other encapsulations are/can be added to the packet) and a 32-bit offset (relative to the beginning of the given pattern) where the program will find the sequence number.  

**Constraint**: The pattern should be given in the first 5000 bytes of the packet payload due to eBPF constraints.

The pattern and the offset should be given in **config.json** in *PATTERN* and *OFFSET* fields.

# Requirements
You need to have the following software:
- linux environment with kernel version 5.3+ (recommended latest Ubuntu, Fedora, etc)
- python3
- pip3
- netifaces from pip3
- git (only for cloning)

# Instalation
## Ubuntu
    sudo apt install python3 python3-pip bcc git -y

    pip3 install netifaces

    git clone https://bitbucket.it.keysight.com/scm/ixvmintern/vtap-project.git

## Fedora
    yum install bcc python3

    pip3 install netifaces

    git clone https://bitbucket.it.keysight.com/scm/ixvmintern/vtap-project.git


# Usage
    sudo python3 monitor.py [-h] [-i INTERFACES] [-t INTERVAL_THROUGHPUT] [-b] [-j INTERVAL_JITTER] [-packet_loss]


## For help type:

    sudo python3 monitor.py -h

## Example:
    sudo python3 monitor.py -i veth1

## Filtering packets
To add one or more rules for filtering the packets open config.json and add them in the RULES dictionary.
You have some examples in the EXAMPLES dictionary.
The "-" character means that the coresponding item is not taken into consideration for filtering.

If you have, for example 1.1.1.1 2.2.2.2 - 22 TCP means that
you monitor only the packets from 1.1.1.1 going to 2.2.2.2 which have the destination port 22 using TCP protocol. The source port does not matter.

    NOTE: If using lists, do not introduce spaces between values and comma.

    [TCP, UDP] -> INCORRECT
    [TCP,UDP] -> CORRECT

