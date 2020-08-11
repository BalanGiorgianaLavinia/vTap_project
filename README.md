# ***Monitoring tool using eBPF*** #
This tool monitors TCP, UDP and ICMP incoming packets on multiple given interfaces.

Current version displays THROUGHPUT, GOODPUT and JITTER for each flow calculated on each second, by default, or by x seconds given as parameter. You can choose displaying the measurements in bits or bytes for throughput and goodput.


# Requirements
You need to have the following software:
- linux environment with kernel version 3.18+ (recommended latest Ubuntu, Fedora, etc)
- python3
- pip3
- netifaces from pip3
- git (only for cloning)

# Instalation
## Ubuntu
    sudo apt install python3, python3-pip, bcc, git -y

    pip3 install netifaces

    git clone https://bitbucket.it.keysight.com/scm/ixvmintern/vtap-project.git

## Fedora
    yum install bcc, python3-dev

    pip3 install netifaces

    git clone https://bitbucket.it.keysight.com/scm/ixvmintern/vtap-project.git


# Usage
    sudo python3 monitor.py [-h] [-i INTERFACES] [-t INTERVAL_THROUGHPUT] [-b] [-B] [-j INTERVAL_JITTER]


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