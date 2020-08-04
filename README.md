# ***Monitoring tool using eBPF*** #
This tool monitors TCP, UDP and ICMP incoming packets on multiple given interfaces.

Current version diplays the throughput for each flow calculated on each second, by default, or by x seconds given as parameter. You can choose displaying the measurements in bits or bytes.


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
sudo python3 monitor.py [-h] [-i INTERFACES] [-t INTERVAL_THROUGHPUT] [-b] [-B]

## For help type:

sudo python3 monitor.py -h

## Example:
sudo python3 monitor.py -i veth1