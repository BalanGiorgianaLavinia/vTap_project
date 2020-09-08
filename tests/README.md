# ***Acceptance tests*** #

## ***Testing Throughput Measurement Program*** #

## Requirements
You need to have bmon and trafgen tools already installed.

## Instalation
### Ubuntu
    sudo apt install bmon -y
    sudo apt-get install netsniff-ng
### Fedora
    sudo yum install bmon
    sudo yum install netsniff-ng

## Usage of the program
    sudo ./test.py      # from the tests folder



## ***Testing Jitter Measurement Program*** #

## Requirements
You need to have trafgen tool already installed.

## Instalation
### Ubuntu
    sudo apt-get install netsniff-ng
### Fedora
    sudo yum install netsniff-ng

## Usage of the program
    sudo python3 test_jitter.py      # from the tests folder


## ***Testing Packet Loss Measurement Program*** #

## Requirements
You need to have gnome terminal and trafgen tool already installed.

## Instalation
### Ubuntu
    sudo apt-get install netsniff-ng
### Fedora
    sudo yum install netsniff-ng

## Usage of the program
    sudo ./test_packet_loss.py      # from the tests folder