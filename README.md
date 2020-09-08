# ***Monitoring tool using eBPF*** #
This tool monitors TCP, UDP and ICMP incoming packets on multiple given interfaces.

Current version displays THROUGHPUT, GOODPUT, JITTER and PACKET LOSS statistics for each flow. 

## Throughput and Goodput
The measurements are displayed in Bytes/second by default. You can choose to dispay them in bits/second with "-b" parameter.
Throughput is calculated using the entire packet size including ethernet header, while goodput is calculated related only to the effective data (payload of TCP/UDP/ICMP packet).

## Jitter
The program displays the average inter-arrival time and the jitter calculated as standard deviation in miliseconds.
If a greater than 2 seconds inter-arrival time is found then this means that the flow probably stopped and the jitter is resetted and calculated for the next packets. 

## Packet Loss
Even if you do not want a packet drop measurement, you must fill the offset and pattern fields from json file; you can leave -1 in offset field and "0xFFFFFFFF" in pattern field from config.json file.
The program displays packet loss related statistics second by second such as: current sequence number, total number of received packets from the beginning of the program, number of reverse errors (how many packets with smaller seq number than the current one are received), small and big errors (number of packets for which the difference between its seq numbers and the previous one is smaller or greater than a sequence threshold). You can give the sequence threshold in **config.json**.

For UDP and ICMP packets you can give to the program a 32-bit offset relative to the beginning of the packet payload (effective data) or a 32-bit pattern (in packet payload, too; this should be given if other encapsulations are/can be added to the packet) and a 32-bit offset (relative to the beginning of the given pattern) where the program will find the sequence number.  

**Constraint**: The pattern should be given in the first 5000 bytes of the packet payload due to eBPF constraints.

The pattern and the offset should be given in **config.json** in *PATTERN* and *OFFSET* fields.

# Requirements
You need to have the following software:
- linux environment with kernel version 5.3+ (recommended latest Ubuntu, Fedora, etc)
- python3
- git (only for cloning)
- pip3
  - netifaces
  - bcc
  - numba
  - pytest
  - ipaddress
  - prometheus_client

# Instalation
## Ubuntu
    sudo apt install python3 python3-pip bcc git -y

    pip3 install netifaces bcc numba pytest ipaddress prometheus_client

    git clone https://bitbucket.it.keysight.com/scm/ixvmintern/vtap-project.git

## Fedora
    yum install bcc python3

    pip3 install netifaces bcc numba pytest ipaddress prometheus_client

    git clone https://bitbucket.it.keysight.com/scm/ixvmintern/vtap-project.git


# Usage
The monitor program can be started with the below command from vtap-project directory:

    sudo ./monitor_controller start [--detached] [-h] [-i INTERFACES] [-t INTERVAL_THROUGHPUT] [-b] [-j INTERVAL_JITTER] [-packet_loss]

    sudo ./monitor_controller stop

    sudo ./monitor_controller status

or

    sudo python3 monitor.py [-h] [-i INTERFACES] [-t INTERVAL_THROUGHPUT] [-b] [-j INTERVAL_JITTER] [-packet_loss]

## Monitor controller:
Parameters:

    start               -> starts the monitor program in interactive mode (the output is displayed continuously)
    start --detached    -> starts the monitor program in detached mode (the program is running in background)
    stop                -> stops the monitor program
    status              -> prints if the monitor program is running or not
    
NOTE! --detached has to be used immediately after start

## Starting Prometheus and Grafana containers:
    sudo docker-compose up -d prometheus grafana grafana-dashboards
   
## Stopping Prometheus and Grafana containers:
    sudo docker stop prometheus-svc grafana grafana-dashboards
    
## Resetting Prometheus and Grafana containers:
    sudo docker rm -f prometheus-svc grafana grafana-dashboards
    sudo docker-compose up -d prometheus grafana grafana-dashboards

### Default ports:
    1. monitor: 8080
    2. prometheus: 9090
    3. grafana: 3000

## For monitor help type:

    sudo python3 monitor.py -h

## Example:
    sudo ./monitor_controller --detached -i veth1
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

# Changing default server ports

## Monitor host server

The default port is 8080.
The port is specified in: 

    prometheus_grafana/prometheus.yaml

      - targets: ['localhost:8080']

1. Change the port 8080 to your desired port.
2. Start/Restart docker container from prometheus_grafana folder using 

        sudo docker stop prometheus-svc
        sudo docker-compose up -d prometheus
3.  Start monitor program from root folder using monitor controller and -server_port <DESIRED_PORT> as argument:

        sudo ./monitor_controller stop
        sudo ./monitor_controller start [--detached] [monitor.py args] -server_port <DESIRED_PORT>

        Example:
            sudo ./monitor_controller start --detached -i veth1 -server_port 2000


## Prometheus server

The default port is 9090.
The port is specified in:

    prometheus_grafana/docker-compose.yaml:

    services:
        prometheus:
            container_name: prometheus-svc
            image: prom/prometheus
            network_mode: host
            ports: 
            - "9090:9090"
            command: --config.file=/etc/prometheus/prometheus.yaml --web.enable-admin-api --web.listen-address=:9090
            volumes:
            - ./prometheus.yaml:/etc/prometheus/prometheus.yaml

and

    prometheus_grafana/grafana-data/datasources:

    "url": "http://localhost:9090",

1. Change every 9090 port to your desired port.
2. Start/Restart docker containers from prometheus_grafana folder using:

        sudo docker-compose up -d prometheus
        sudo docker rm -f grafana grafana-dashboards
        sudo docker-compose up -d grafana grafana-dashboards

## Grafana server

The default port is 3000.
The port is specified in:

    prometheus_grafana/docker-compose.yaml:

    ports:
      - "3000:3000"
    ...
    
    - GF_SERVER_HTTP_PORT=3000
    ...

    curl --request POST http://localhost:3000/api/datasources --header 'Content-Type: application/json' -d @datasources.json
    curl --request POST http://localhost:3000/api/dashboards/db --header 'Content-Type: application/json' -d @dashboard.json"

1. Change every 3000 port to your desired port.
2. Restart docker container from prometheus_grafana folder using:

        sudo docker-compose up -d grafana grafana-dashboards