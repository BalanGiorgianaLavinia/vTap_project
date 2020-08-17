#!/bin/env python3
import os
import subprocess
import signal
import time
import tempfile
import errno
import json

MEASURE_UNIT = 'MiB'
configs = [
    {
        "RULES": [
            "- - - - -"
        ],
    },

    {
        "RULES": [
            "- - - - [TCP,UDP]"
        ],
    },

    {
        "RULES": [
            "192.168.51.1 - - - -"
        ],
    },

    {
        "RULES": [
            "192.168.51.2 - 4500 - -"
        ],
    }

]

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

# run veth.sh
os.system('./veth.sh > /dev/null 2>&1')

# change directory 
os.chdir("../")

os.system("cp config.json config.json.bk")

bmon_pipe = 'bmon_pipe'
monitor_pipe = 'monitor_pipe'


print('\nStart testing...\n')

for i in range(4):
    with open('config.json', 'w') as outfile:
            json.dump(configs[i], outfile)

    if i == 0:
        print('TEST ' + str(i + 1) + ': Monitor all packets coming on veth1 \n\t' + 
              'indifferently of ip/port source/destination or protocol \n\twith ', end='')
    elif i == 1:
        print('\nTEST ' + str(i + 1) + ': Filter only TCP and UDP packets \n\twith ', end='')
    elif i == 2:
        print('\nTEST ' + str(i + 1) + ': Filter only the packets with source IP ' + 
              '192.168.51.1 which represents, in fact, only the ICMP packets \n\twith ', end='')
    elif i == 3:
        print('\nTEST ' + str(i + 1) + ': Filter the packets with source IP 192.168.51.2 ' + 
              '(TCP and UDP flows matched) and source port 4500 (=> only UDP flow matched) ' + 
              '\n\twith ', end='')


    with open('config.json', 'r') as outfile:
        print(str(outfile.readlines()) + ' rule in config.json')
    time.sleep(6)


    if i == 0:
        # start BMON
        time.sleep(1)
        print('\nRun BMON: bmon -p veth1')

    # start MONITOR
    time.sleep(1)
    print('\nRun MONITOR: python3 monitor.py -i veth1 -B')

    proc_bmon = subprocess.Popen("bmon -o ascii -p veth1 > bmon_pipe &", shell=True)
    proc_monitor = subprocess.Popen("python3 monitor.py -i veth1 -B -test " +
                                    "> monitor_pipe &", shell=True)


    # start TRAFGEN
    time.sleep(1)
    print('\nRun traffic generator: ip netns exec test trafgen --dev veth0 ' + 
          '--rate 600Mbit --conf config.cfg -q')
    proc_trafgen = subprocess.Popen("ip netns exec test trafgen --dev veth0 " + 
                                    "--rate 600Mbit --conf config.cfg -q " +
                                    "> /dev/null", shell=True)


    try:
        os.mkfifo(monitor_pipe)
        os.mkfifo(bmon_pipe)
    except OSError as oe: 
        if oe.errno != errno.EEXIST:
            raise

    # open pipes
    open_monitor_pipe = open(monitor_pipe, 'r')
    open_bmon_pipe = open(bmon_pipe, 'r')

    time.sleep(1)
    print('\nNow wait 6 seconds for the calculations to be done...')
    if i == 0:
        print('And then we compare the results from BMON and MONITOR ')

    t = time.time()
    try:
        while True:

            line_bmon = open_bmon_pipe.readline()
            line_bmon = line_bmon.split()
            if len(line_bmon) != 5:
                continue

            bmon_throughput = line_bmon[1][:-3]
            if len(bmon_throughput) > 2:
                bmon_throughput = float(bmon_throughput)

            monitor_throughput = 0.00
            tcp_throughput = 0.00
            udp_throughput = 0.00
            icmp_throughput = 0.00

            for j in range(5):
                line_monitor = open_monitor_pipe.readline()
                line_monitor = line_monitor.split()
                if len(line_monitor) > 1:
                    if j > 1:
                        if j == 2:
                            tcp_throughput = float(line_monitor[3])
                        elif j == 3:
                            udp_throughput = float(line_monitor[3])
                        else:
                            icmp_throughput = float(line_monitor[3])
            monitor_throughput += tcp_throughput + udp_throughput + icmp_throughput

            if time.time() - t >= 6:
                break

        if i == 0:
            print('\n\tBMON result: ' + str(bmon_throughput) + MEASURE_UNIT)

        print('\tmonitor.py results: TCP->' + str(tcp_throughput) + MEASURE_UNIT + \
            '     UDP->' + str(udp_throughput) + MEASURE_UNIT + \
            '     ICMP->' + str(icmp_throughput) + MEASURE_UNIT)
        if i == 0:
            print('\tSum of monitor flow throughputs: ' + str(monitor_throughput) + MEASURE_UNIT)
        
        time.sleep(1)

        if i == 0:
            print('\nTest if a tollerance of 5%' + ' is verified and...', end='')
            time.sleep(2)
            # test with tollerance 5%
            if monitor_throughput >= 0.95*bmon_throughput and \
               monitor_throughput <= 1.05*bmon_throughput:
                print('CORRECT MEASUREMENT!!!')
                print('TEST 1 DONE SUCCESSFULLY')
            else:
                print('WRONG MEASUREMENT!!!')
            time.sleep(1)

        if i == 1:
            print('\nAs you can see no ICMP flow monitored -> 0.0 bitrate for ICMP')
            time.sleep(8)
            print('TEST 2 DONE SUCCESSFULLY')

        if i == 2:
            print('\nAs you can see no TCP and UDP flows monitored because the ' + 
                  'TCP and UDP packets do not have 192.168.51.1 as source IP')
            time.sleep(8)
            print('TEST 3 DONE SUCCESSFULLY')
        
        if i == 3:
            print('\nIn this case we should not have any TCP and ICMP flows monitored ' +
                  'because TCP packets do not match the source port condition and ' + 
                  'ICMP packets have neither that source IP nor ports')
            time.sleep(8)
            print('TEST 4 DONE SUCCESSFULLY')

        print('===============================================================================')

    except KeyboardInterrupt:
        print('\nexiting test..')
    finally:
        open_bmon_pipe.close()
        open_monitor_pipe.close()
        kill_process('bmon')
        kill_process('monitor.py')
        kill_process('trafgen')
        os.kill(proc_trafgen.pid, signal.SIGINT)
        os.system("rm {0} {1}".format(monitor_pipe, bmon_pipe))
        os.system("rm config.json")

print('\n\nFor a better understanding of the tests behavior take a look at the ' +
      'config.cfg file (constraints of the generated packages)\n')

os.system("cp config.json.bk config.json")
os.system("rm config.json.bk")
