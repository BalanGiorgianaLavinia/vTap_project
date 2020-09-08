import subprocess
import sys
import os
import signal
import numpy as np
import time
import statistics
from tabulate import tabulate


def str_to_ns(time_str):
     """
     input: time in a format `hh:mm:ss.up_to_9_digits`
     """
     h, m, s = time_str.split(":")
     int_s, ns = s.split(".")
     ns = map(lambda t, unit: np.timedelta64(t, unit),
              [h,m,int_s,ns.ljust(9, '0')],['h','m','s','ns'])
     return sum(ns)


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

tcpdump_pipe = "tcpdump_pipe"
monitor_pipe = "monitor_pipe"

kill_process("trafgen")


os.chdir("../")

proc_monitor = subprocess.Popen("python3 monitor.py -i veth1 -test_jitter " + \
                                "> monitor_pipe &", shell=True)

time.sleep(2)

proc_tcpdump = subprocess.Popen("tcpdump -i veth1 --immediate-mode -l -n" + \
                                " --time-stamp-precision=nano -ttt " + \
                                "> tcpdump_pipe &", shell=True)


try:
    os.mkfifo(tcpdump_pipe)
    os.mkfifo(monitor_pipe)
except OSError as oe: 
    pass

open_monitor_pipe = open(monitor_pipe, 'r')
open_tcpdump_pipe = open(tcpdump_pipe, 'r')

os.chdir("tests")


values_monitor = {
    "Jitter": 0.0,
    "Average": 0.0
}

values_tcpdump = {
    "Jitter": 0.0,
    "Average": 0.0
}

test_number = 0
trafgen_gaps = [10, 20, 50, 100, 500]

os.chdir("../")
print("Starting trafgen test {0} with {1} ms gap between packets"\
      .format(test_number, trafgen_gaps[test_number]))
time.sleep(1)

proc_trafgen = subprocess.Popen("ip netns exec test trafgen --dev veth0 " + \
                                "--conf config_jitter.cfg -t {}ms > /dev/null"
                                .format(trafgen_gaps[test_number]), shell=True)

trafgen_timer = time.time()


nanos = []
old_time = trafgen_timer
try:
    while True:
        line_tcpdump = open_tcpdump_pipe.readline()
        line_monitor = open_monitor_pipe.readlines()

        data_monitor = []
        data_tcpdump = []

        if len(line_tcpdump) > 5:
            data_tcpdump = line_tcpdump.split()[0]
           
            ns = int(str_to_ns(data_tcpdump))
            if ns == 0:
                continue

            if ns > (2 * 10**9):
                nanos = []
                continue

            nanos.append(ns)

        for line in line_monitor:
            data_monitor = line.split()

            if data_monitor == [] or len(data_monitor) < 2:
                continue

            if "TCP" in data_monitor[1]:
                if "Average" in data_monitor[0]:
                    values_monitor["Average"] = float(data_monitor[2])
                elif "Jitter" in data_monitor[0]:
                    values_monitor["Jitter"] = float(data_monitor[2])

        current_time = time.time()
        if current_time - old_time >= 1:
            os.system('clear')
            old_time = current_time

            print("Running trafgen with {} ms gap between packets"
                  .format(trafgen_gaps[test_number]))

            if len(nanos) > 1:
                values_tcpdump["Average"] = round(statistics.mean(nanos) / 10**6, 4)
                values_tcpdump["Jitter"] = round(statistics.stdev(nanos) / 10**6, 4)


            print(tabulate([['Avg', values_tcpdump["Average"], values_monitor["Average"], "ms"], 
                            ['Jitter', values_tcpdump["Jitter"], values_monitor["Jitter"], "ms"]], 
                            headers=[' ','TCPDUMP', 'MONITOR.PY', "UNIT"]))

            nanos = []             

        if time.time() - trafgen_timer >= 12:
            trafgen_timer = time.time()
            print("Test {} ending".format(test_number))
            nanos = []

            test_number += 1
            if test_number >= len(trafgen_gaps):
                kill_process("trafgen")
                print("Tests done... Exiting")
                time.sleep(2)
                raise KeyboardInterrupt

            kill_process("trafgen")

            print("Starting trafgen test {0} with {1} ms gap between packets"
                  .format(test_number, trafgen_gaps[test_number]))
            proc_trafgen = subprocess.Popen("ip netns exec test trafgen --dev veth0 " + \
                                            "--conf config_jitter.cfg -t {}ms > /dev/null"
                                            .format(trafgen_gaps[test_number]), shell=True)

            time.sleep(1)
            old_time = time.time()


except KeyboardInterrupt:
    exit(0)
finally:
    kill_process("tcpdump")
    kill_process('monitor.py')

    open_monitor_pipe.close()

    os.chdir("tests")
    open_tcpdump_pipe.close()
