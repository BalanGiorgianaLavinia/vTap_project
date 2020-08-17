#!/bin/bash

ip link add veth0 type veth peer name veth1
ip netns add test
ip link set veth0 netns test
ip link set veth1 up
ip netns exec test ip link set veth0 up

ip addr add 10.1.0.2/24 dev veth1
ip netns exec test ip addr add 10.1.0.1/24 dev veth0

