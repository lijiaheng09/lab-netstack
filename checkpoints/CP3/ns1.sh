./bypassKernel
tcpdump -n -c 1 -i veth1-2 -Q out -w ../../../checkpoints/CP3/capture.pcap icmp &
../../../build/tools/cli -fi ../../../checkpoints/CP3/ns1-cli.txt
