set -x
C=$PWD
cd ../echo
make clean-wrap; make wrap
cd $C/../../utils/vnetUtils/examples
sudo ./makeVNetRaw <example.txt
cd ../helper
sudo ./execNS ns1 tcpdump -n -c 1 -i veth1-2 -Q out -w $C/capture.pcap tcp &
sleep 1
sudo ./execNS ns1 $C/../echo/perf_server_wrap &
sudo ./execNS ns2 $C/../echo/perf_client_wrap 10.100.1.1
wait
cd ../examples
sudo ./removeVNet <example.txt
tcpdump -XX -r $C/capture.pcap
exit
