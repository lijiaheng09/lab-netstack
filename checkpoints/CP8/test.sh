set -x
C=$PWD
E=$PWD/../echo
cd $E
make clean-wrap; make wrap
cd $C/../../utils/vnetUtils/examples
sudo ./makeVNetRaw <example.txt
cd ../helper

sudo ./execNS ns1 ../../netem.sh veth1-2 add
sudo ./execNS ns2 ../../netem.sh veth2-1 add

sudo ./execNS ns1 tcpdump -n -i veth1-2 -w $C/capture.pcap tcp &
sleep 1
sudo ./execNS ns1 $E/echo_server_wrap &
sudo ./execNS ns2 $E/echo_client_check_wrap 10.100.1.1
wait %2
cd ../examples
sudo ./removeVNet <example.txt
exit
