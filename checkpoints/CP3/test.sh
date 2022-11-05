set -x
C=$PWD
cd ../../utils/vnetUtils/examples
sudo ./makeVNet <example.txt
cd ../helper
sudo ./execNS ns1 $C/ns1.sh
cd ../examples
sudo ./removeVNet <example.txt
tcpdump -XX -r $C/capture.pcap
