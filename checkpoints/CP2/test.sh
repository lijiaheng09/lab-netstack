set -x

C=`pwd`
cd ../../utils/vnetUtils/examples/
sudo ./makeVNet <example.txt
cd ../helper/

CMD="../../../build/tools/cli -c eth-test"
sudo ./execNS ns1 $CMD veth1-2 2>/dev/null &
sudo ./execNS ns4 $CMD veth4-3 2>/dev/null &
sudo ./execNS ns2 $CMD veth2-1 veth2-3 2>/dev/null &
sudo ./execNS ns0 $CMD veth0-3 2>/dev/null &
sudo ./execNS ns3 $CMD veth3-0 veth3-2 veth3-4
wait
cd ../examples/
sudo ./removeVNet <example.txt
exit
