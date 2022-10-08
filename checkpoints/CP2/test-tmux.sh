set -x

C=`pwd`
cd ../../utils/vnetUtils/examples/
sudo ./makeVNet <example.txt
cd ../helper/
veth0_3=`sudo ./execNS ns0 ifconfig | $C/getEther.py veth0-3`
veth1_2=`sudo ./execNS ns1 ifconfig | $C/getEther.py veth1-2`
veth2_1=`sudo ./execNS ns2 ifconfig | $C/getEther.py veth2-1`
veth2_3=`sudo ./execNS ns2 ifconfig | $C/getEther.py veth2-3`
veth3_0=`sudo ./execNS ns3 ifconfig | $C/getEther.py veth3-0`
veth3_2=`sudo ./execNS ns3 ifconfig | $C/getEther.py veth3-2`
veth3_4=`sudo ./execNS ns3 ifconfig | $C/getEther.py veth3-4`
veth4_3=`sudo ./execNS ns4 ifconfig | $C/getEther.py veth4-3`
tmux split-window -t 1 "sudo ./execNS ns1 ../../../build/tools/eth_test veth1-2 $veth2_1; read"
tmux split-window -h -t 1 "sudo ./execNS ns3 ../../../build/tools/eth_test veth3-0 $veth0_3 veth3-2 $veth2_3 veth3-4 $veth4_3; read"
tmux split-window -h -t 3 "sudo ./execNS ns4 ../../../build/tools/eth_test veth4-3 $veth3_4; read"
tmux split-window -h -t 4 "sudo ./execNS ns2 ../../../build/tools/eth_test veth2-1 $veth1_2 veth2-3 $veth3_2; read"
sudo ./execNS ns0 ../../../build/tools/eth_test veth0-3 $veth3_0
wait
cd ../examples/
sudo ./removeVNet <example.txt
exit
