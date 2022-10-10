set -x

C=`pwd`
cd ../../utils/vnetUtils/examples/
sudo ./makeVNet <example.txt
cd ../helper/

CMD="../../../build/tools/cli -c eth-test"
tmux split-window -t 1 "sudo ./execNS ns1 $CMD veth1-2; read"
tmux split-window -h -t 1 "sudo ./execNS ns3 $CMD veth3-0 veth3-2 veth3-4; read"
tmux split-window -h -t 3 "sudo ./execNS ns4 $CMD veth4-3; read"
tmux split-window -t 4 "sudo ./execNS ns2 $CMD veth2-1 veth2-3; read"
sudo ./execNS ns0 $CMD veth0-3
read
cd ../examples/
sudo ./removeVNet <example.txt
exit
