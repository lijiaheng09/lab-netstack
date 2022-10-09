set -x
PROJ=`realpath $PWD/../../..`
TESTS=$PROJ/utils/tests
TOOLS=$PROJ/build/tools

cd $PROJ/utils/vnetUtils/examples
sudo ./makeVNet <example.txt
cd ../helper

veth1_2=`sudo ./execNS ns1 ifconfig | $TESTS/getEtherAddr.py veth1-2`
veth3_2=`sudo ./execNS ns3 ifconfig | $TESTS/getEtherAddr.py veth3-2`

sudo ./execNS ns2 ./bypassKernel
sudo ./execNS ns1 ethtool -K veth1-2 rx off tx off sg off tso off
sudo ./execNS ns3 ethtool -K veth3-2 rx off tx off sg off tso off
tmux split-window -t 1 sudo ./execNS ns1 bash
tmux split-window -t 2 -h sudo ./execNS ns3 bash
sudo ./execNS ns2 bash
