set -x
C=$PWD
E=$PWD/../echo
cd $E
make clean-wrap; make wrap
cd $C/../../utils/vnetUtils/examples
sudo ./makeVNetRaw <$C/vnet.txt
cd ../helper
tmux split-window -t 1 "sudo ./execNS ns2 ../../../build/tools/cli -cw auto-config -r"
tmux split-window -t 2 -h "sudo ./execNS ns3 ../../../build/tools/cli -cw auto-config -r"
tmux split-window -t 1 "sudo ./execNS ns4 $E/echo_server_wrap 2>/dev/null; read"
sudo ./execNS ns1 $E/echo_client_wrap 10.100.3.2 2>/dev/null
read
cd ../examples
sudo ./removeVNet <$C/vnet.txt
exit
