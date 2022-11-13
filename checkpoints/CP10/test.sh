set -x
C=$PWD
E=$PWD/../echo
cd $E
make clean-wrap; make wrap
cd $C/../../utils/vnetUtils/examples
sudo ./makeVNetRaw <$C/vnet.txt
cd ../helper
sudo ./execNS ns2 ../../../build/tools/cli -cw auto-config -r 2>/dev/null &
sudo ./execNS ns3 ../../../build/tools/cli -cw auto-config -r 2>/dev/null &
sudo ./execNS ns4 $E/perf_server_wrap 2>/dev/null &
sudo ./execNS ns1 $E/perf_client_wrap 10.100.3.2 2>/dev/null
wait %3
cd ../examples
sudo ./removeVNet <$C/vnet.txt
exit
