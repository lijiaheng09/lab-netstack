set -x
C=$PWD
cd ../../utils/vnetUtils/examples
sudo ./makeVNetRaw <$C/vnet.txt
cd ../helper
sudo ./execNS ns2 ../../../build/tools/cli -cw auto-config -r 3 10 20 &
sleep 1
NS2_PID=`ps -C cli -o pid=`
sleep 1
sudo ./execNS ns3 ../../../build/tools/cli -cw auto-config -r 3 10 20 &
sleep 1
sudo ./execNS ns4 ../../../build/tools/cli -cw auto-config -r 3 10 20 &
sleep 1
echo CLI on ns2 has PID $NS2_PID
echo $NS2_PID >/tmp/ns2_pid
sudo ./execNS ns1 ../../../build/tools/cli -fi $C/ns1-cli.txt
cd ../examples
sudo ./removeVNet <$C/vnet.txt
