set -x

C=`pwd`
cd ../../utils/vnetUtils/examples/
sudo ./makeVNet <example.txt
cd ../helper/
set -x
sudo ./execNS ns3 ../../../build/tools/cli -fi $C/test.txt
cd ../examples/
sudo ./removeVNet <example.txt
exit
