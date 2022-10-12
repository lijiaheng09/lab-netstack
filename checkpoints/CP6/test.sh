set -x
C=$PWD
cd ../../utils/vnetUtils/examples
sudo ./makeVNetRaw <$C/vnet.txt
cd ../helper
for i in {1..6}; do
  if [[ $i != 2 ]]; then
    sudo ./execNS ns$i ../../../build/tools/cli -cw auto-config -r 2>/dev/null &
  fi
done
sudo ./execNS ns2 ../../../build/tools/cli -fi $C/ns2-cli.txt
cd ../examples
sudo ./removeVNet <$C/vnet.txt
