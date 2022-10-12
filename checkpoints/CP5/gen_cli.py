IP = [
  '',
  '10.100.1.1',
  '10.100.1.2',
  '10.100.2.2',
  '10.100.3.2',
  '10.100.4.2',
  '10.100.5.2',
]
for i in range(1, 7):
  with open(f'scripts/ns{i}-cli.txt', 'w') as fp:
    print('auto-config -r 1 4 10', file=fp)
    print('sleep 5', file=fp)
    print(f'route-rip-info', file=fp)
    for j in range(1, 7):
      if i != j:
        print('!echo =================', file=fp)
        print(f'!echo traceroute to ns{i}-ns{j}', file=fp)
        print(f'traceroute {IP[j]}', file=fp)
    print(f'!echo !!!ns{i} Done!!! >/dev/stderr', file=fp)
    if i == 5:
      print(f'sleep 5', file=fp)
      print(f'!echo !!!ns5 break!!! >/dev/stderr', file=fp)
    else:  
      print(f'sleep 15', file=fp)
      print(f'!echo !!!ns{i}: make sure now break ns5!!! >/dev/stderr', file=fp)
      print(f'route-rip-info', file=fp)
      for j in range(1, 7):
        if j != i and j != 5:
          print('!echo =================', file=fp)
          print(f'!echo traceroute to ns{i}-ns{j}', file=fp)
          print(f'traceroute {IP[j]}', file=fp)
      print(f'!echo !!!ns{i} Done 2!!! >/dev/stderr', file=fp)
      print(f'sleep 15', file=fp)
