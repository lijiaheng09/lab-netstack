#! /usr/bin/env python3

import sys

if __name__ == '__main__':
    pref = sys.argv[1] + ':'
    while True:
        v = input().split()
        if len(v) > 1 and v[0] == pref:
            break
    while True:
        v = input().split()
        if len(v) > 1 and v[0] == 'ether':
            print(v[1])
            exit()
