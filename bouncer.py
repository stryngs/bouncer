#!/usr/bin/python3

import argparse
import signal
import sys
import time
from scapy.all import *

class Bouncer(object):

    __slots__ = ['FILTER',
                 'LFILTER',
                 'PRN',
                 'baseline',
                 'count',
                 'interface',
                 'interval',
                 'iteration',
                 'lastTime',
                 'lfilter',
                 'pks',
                 'sh',
                 'timer',
                 'wrt']

    def __init__(self, **kwargs):
        self.count = 1
        self.interface = kwargs.get('interface')
        self.lfilter = kwargs.get('LFILTER')
        self.interval = kwargs.get('interval')
        self.iteration = 1
        self.sh = kwargs.get('sh')
        print('Opening events.log')
        self.sh.wrt = open('events.log', 'a')
        if kwargs.get('baseline') is None:
            self.baseline = 1000
        else:
            self.baseline = int(kwargs.get('baseline'))

        self.FILTER = kwargs.get('FILTER')
        self.LFILTER = self.lFilter()
        self.PRN = self.pRn()

        self.timer = time.time()
        self.lastTime = time.time()

        ## With lfilter
        ### Need to create an arg concept
        if self.lfilter is not None:

            ## With filter
            if self.FILTER is not None:
                p = sniff(iface = self.interface, prn = self.PRN, lfilter = self.LFILTER, filter = self.FILTER, store = 0)
            else:
                p = sniff(iface = self.interface, prn = self.PRN, lfilter = self.LFILTER, store = 0)

        ## With prn
        else:
            if self.FILTER is not None:
                p = sniff(iface = self.interface, prn = self.PRN, filter = self.FILTER, store = 0)

            else:
                p = sniff(iface = self.interface, prn = self.PRN, store = 0)


    def lFilter(self):
        def snarf(pkt):
            pass
        return snarf


    def pRn(self):
        """stdout and storage"""
        def snarf(pkt):
            capTime = time.time()
            if pkt.haslayer('TCP'):
                proto = 'TCP'
                dpt = pkt[TCP].dport
            elif pkt.haslayer('UDP'):
                proto = 'UDP'
                dpt = pkt[UDP].dport
            else:
                proto = 'UNK'
                dpt = None
            self.sh.wrt.write('{0}:{1}:{2}\n'.format(str(capTime), proto, str(dpt)))

            if self.count % self.baseline == 0:

                timeDelta = capTime - self.lastTime
                self.pks = (self.baseline / timeDelta)
                self.lastTime = time.time()
                print(int(self.pks), '| {:.3f} |'.format(timeDelta), self.FILTER, '| {0} | {1}'.format(self.baseline, self.iteration))
                self.iteration += 1
            self.count += 1
        return snarf


class Shared(object):
    slots = ['wrt']


def crtlC(sh):
    """Handle CTRL+C."""
    def tmp(signal, frame):
        print('\nClosing events.log')
        sh.wrt.close()
        sys.exit(0)
    return tmp


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'A way of monitoring and controlling the flow of packets and frames', prog = 'bouncer')
    parser.add_argument('-b', help = 'baseline')
    parser.add_argument('-f', help = 'filter')
    parser.add_argument('-i', help = 'interface')
    parser.add_argument('-r', help = 'reader')
    args = parser.parse_args()

    ## read
    if args.r is not None:
        eDict = {}
        with open(args.r) as iFile:
            events = iFile.read().splitlines()
        for event in events:
            ev = event.split(':')

            ## UNK ignores
            try:
                eDict.update({float(ev[0]): (ev[1], int(ev[2]))})
            except:
                pass

        ## storage
        tcpDict = {}
        udpDict = {}
        for k, v in eDict.items():

            ## protocols
            if v[0] == 'TCP':
                portCheck = tcpDict.get(v[1])
                if portCheck is not None:
                    newC = portCheck + 1
                else:
                    newC = 1
                tcpDict.update({v[1]: newC})
            elif v[1] == 'UDP':
                portCheck = udpDict.get(v[1])
                if portCheck is not None:
                    newC = portCheck + 1
                else:
                    newC = 1
                udpDict.update({v[1]: newC})

        ## ascending
        tOrder = [i for i in tcpDict.keys()]
        tOrder.sort()
        uOrder = [i for i in udpDict.keys()]
        uOrder.sort()

        ## stdouts
        if len(tOrder) > 0:
            for t in tOrder:
                print(t, ' | ', tcpDict.get(t))
        if len(uOrder) > 0:
            for u in uOrder:
                print(u, ' | ', udpDict.get(u))

        ## UNK declarations go here

    ## sniff
    else:
        sh = Shared()
        signal_handler = crtlC(sh)
        signal.signal(signal.SIGINT, signal_handler)
        bn = Bouncer(baseline = args.b, FILTER = args.f, interface = args.i, sh = sh)
