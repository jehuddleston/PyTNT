#!/usr/bin/env python

"""
implementation of TNT
"""

import sys
import os
import stat
from enum import Enum, Flag, auto
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperPing, ScamperAddr
from ipaddress import ip_address, ip_network
import argparse
import json
import time
from datetime import timedelta

reserved_prefixes = [ip_network('0.0.0.0/8'), ip_network('10.0.0.0/8'), ip_network('100.64.0.0/10'), ip_network('127.0.0.0/8'), ip_network('169.254.0.0/16'), ip_network('172.16.0.0/12'), ip_network('192.0.0.0/24'), ip_network('192.0.2.0/24'), ip_network('192.88.99.0/24'), ip_network('192.168.0.0/16'), ip_network('198.18.0.0/15'), ip_network('198.51.100.0/24'), ip_network('203.0.113.0/24'), ip_network('224.0.0.0/4'), ip_network('233.252.0.0/24'), ip_network('240.0.0.0/4'), ip_network('255.255.255.255/32')]


tunnels = {}

class IngressStatus(Enum):
    NULL = 0
    START = 1

class TntHopType(Flag):
    INGR = auto()    # ingress LSR
    EGR = auto()     # egress LSR
    INTERN = auto()  # internal LSR
    EXP = auto()     # in explicit tunnel
    IMP_QT = auto()  # in implicit qttl tun
    IMP_UT = auto()  # in implicit uturn tun
    OPA = auto()     # in opaque tunnel
    INV = auto()     # in invisible tunnel

class TntHopDisc(Flag):
    FRPLA = auto()   # FRPLA trigger
    RTLA = auto()    # RTLA trigger
    DUP_IP = auto()  # Duplicate IP trigger
    MTTL = auto()    # mTTL trigger
    DPR = auto()     # discovery with DPR
    BRPR = auto()    # discovery with BRPR
    BUD = auto()     # discovery wth buddy IP
    INC = auto()     # incomplete discovery
    REV = auto()     # hop was revealed
    PREV = auto()    # hop is bfr non-rsp ing
    NTH_REV = auto() # nothing revealed
    INGR_NF = auto() # ingress not found
    TGT_NR = auto()  # target not reached
    BUD_REP = auto() # buddy report

class Trigger(Enum):
    NULL = 0
    DUP_IP = 1
    RTLA = 2
    FRPLA = 3
    MTTL = 4

class RevMode(Enum):
    NULL = 0
    DPR = 1
    BRPR = 2

@staticmethod
def ittl(ttl) -> int:
    if ttl > 128:
        return 255
    if ttl > 64:
        return 128
    if ttl > 32:
        return 64
    return 32

@staticmethod
def process_queue(queue, ctrl, vp=None):
    while len(queue) > 0:
        test = queue.pop(0)
        if test.method == "trace":
            ctrl.do_trace(test.dst, firsthop=test.start_ttl, wait_timeout=1,
                          userid=test.userid, attempts=3,method='icmp-paris',inst=vp)
        else:
            ctrl.do_ping(test.dst, attempts=1,inst=vp)

@staticmethod
def process_hops_pings(hops, pings, queue,probed=set()):
    for hop in hops:
        if hop is None:
            continue
        if pings.is_probed(hop.src):
            hop._ping_rttl = pings.get_rttl(hop.src)
        else:
            hop._trace._waiting += 1
            pings.block(hop.src, hop)
            if queue is not None and hop.src not in probed:
                probed.add(hop.src)
                t = Test("ping", hop.src)
                if t not in queue:
                    queue.append(t)

class Test:
    def __init__(self, method, dst):
        self.method = method
        self.dst = dst
        self.start_ttl = None
        self.userid = None

    def __eq__(self,other):
        return self.method == other.method and self.dst == other.dst

class TunnelTest:
    def __init__(self, start_addr, next_addr, target_addr,
                 trigger_type, userid, ingress_status):
        self._start_addr = start_addr
        self._next_addr = next_addr
        self._target_addr = target_addr
        self._ingress_status = ingress_status
        self._userid = userid
        self._trigger_type = trigger_type
        self._iteration = 1
        self._rev_mode = RevMode.NULL

    @property
    def dst(self):
        return self._target_addr

    @property
    def userid(self):
        return self._userid

class Tunnel:
    def __init__(self, start_addr, next_addr):
        self._start_addr = start_addr
        self._next_addr = next_addr
        self._lsp = []
        self._status = 0

    def __eq__(self, other):
        if(self._start_addr != other._start_addr or
           self._next_addr != other._next_addr):
            return False
        return True

    def __hash__(self):
        return hash((self._start_addr, self._next_addr))
    
    def __len__(self):
        return len(self._lsp)

    # add the discovered hops to the tunnel structure stored in the tunnel test
    def add(self, lsrs):
        # check if hops were discovered
        if lsrs is None or len(lsrs) == 0:
            return
        
        to_add = lsrs.copy()
        to_add.reverse()

        if len(to_add) == len(self._lsp):
            for i in range(len(to_add)):
                a = to_add[i]
                l = self._lsp[i]
                if a == None:
                    continue
                if l == None:
                    self._lsp[i] = a
                    continue
                if a.src == l.src:
                    continue
            return
        # lsrs.reverse()
        
        # lsrs.reverse()
        # lsps = []

        # lf = -1
        # while len(self._lsp)>lf:
        #     lf = len(self._lsp)

        #     rest2 = []
        #     for r in lsrs:
                
        # srcs = [lsr.src if lsr is not None else None for lsr in self._lsp]
        # to_add = [lsr.src if lsr is not None else None for lsr in lsrs]
        # to_add.reverse()

        # first = set(srcs)
        # lsp = []
        # lf = -1
        # while len(first) > lf:
        #     lf = len(first)
        #     rest2 = []
        #     for a in to_add:
        #         if len(first.intersection(set(to_add)))>0:
        #             first |= set(to_add)
        #         else:
        #             rest2.append()


        #avoid adding duplicate lsr sequences to the tunnel
        for hop in lsrs:
            srcs = [lsr.src if lsr is not None else None for lsr in self._lsp]
            to_add = [lsr.src if lsr is not None else None for lsr in lsrs]
            to_add.reverse()
            
            in_tun = False
            for idx in range(len(srcs) - len(to_add)+1):
                if srcs[idx: idx + len(to_add)] == to_add:
                    in_tun = True
                    break

            if not in_tun:
                self._lsp.insert(0, hop)

class PingTests:

    class _PingState(Enum):
        NOT_PROBED = 0
        PROBING = 1
        PROBED = 2

    class _PingResult:
        def __init__(self):
            self._state = PingTests._PingState(0)
            self._rttl = None

    def __init__(self):
        self._pings = {}
        self._blocked = {}

    def process(self, ping):
        rttls = {}
        rttl_freq = 0
        rttl = 0
        for reply in ping:
            if reply.is_icmp_echo_reply():
                if reply.reply_ttl not in rttls:
                    rttls[reply.reply_ttl] = 0
                rttls[reply.reply_ttl] += 1
        for ttl in sorted(rttls):
            if rttls[ttl] > rttl_freq:
                rttl = ttl
                rttl_freq = rttls[ttl]
        if ping.dst not in self._pings:
            self._pings[ping.dst] = PingTests._PingResult()
        if rttl_freq > 0:
            self._pings[ping.dst]._rttl = rttl
        self._pings[ping.dst]._state = PingTests._PingState.PROBED

    def is_probed(self, addr):
        if addr not in self._pings:
            return False
        if self._pings[addr]._state != PingTests._PingState.PROBED:
            return False
        return True

    def get_rttl(self, addr):
        if addr not in self._pings:
            return None
        return self._pings[addr]._rttl

    def block(self, addr, test):
        if addr not in self._blocked:
            self._blocked[addr] = []
        self._blocked[addr].append(test)

    def blocked(self, addr):
        if addr not in self._blocked:
            return
        while len(self._blocked[addr]) > 0:
            yield self._blocked[addr].pop(0)
        del self._blocked[addr]

class TntHop:
    def __init__(self, hop, trace):
        self._hop = hop
        self._types = TntHopType(0)
        self._disc = TntHopDisc(0)
        self._iteration = 0
        self._ping_rttl = None
        self._trace = trace

    # def __eq__(self,other):
    #     if not isinstance(other,TntHop):
    #         return False
        

    def __str__(self):
        line = f"{self.src:<15} {(self.rtt.total_seconds()*1000):.3f} ms"
        hop_reply_ttl = str(self.reply_ttl)
        if self.src.is_reserved():
            line += " rsvd rTTLs=<" + hop_reply_ttl + ",*>"
        else:
            if self._ping_rttl is None:
                line += " rTTLs=<" + hop_reply_ttl + ",*>"
            else:
                rttl = self._ping_rttl
                line += " rTTLs=<" + hop_reply_ttl + "," + str(rttl) + ">"

        if self.is_ttl_exp():
            line += " qttl=" + str(self.icmp_q_ttl) + (
                ((" uturn=" + str(self.uturn()) if self.uturn() != 0 else "")) +
                ((" frpla=" + str(self.frpla()) if self.frpla() > 0 else "")) +
                ((" rtla=" + str(self.rtla())) if self.rtla() > 0 else ""))

        if self.is_mpls():
            line += " [MPLS" + (
                (",EXP" if self.is_exp() else "") +
                (",OPA" if self.is_opa() else "") +
                (",IMP" if self.is_imp() else "") +
                (",INV" if self.is_inv() else "") +
                (",LSR" if self.is_intern() else "") +
                (",EGR" if self.is_egr() else "") +
                (",ING" if self.is_ingr() else ""))

            # trigger and signatures
            line += self.disc_str()
            if self.is_inferred():
                line += ",INF"
            else:
                # implicit signatures
                line += ((",QTTL" if self.is_imp_qt() else "") +
                         (",UTURN" if self.is_imp_ut() else ""))

            # discovery method
            if self.is_rev():
                if self.is_dpr():
                    line += ",DPR"
                elif self.is_brpr():
                    line += ",BRPR"
                line += f",step={self._iteration}"

            line += "]"

        if self.icmpext is not None:
            mplsc = 0
            mplsext = self.icmpext.mpls
            if mplsext is not None:
                mplsc = mplsext.mpls_count
            if mplsc > 0:
                mttl = mplsext.mpls_ttl(0)
                mlabel = mplsext.mpls_label(0)
                line += " Labels " + str(mlabel) + " mTTL=" + str(mttl)
                for j in range(1, mplsc):
                    mttl = mplsext.mpls_ttl(j)
                    mlabel = mplsext.mpls_label(j)
                    line += " | "  + str(mlabel) + " mTTL=" + str(mttl)

        return line

    def process_ping(self, rttl):
        self._ping_rttl = rttl
        self._trace._waiting -= 1
        if self._iteration != 0:
            self._trace = None

    # scamper_trace_hop_disc_trig_print
    def disc_str(self):
        return ((",DUPIP" if self.is_dupip() else "") +
                (",RTLA" if self.is_rtla() else "") +
                (",FRPLA" if self.is_frpla() else "") +
                (",MTTL" if self.is_mttl() else ""))

    @property
    def src(self):
        return self._hop.src

    def is_ttl_exp(self):
        return self._hop.is_icmp_ttl_exp()

    @property
    def icmp_q_ttl(self):
        return self._hop.icmp_q_ttl

    @property
    def icmpext(self):
        return self._hop.icmp_exts

    @property
    def probe_ttl(self):
        return self._hop.probe_ttl

    @property
    def reply_ttl(self):
        return self._hop.reply_ttl

    @property
    def rtt(self):
        return self._hop.rtt

    def is_juniper_imp(self):
        er_rttl = self._ping_rttl
        if er_rttl is None:
            return False
        er_ittl = ittl(er_rttl)
        te_rttl = self._hop.reply_ttl
        te_ittl = ittl(te_rttl)
        return te_ittl == 255 and er_ittl == 64

    def rtla(self):
        # The ping reply TTL must be available
        er_rttl = self._ping_rttl
        if er_rttl is None:
            return 0
        er_ittl = ittl(er_rttl)
        te_rttl = self._hop.reply_ttl
        te_ittl = ittl(te_rttl)
        # Router must be <255,X> with X <= 128 @@@
        if te_ittl != 255 or er_ittl == 255:
            return 0
        nb_hops_return_te = te_ittl - te_rttl + 1
        nb_hops_return_er = er_ittl - er_rttl + 1
        return nb_hops_return_te - nb_hops_return_er

    def frpla(self):
        te_rttl = self._hop.reply_ttl
        te_ittl = ittl(te_rttl)
        nb_hops_forward = self._hop.probe_ttl
        nb_hops_return = te_ittl - te_rttl + 1
        return nb_hops_return - nb_hops_forward

    def uturn(self):
        # The ping reply TTL must be available
        er_rttl = self._ping_rttl
        if er_rttl is None:
            return 0
        er_ittl = ittl(er_rttl)
        te_rttl = self._hop.reply_ttl
        te_ittl = ittl(te_rttl)
        nb_hops_return_te = te_ittl - te_rttl + 1
        nb_hops_return_er = er_ittl - er_rttl + 1
        return nb_hops_return_te - nb_hops_return_er

    def clear_type_lsr(self):
        self._types &= (TntHopType.EXP | TntHopType.IMP_QT | TntHopType.IMP_UT |
                        TntHopType.OPA | TntHopType.INV)

    def clear_types(self):
        self._types = TntHopType(0)

    def set_type(self, hop_type):
        self._types |= hop_type

    def is_ingr(self):
        return self._types & TntHopType.INGR

    def is_egr(self):
        return self._types & TntHopType.EGR

    def is_intern(self):
        return self._types & TntHopType.INTERN

    def is_exp(self):
        return self._types & TntHopType.EXP

    def is_imp_qt(self):
        return self._types & TntHopType.IMP_QT

    def is_imp_ut(self):
        return self._types & TntHopType.IMP_UT

    def is_imp(self):
        return self._types & (TntHopType.IMP_QT | TntHopType.IMP_UT)

    def is_opa(self):
        return self._types & TntHopType.OPA

    def is_inv(self):
        return self._types & TntHopType.INV

    def is_opa_egr(self):
        return self._types & TntHopType.OPA and self._types & TntHopType.EGR

    def is_mpls(self):
        return self.is_ingr() or self.is_egr() or self.is_intern()

    def is_inferred(self):
        if not self._types & TntHopType.INTERN:
            return False
        if self._types & (TntHopType.INV | TntHopType.OPA | TntHopType.IMP_UT |
                          TntHopType.IMP_QT | TntHopType.EXP):
            return False
        return True

    def clear_disc_trig(self):
        self._disc &= (TntHopDisc.FRPLA | TntHopDisc.RTLA | TntHopDisc.DUP_IP |
                       TntHopDisc.MTTL)

    def set_disc(self, hop_disc):
        self._disc |= hop_disc

    def is_rev(self):
        return self._disc & TntHopDisc.REV

    def is_dpr(self):
        return self._disc & TntHopDisc.DPR

    def is_brpr(self):
        return self._disc & TntHopDisc.BRPR

    def is_dupip(self):
        return self._disc & TntHopDisc.DUP_IP

    def is_rtla(self):
        return self._disc & TntHopDisc.RTLA

    def is_frpla(self):
        return self._disc & TntHopDisc.FRPLA

    def is_mttl(self):
        return self._disc & TntHopDisc.MTTL

    # scamper_trace_hop_disc_trig_mflags_set
    def mpls_disc_trigger_set(self, tunt):
        if tunt._trigger_type == Trigger.RTLA:
            self.set_disc(TntHopDisc.RTLA)
        elif tunt._trigger_type == Trigger.FRPLA:
            self.set_disc(TntHopDisc.FRPLA)
        elif tunt._trigger_type == Trigger.DUP_IP:
            self.set_disc(TntHopDisc.DUP_IP)
        elif tunt._trigger_type == Trigger.MTTL:
            self.set_disc(TntHopDisc.MTTL)

    # scamper_trace_hop_tunnel_type_mflag_set
    def mpls_type_trigger_set(self, tunt):
        if tunt._trigger_type == Trigger.MTTL:
            self.set_type(TntHopType.OPA)
        else:
            self.set_type(TntHopType.INV)

    # scamper_trace_hop_mpls_flags_set
    # Update the MPLS flags of an LSR depending on the tunnel test state
    def mpls_flags_set(self, tunt):
        self._iteration = tunt._iteration
        self.set_disc(TntHopDisc.REV)
        self.set_type(TntHopType.INTERN)
        # update the trigger
        self.mpls_disc_trigger_set(tunt)
        self.mpls_type_trigger_set(tunt)
        # update the revelation mode
        if tunt._rev_mode == RevMode.DPR:
            self.set_disc(TntHopDisc.DPR)
        elif tunt._rev_mode == RevMode.BRPR:
            self.set_disc(TntHopDisc.BRPR)
        # XXX: buddy_status

    # triggers 1/2
    def process_mplsext(self, prev):
        # flag as MPLS hop
        self.set_type(TntHopType.INTERN)

        # triggers 1/2: labels -> Explicit/opaque depending
        # on the MPLS TTL for the top label
        mplsext = self.icmpext.mpls if self.icmpext is not None else None
        mttl = mplsext.mpls_ttl(0)

        if mttl > 236 and mttl < 255:
            self.set_type(TntHopType.OPA)
        else:
            self.set_type(TntHopType.EXP)

        # if mttl > 1 or mttl < 255:
        #     self.set_type(TntHopType.EXP)
        # else:
        #     print('Found OPA!')
        #     self.set_type(TntHopType.OPA)

        # identify ingress
        if prev is not None and not prev.is_intern():
            if prev.is_egr() and not prev.is_juniper_imp():
                # if hop tagged as ingress and egress, it could be
                # implicit
                prev.clear_types()
                prev.set_type(TntHopType.INTERN)
                self.clear_disc_trig()
            else:
                # otherwise, should be a real ingress
                prev.set_type(TntHopType.INGR)
                if self.is_opa():
                    prev.set_type(TntHopType.OPA)
                    prev.set_disc(TntHopDisc.MTTL)
                else:
                    prev.set_type(TntHopType.EXP)

    # trigger 3
    def process_qttl(self, prev, prev2):
        # flag the hop
        self.set_type(TntHopType.INTERN | TntHopType.IMP_QT)

        # identify the entry of the tunnel
        if self.icmp_q_ttl != 2:
            return

        # First LSR
        if (prev is not None and prev.icmp_q_ttl <= 1 and
            not prev.is_intern() and not prev.is_opa_egr()):
            # Flag the first LSR
            prev.clear_type_lsr()
            prev.set_type(TntHopType.INTERN | TntHopType.IMP_QT)
        elif (prev is None and prev2 is not None and
              not prev2.is_intern() and not prev2.is_ingr() and
              (not prev2.is_egr() or prev2.is_juniper_imp())):
            # ingress hop
            prev2.clear_types()
            prev2.set_type(TntHopType.INTERN | TntHopType.IMP_QT)
            prev2.set_type(TntHopType.INGR)

    def process_egr(self, prev, prev2, dst):
        if prev is not None:
            # previous hop must be an LSR
            if not prev.is_intern():
                return

            if prev.is_exp():
                self.set_type(TntHopType.EGR | TntHopType.EXP)
            elif prev.is_imp():
                # for implicit tunnels, egress is one hop after qTTL <= 1
                self.set_type(TntHopType.IMP_QT)
                if (self.src == dst or
                    (prev.icmp_q_ttl <= 1 and prev.src != self.src)):
                    self.set_type(TntHopType.EGR)
                else:
                    self.set_type(TntHopType.INTERN)
            elif prev.is_opa():
                prev.clear_type_lsr()
                prev.set_type(TntHopType.EGR)
        elif prev2 is not None and prev2.is_imp() and prev2.icmp_q_ttl > 1:
            self.set_type(TntHopType.EGR | TntHopType.IMP_QT)

class TntTrace:
    def __init__(self, trace: ScamperTrace):
        self._trace = trace
        self._hops = [None] * trace.hop_count
        self._tests = []
        self._waiting = 0
        self._identify_called = False
        self._userid = trace.userid
        for i, hop in enumerate(trace.hops()):
            if hop is not None:
                self._hops[i] = TntHop(hop, self)

    def __str__(self):
        txt = "trace from " + str(self.src) + " to " + str(self.dst) + "\n"
        for i in range(self.firsthop-1, self.hop_count):
            hop = self.hop(i)
            next_hop = self.hop(i+1)

            # print out regular traceroute hop
            txt += ((f"{i+1:3} ") + ("*" if hop is None else str(hop)) + "\n")

            # print out inferred tunnel hops if there are hops to print
            if hop is None or next_hop is None:
                continue
            tun = Tunnel(hop.src, next_hop.src)
            if tun not in tunnels:
                continue
            tun = tunnels[tun]
            for j, lsr in enumerate(tun._lsp):
                txt += ("%3s " % (f"H{j+1}"))
                txt += ("*" if lsr is None else str(lsr)) + "\n"
        return txt

    # get list of unique addresses observed in the traceroute
    def addrs(self):
        addrs = {}
        for hop in self._trace.hops():
            if hop is not None:
                addrs[hop.src] = 1
        return addrs.keys()

    # get the first hop probed in the traceroute
    @property
    def firsthop(self):
        return self._trace.firsthop

    # get the maximum TTL probed
    @property
    def hop_count(self):
        return len(self._hops)

    @property
    def src(self):
        return self._trace.src

    @property
    def dst(self):
        return self._trace.dst

    @property
    def userid(self):
        return self._userid
    
    # def set_userid(self, u):
    #     self.userid

    # get the hop for a given TTL
    def hop(self, i):
        if i < 0 or i >= len(self._hops):
            return None
        return self._hops[i]

    # return observed hops
    @property
    def hops(self):
        return self._hops

    # queue an invisible/opaque tunnel test for a TNT test
    def tunnel_test_add(self, start_addr, next_addr, start_ttl, trigger_type,
                        userid, ingress_status, queue):
        tunnel_test = TunnelTest(start_addr, next_addr, next_addr,
                                 trigger_type, userid, ingress_status)
        self._tests.append(tunnel_test)
        if queue is not None:
            test = Test("trace", next_addr)
            test.start_ttl = start_ttl
            test.userid = userid
            queue.append(test)

    def can_identify(self):
        return self._waiting == 0 and self._identify_called is False

    # identify MPLS tunnels and LSRs, if explicit, implicit, or opaque
    def identify(self, queue):
        self._identify_called = True
        if str(self.dst) == '213.155.141.54':
            print('Hi')

        for i in range(self._trace.firsthop-1, self._trace.hop_count):
            hop = self.hop(i)
            prev_hop = self.hop(i-1)
            prev2_hop = self.hop(i-2)

            # get hop if any response
            if hop is None:
                # check if previous hop is not opaque
                if prev_hop is not None and prev_hop.is_opa():
                    prev_hop.clear_type_lsr()
                    prev_hop.set_type(TntHopType.EGR)
                continue

            # if str(self.dst) == '167.124.77.124' and str(hop.src) == '168.209.160.109':
            #     print(hop.is_ttl_exp())

            if hop.is_ttl_exp():
                if hop.icmpext is not None:
                    mplsext = hop.icmpext.mpls
                    if mplsext is not None and mplsext.mpls_count > 0:
                        # trigger 1/2: use mplsext included in response
                        hop.process_mplsext(prev_hop)
                        continue

                if hop.icmp_q_ttl > 1 and hop.icmp_q_ttl != 255:
                    # trigger 3: q-TTL > 1 -> Implicit
                    hop.process_qttl(prev_hop, prev2_hop)
                    continue

            # identify egress hops for explicit, implicit, and opaque tunnels
            hop.process_egr(prev_hop, prev2_hop, self._trace.dst)

        # special loop for invisible tunnels, mandatory due to
        # potential overlap with implicit tunnels
        for i in range(self._trace.firsthop-1, self._trace.hop_count):
            hop = self.hop(i)
            prev_hop = self.hop(i-1)

            # get hop if any public response, not involved in another tunnel
            if hop is None or hop.src.is_reserved() or hop.is_intern():
                continue

            # duplicate IP address
            if prev_hop is not None and prev_hop.src == hop.src:
                # first IP is already tagged for another tunnel
                if prev_hop.is_egr() or prev_hop.is_intern():
                    continue
                ingress_hop = self.hop(i-2)
                start_hop = self.hop(i-3)
            else:
                ingress_hop = prev_hop
                start_hop = self.hop(i-2)

            # ingress cannot be inside an implicit or explicit tunnel
            if (ingress_hop is not None and not hop.is_opa() and
                ingress_hop.is_intern()):
                continue

            # get the start and ingress hops
            if ingress_hop is None:
                if start_hop is None or start_hop.src.is_reserved():
                    continue
                start_addr = start_hop.src
                ingress_status = IngressStatus.NULL
                tmp_hop = start_hop
            else:
                if ingress_hop.src.is_reserved():
                    continue
                start_addr = ingress_hop.src
                ingress_status = IngressStatus.START
                tmp_hop = ingress_hop

            # get the probing start TTL
            if tmp_hop.probe_ttl > 2:
                start_ttl = tmp_hop.probe_ttl - 2
            else:
                start_ttl = 1

            # ingress and egress are the same router
            if start_addr == hop.src:
                continue

            # an opaque tunnel is found
            if hop.is_opa_egr():
                self.tunnel_test_add(start_addr, hop.src, start_ttl,
                                     Trigger.MTTL, self._userid,
                                     ingress_status, queue)
                continue

            # Egress can not be already an egress for another tunnel
	    # Triggers are computed on time-exceeded messages
            if hop.is_egr() or not hop.is_ttl_exp():
                continue

            # Trigger 4: Duplicate IP address -> Invisible, UHP
            if prev_hop is not None and prev_hop.src == hop.src:
                self.tunnel_test_add(start_addr, hop.src, start_ttl,
                                     Trigger.DUP_IP, self._userid,
                                     ingress_status, queue)
                continue

            # test if potential egress is not a duplicate IP
            tmp_hop = self.hop(i+1)
            if (tmp_hop is not None and tmp_hop.is_ttl_exp() and
                tmp_hop.src == hop.src):
                continue

            # Trigger 5: RTLA -> Invisible
            if hop.rtla() >= 1:
                self.tunnel_test_add(start_addr, hop.src, start_ttl,
                                     Trigger.RTLA, self._userid,
                                     ingress_status, queue)
                continue

            # Trigger 6: FRPLA -> Invisible
            if hop.frpla() >= 3:
                self.tunnel_test_add(start_addr, hop.src, start_ttl,
                                     Trigger.FRPLA, self._userid,
                                     ingress_status, queue)
                continue

    def find_test(self, target_addr):
        if not isinstance(target_addr, ScamperAddr):
            raise ValueError("invalid target_addr")
        for test in self._tests:
            if test._target_addr == target_addr:
                return test
        return None

    def process_trace(self, trace, pings, queue):
        try:
        # check if the target was reached
            tunt = self.find_test(trace.dst)
            if (tunt is None or
                trace.hop(trace.hop_count-1) is None or
                trace.hop(trace.hop_count-1).src != tunt._target_addr):
                return
        except Exception as e:
            return

        start_hop = None
        for i in range(trace.firsthop-1, trace.hop_count):
            hop = trace.hop(i)
            nxthop = trace.hop(i+1)
            if hop is not None and hop.src == tunt._start_addr:
                start_hop = i
                if nxthop is not None and nxthop.src == tunt._start_addr:
                    start_hop = i+1
                break

        # the end of the trace is reached, the ingress was not found
        if start_hop is None:
            return

        # check if the start address is the ingress address
        if tunt._ingress_status == IngressStatus.NULL:
            start_hop += 1

        # the next hop is the target, no LSR was revealed
        if start_hop >= trace.hop_count - 2:
            return

        # push the new LSRs in the list, in reverse order
        lsrs = []
        for i in range(start_hop+1, trace.hop_count-1):
            hop = trace.hop(i)
            if hop is not None:
                hop = TntHop(hop, self)
            lsrs.insert(0, hop)

        # check if BRPR or DPR step
        nlsrs = len(lsrs)
        # if str(self.dst) == '62.253.218.63':
        #     print(f'found {nlsrs} lsrs')
        if nlsrs == 1:
            tunt._rev_mode = RevMode.BRPR
        elif nlsrs > 2:
            tunt._rev_mode = RevMode.DPR
        else:
            tunt._rev_mode = RevMode.DPR
            if(lsrs[0] is not None and lsrs[1] is not None and
               lsrs[0].src == lsrs[1].src):
                tunt._rev_mode = RevMode.BRPR

        # if str(self.dst) == '62.253.218.63':
        #     print(f'tunnel start: {tunt._start_addr}, tunnel end: {tunt._next_addr}')

        tun = Tunnel(tunt._start_addr, tunt._next_addr)
        if tun not in tunnels:
            tunnels[tun] = tun
        else:
            tun = tunnels[tun]
        tun.add(lsrs)
        # if str(tunt._start_addr) == '212.187.174.237' and str(tunt._next_addr) == '171.75.9.213':
        #     print(f'added {nlsrs} to tunnel, new length: {len(tun)}')
        

        # Update ingress/egress/LH MPLS flags
        for j in range(self.firsthop-1, self.hop_count):
            ing = self.hop(j)
            egr = self.hop(j+1)
            if ing is None or egr is None:
                continue
            if ing.src != tunt._start_addr or egr.src != tunt._next_addr:
                continue
            ing.mpls_disc_trigger_set(tunt)
            ing.mpls_type_trigger_set(tunt)
            ing.set_type(TntHopType.INGR)
            egr.mpls_disc_trigger_set(tunt)
            egr.mpls_type_trigger_set(tunt)
            egr.set_type(TntHopType.EGR)
            break

        # update the MPLS flags of an LSR depending on the tunnel test state
        for hop in lsrs:
            if hop is not None:
                hop.mpls_flags_set(tunt)

        # schedule pings to the hops that are part of this LSP
        process_hops_pings(lsrs, pings, queue)

        return

class TntTests:
    def __init__(self):
        self._tests = {}

    def add(self, trace: TntTrace):
        self._tests[trace.userid] = trace

    def get(self, userid):
        if userid not in self._tests:
            return None
        return self._tests[userid]

    def tests(self):
        userids = {}
        for userid in self._tests:
            userids[userid] = 1
        for userid in sorted(userids.keys()):
            yield self._tests[userid]

    def __len__(self):
        return len(self._tests)

@staticmethod
def is_reserved(addr):
    ip = ip_address(addr)
    for pref in reserved_prefixes:
        if ip in pref:
            return True
    return False

def dump_trace(trace):
    txt = "trace [icmp-paris] from " + trace['src'] + " to " + str(trace['dst']) + "\n"
    curr = 1
    inv = 0
    total = 0
    total_inv = 0
    prev_found = False
    if 'hops' not in trace:
        return
    
    for hop in trace['hops']:
        # hop = self.hop(i)
        # next_hop = self.hop(i+1)
        probe_ttl = hop['probe_ttl']
        # print(f'Probe TTL: {probe_ttl}, curr: {curr}')
        hop_types_mflag = hop['hop_types_mflags']
        hop_fail_mflags = hop['hop_fail_mflags']
        hop_disc_mflags = hop['hop_disc_mflags']
        hop_mpls_iteration = hop['hop_mpls_iteration']

        #Fill in missing hops
        for i in range(curr,probe_ttl):
            # print(i)
            if inv == 0:
                txt += (f"{i:3} *\n")
                if prev_found:
                    inv+=1
                    prev_found = False
            else:
                
                # txt += (f"H{inv:3} *\n")
                txt += ("%3s *\n" % (f"H{inv}"))
                inv += 1
                total_inv += 1
            curr += 1
            total += 1
        # print(f'Probe TTL: {probe_ttl}, curr: {curr}')
        if hop_disc_mflags & 0x0100:
            if inv == 0:
                inv += 1
            
            # line = f"H{inv:3} "
            line = ("%3s " % (f"H{inv}"))
            inv += 1
            total_inv += 1
        else:
            if hop_disc_mflags & 0x0200:
                prev_found = True
            if ((hop_types_mflag & 0x80) and (not (hop_types_mflag & 0x04) or not(hop_types_mflag & 0x10 or hop_types_mflag & 0x20)) and (not(hop_types_mflag & 0x02) or inv == 0)):
                inv += 1
            else:
                inv = 0
            line = f"{probe_ttl:3} "
        curr += 1
        total += 1
        # print(f'Probe TTL: {probe_ttl}, curr: {curr}')
        
        line += f"{hop['addr']:<15} {float(hop['rtt']):.3f} ms"
        hop_reply_ttl = hop['reply_ttl']
        ping_ttl = hop['hop_ping_rttl']
        if is_reserved(hop['addr']):
            line += " rsvd rTTLs=<" + str(hop_reply_ttl) + ",*>"
        else:
            if ping_ttl == 0:
                line += " rTTLs=<" + str(hop_reply_ttl) + ",*>"
            else:
                line += " rTTLs=<" + str(hop_reply_ttl) + "," + str(ping_ttl) + ">"
        
        reply_ittl = ittl(hop_reply_ttl)
        ping_ittl = ittl(ping_ttl)

        uturn = (reply_ittl - hop_reply_ttl + 1) - (ping_ittl - ping_ttl + 1) if ping_ttl != 0 else 0
        frpla = (reply_ittl - hop_reply_ttl + 1) - probe_ttl
        rtla = (reply_ittl - hop_reply_ttl + 1) - (ping_ittl - ping_ttl + 1) if reply_ittl == 255 and ping_ittl != 255 else 0 
        if hop['icmp_type'] == 11 and hop['icmp_code'] == 0:
            line += " qttl=" + str(hop['icmp_q_ttl'])
            line += (" uturn=" + str(uturn)) if uturn != 0 else ""
            line += (" frpla=" + str(frpla)) if  frpla > 0 else ""
            line += (" rtla=" + str(rtla)) if rtla > 0 else ""
        


        if hop_types_mflag & 0x01 or hop_types_mflag & 0x02 or hop_types_mflag & 0x04:
            line += " [MPLS" 

            #Not internal
            if not hop_types_mflag & 0x04:
                line += ",EXP" if hop_types_mflag & 0x08 else ""
                line += ",OPA" if hop_types_mflag & 0x40 else ""
                line += ",IMP" if hop_types_mflag & 0x10 or hop_types_mflag & 0x20 else ""
                line += ",INV" if hop_types_mflag & 0x80 else ""
            else:
                if hop_types_mflag & 0x10 or hop_types_mflag & 0x20:
                    line += ",IMP"
                elif hop_types_mflag & 0x40:
                    line += ",OPA" 
                elif hop_types_mflag & 0x08:
                    line += ",EXP" 
                elif hop_types_mflag & 0x80:
                    line += ",INV" 
                line += ",LSR"

            line += ",EGR" if hop_types_mflag & 0x02 else ""
            line += ",ING" if hop_types_mflag & 0x01 else ""


            line += ",INCOMP?" if hop_disc_mflags & 0x0080 else ""

            if (hop_disc_mflags & 0x0000f == 0) and (hop_types_mflag & 0x80):
                line += ",BRTF"
            else:
                if hop_disc_mflags & 0x0004:
                    line += ",DUPIP"
                if hop_disc_mflags & 0x0002:
                    line += ",RTLA"
                if hop_disc_mflags & 0x0001:
                    line += ",FRPLA"
                if hop_disc_mflags & 0x0008:
                    line += ",MTTL"
                


            # line += ",INF" if hop_types_mflag & 0xf8 and hop_types_mflag & 0x04
            if ((hop_types_mflag & 0xf8) == 0) and (hop_types_mflag & 0x04):
                line += ",INF"
            else:
                if hop_types_mflag & 0x10:
                    line += ",QTTL"
                if hop_types_mflag & 0x20:
                    line += ",UTURN"
            
            if hop_disc_mflags & 0x0100:
                if hop_disc_mflags & 0x0010:
                    line += ",DPR"
                elif hop_disc_mflags & 0x0020:
                    line += ",BRPR"
                elif hop_disc_mflags & 0x0040:
                    line += ",BUD"
                else:
                    line += ",UNKN"
                line += (f",step={hop_mpls_iteration}")
            line += "]"

        if "icmpext" in hop:
            ie = hop['icmpext'][0]
            # print(ie)
            if 'mpls_labels' in ie:
                labels = ie['mpls_labels']
                mc = len(labels)
                line += f" Labels {labels[0]['mpls_label']} mTTL={labels[0]['mpls_ttl']}"
                for i in range(1,mc):
                    ext = labels[i]
                    line += f" | {ext['mpls_label']} mTTL={ext['mpls_ttl']}"

        line += "\n"
        txt += line
    
    for i in range(total+1, trace['hop_count']+1):
        hopnum = i - total_inv
        txt += f"{hopnum:3} *\n"
        
    print(txt)


def run_initial_traces(addresses,tnts,pings,queue,ctrl,out):
    traces = []
    for i in range(len(addresses)):

        ### START OPT

        ctrl.do_trace(addresses[i], wait_timeout=1, attempts=2,
                          userid=i, sync=False)
    print('Waiting for traces')    
    # queue = []
    for o in ctrl.responses():
        out.write(o)
        trace = TntTrace(o)
        tnts.add(trace)
        process_hops_pings(trace.hops, pings, queue)
        traces.append(trace)
    return traces

def run_pings(pings,queue, ctrl, out):
    process_queue(queue, ctrl)
    for o in ctrl.responses():
        out.write(o)
        pings.process(o)
        for hop in pings.blocked(o.dst):
            hop.process_ping(pings.get_rttl(o.dst))

def find_next_traces(traces):
    queue = []
    for i in range(len(traces)):
        trace = traces[i]
        to_trace = []
        # once we have all the pings, infer tunnels, which can cause
        # a series of subsequent pings and traceroutes
        trace.identify(to_trace)
        #associate traces with original trace
        # for t in to_trace:
        #     dst = t.dst
        #     if dst in testmap:
        #         testmap[dst].append(i)
        #     else:
        #         testmap[dst] = [i]
        # print(f'Trace userid: {trace.userid} with destination {trace.dst} sending {len(to_trace)} traces: ')
        for test in to_trace:
            assert test.userid == trace.userid
            # print(f'\ttest dst: {test.dst}')
        # print(to_trace)
        for t in to_trace:
            if t not in queue:
                queue.append(t)
    return queue

def run_extra_traces(queue,ctrl,out,testmap,traces,pings):
    process_queue(queue, ctrl)

    for o in ctrl.responses():
        out.write(o)
        if isinstance(o, ScamperTrace):
            #Get trace from trace destination
            idx = testmap[o.dst]
            for i in idx:
                trace = traces[i]
                trace.process_trace(o, pings, queue)
                process_queue(queue, ctrl)
        elif isinstance(o, ScamperPing):
            pings.process(o)
            for hop in pings.blocked(o.dst):
                hop.process_ping(pings.get_rttl(o.dst))


def _feedme(ctrl, inst, vps):
#   print(f'inst: {inst.shortname}, # tests: {len(vps[inst])}')
  if len(vps[inst]) == 0:
    inst.done()
  else:
    test = vps[inst].pop(0)
    # print('Sending')
    if test.method == 'trace':
        ctrl.do_trace(test.dst, firsthop=test.start_ttl, wait_timeout=1,wait_probe=timedelta(milliseconds=50),
                          userid=test.userid, attempts=3,method='icmp-paris',inst=inst)
    elif test.method == 'ping':
        ctrl.do_ping(test.dst,inst=inst,attempts=1,wait_probe=0.2,wait_timeout=0.5)

@staticmethod
def main() -> int:
    tnts = TntTests()
    pings = PingTests()

    parser = argparse.ArgumentParser()
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-f','--file', help='Warts file to read')
    group1.add_argument('-u','--unix', help='Scamper unix socket to use')
    group1.add_argument('-m','--mux', help='Scamper Mux to use')
    group1.add_argument('-d','--dump',help='Dump JSON output from old TNT')
    parser.add_argument('-i','--ip', help='IP address to trace')
    parser.add_argument('-a','--addresses',help='File of IP addresses to probe')
    group1.add_argument('-p', '--port', help='Local Scamper port')
    parser.add_argument('-o','--out',default='tnt.warts')
    parser.add_argument('-s','--seed')
    # parser.add_argument('-n','--noprobe',action='store_true')
    args = parser.parse_args()

    # if len(sys.argv) != 3:
    #     print("usage: tnt.py $socket $ip")
    #     return -1


    try:
        # if args.unix is not None:
        #     statinfo = os.stat(args.unix)
        #     if stat.S_ISSOCK(statinfo.st_mode):
        #         ctrl = ScamperCtrl(unix=args.unix)
        #         out = ScamperFile(args.out, 'w')
        #         inf = None
        if args.mux is not None:
            statinfo = os.stat(args.mux)
            if stat.S_ISSOCK(statinfo.st_mode):
                mux = args.mux
                # ctrl.add_vps(ctrl.vps())
                inf = None
            else:
                print('Error: provided MUX is not a socket')
                return -1
        elif args.port is not None:
            ctrl = ScamperCtrl()
            ctrl.add_inet(port=int(args.port))
            out = ScamperFile(args.out, 'w')
            inf = None
        elif args.file is not None:
            inf = ScamperFile(args.file)
            inf.filter_types(ScamperTrace, ScamperPing)
        elif args.dump is not None:
            inf = open(args.dump, 'r')
            for line in inf:
                o = json.loads(line)
                if o['type'] == 'trace':
                    dump_trace(o)
            return 0
    except RuntimeError as e:
        print(e)
        return -1

    if inf is not None:
        ctr = 0
        extra = False
        needed = {}
        for o in inf:
            if isinstance(o, ScamperTrace):
                if not extra:
                    trace = TntTrace(o)
                    trace._userid = ctr
                    ctr+=1
                    tnts.add(trace)
                    queue = []
                    trace.identify(queue)
                    for test in queue:
                        dst = str(test.dst)
                        if dst not in needed:
                            needed[dst] = []
                        needed[dst].append(trace)
                    process_hops_pings(trace.hops, pings, None)
                else:
                    if str(o.dst) in needed:
                        for t in needed[str(o.dst)]:
                            t.process_trace(o,pings,None)
            elif isinstance(o, ScamperPing):
                extra = True
                pings.process(o)
                for hop in pings.blocked(o.dst):
                    hop.process_ping(pings.get_rttl(o.dst))
                    if hop._trace is not None and hop._trace.can_identify():
                        hop._trace.identify(None)
        
        inf.close()
        bn = os.path.basename(args.file)
        bn = bn.split('.')[0]
        bn = f'{bn}-tnt.txt'
        with open(bn,'w+') as f:
            for trace in tnts.tests():
                f.write(str(trace))

    elif args.seed:
        print('Starting')
        
        files = []
        with open(args.seed,'r') as f:
            for line in f:
                files.append(line.strip())
       
        outmap = {}
        probed = set()
        ctr=0
        print('Building maps')
        init_time = time.perf_counter()
        for file in files:
            try:
                f = ScamperFile(file)
                f.filter_types(ScamperTrace,ScamperPing)
                for o in f:
                    if isinstance(o,ScamperTrace):
                        vp = o.list.monitor.split('.')[0]
                    
                        if vp not in outmap:
                            outmap[vp] = ScamperFile(f'{vp}.warts.gz','w')
                        
                        t = TntTrace(o)
                        t._userid = ctr
                        ctr+=1
                        tnts.add(t)
                        outmap[vp].write(o)
                
                    elif isinstance(o,ScamperPing):
                        vp = o.list.monitor.split('.')[0]
                        
                        if vp not in outmap:
                            outmap[vp] = ScamperFile(f'{vp}.warts.gz','w')
                        pings.process(o)
                        probed.add(o.dst)
                        outmap[vp].write(o)
                        for hop in pings.blocked(o.dst):
                            hop.process_ping(pings.get_rttl(o.dst))
                           
            except Exception as e:
                continue
        second_time = time.perf_counter()
        print(f'Built maps in {second_time - init_time} seconds')

        print('Finding and sending pings')
        npings = 0
        
        queuemap = {}
        for t in tnts.tests():
            queue = []
            vp = t._trace.list.monitor.split('.')[0]
            process_hops_pings(t.hops,pings,queue,probed)
            if vp not in queuemap:
                queuemap[vp] = []
            queuemap[vp].extend(queue)
            
            # feedmap[instmap[vp]].extend(queue)
            # process_queue(queue,ctrl,instmap[vp])
        feedmap = {}
        ctrl = ScamperCtrl(mux=args.mux,morecb=_feedme,param=feedmap)
        ctrl.add_vps(ctrl.vps())
        instmap = {}
        instances = ctrl.instances()
        for inst in instances:
            #print(inst.shortname)
            instmap[inst.shortname] = inst
            if inst.shortname in queuemap:
                feedmap[inst] = queuemap[inst.shortname]
                npings += len(queuemap[inst.shortname])
        print(f'The mux has {len(instmap)} vps')




        third_time = time.perf_counter()
        print(f'Sent {npings} pings in {third_time-second_time} seconds')
        npings = 0
        while not ctrl.is_done():
            o = None
            try:
                o=ctrl.poll(timeout=timedelta(seconds=10))
            except Exception as e:
                # print(f'Caught Exception: {e}')
                continue
                
            if o is None:
                if ctrl.is_done():
                    print('Done sending pings')
                else:
                    print('Timed out')
                break
            if isinstance(o,ScamperPing):
                npings += 1
                vp = o.list.monitor.split('.')[0]
                outmap[vp].write(o)
                pings.process(o)
                for hop in pings.blocked(o.dst):
                    hop.process_ping(pings.get_rttl(o.dst))
        
        fourth_time = time.perf_counter()
        print(f'Processed {npings} pings in {fourth_time-third_time} seconds, sending next traces')
        # Reconnect to the mux
        ntraces = 0
        queuemap = {}
        
        testmap = {}

        for t in tnts.tests():
            vp = t._trace.list.monitor.split('.')[0]
            if vp not in instmap:
                continue
            queue = find_next_traces([t])
            if vp not in queuemap:
                queuemap[vp] = []
            queuemap[vp].extend(queue)

        feedmap = {}
        ctrl = ScamperCtrl(mux=args.mux,morecb=_feedme,param=feedmap)
        ctrl.add_vps(ctrl.vps())
        instmap = {}
        instances = ctrl.instances()
        for inst in instances:
            instmap[inst.shortname] = inst
            if inst.shortname in queuemap:
                feedmap[inst] = queuemap[inst.shortname]
                ntraces += len(queuemap[inst.shortname])

        fifth_time = time.perf_counter()
        print(f'Sent {ntraces} traces in {fifth_time-fourth_time} seconds')
    
        while not ctrl.is_done():
            o = None
            try:
                o=ctrl.poll(timeout=timedelta(seconds=30))
            except Exception as e:
                # print(f'Caught Exception: {e}')
                # print(e.with_traceback())
                continue
                
            if o is None:
                if ctrl.is_done():
                    print('Done sending traces')
                else:
                    print('Timed out')
                break
            vp = o.list.monitor.split('.')[0]
            outmap[vp].write(o)
            if isinstance(o,ScamperPing):
                pings.process(o)
                for hop in pings.blocked(o.dst):
                    hop.process_ping(pings.get_rttl(o.dst))
            elif isinstance(o,ScamperTrace):
                queue = []
                t = tnts.get(o.userid)
            
                if t == None:
                    continue
                t.process_trace(o,pings,queue)
                feedmap[instmap[vp]].extend(queue)
                
        sixth_time = time.perf_counter()
        print(f'Processed extra traces in {sixth_time-fifth_time} seconds')
        print(f'Found {len(tunnels)} tunnels')
        for vp in outmap:
            outmap[vp].close()
        outmap = {}
                    

        for t in tnts.tests():
            vp = t._trace.list.monitor
            if vp not in outmap:
                out = open(f'{vp}-tnt.txt','w+')
                outmap[vp] = out
            outmap[vp].write(str(t))

        for vp in outmap:
            outmap[vp].close()
        
    else:
        # do the initial traceroute
        addresses = []
        if args.ip:
            addresses.append(args.ip)
        elif args.addresses:
            with open(args.addresses,'r') as f:
                for line in f:
                    addresses.append(line.strip())

        init_time = time.perf_counter()
        for i in range(len(addresses)):

            # queue = []
            # o = ctrl.do_trace(addresses[i], wait_timeout=1, attempts=2,
            #                 userid=i, sync=True)
            # out.write(o)
            # trace = TntTrace(o)
            # tnts.add(trace)
            # process_hops_pings(trace.hops, pings, queue)

            # # figure out the unique addresses to send followup pings to
            # process_queue(queue, ctrl)
            # for o in ctrl.responses():
            #     out.write(o)
            #     pings.process(o)
            #     for hop in pings.blocked(o.dst):
            #         hop.process_ping(pings.get_rttl(o.dst))

            # # once we have all the pings, infer tunnels, which can cause
            # # a series of subsequent pings and traceroutes
            # trace.identify(queue)
            # process_queue(queue, ctrl)

            # for o in ctrl.responses():
            #     out.write(o)
            #     if isinstance(o, ScamperTrace):
            #         print('EXTRA TRACE: ')
            #         print(str(TntTrace(o)))
            #         print('------------------------')
            #         trace.process_trace(o, pings, queue)
            #         process_queue(queue, ctrl)
            #     elif isinstance(o, ScamperPing):
            #         pings.process(o)
            #         for hop in pings.blocked(o.dst):
            #             hop.process_ping(pings.get_rttl(o.dst))

        ### START OPT

            ctrl.do_trace(addresses[i], wait_timeout=1, attempts=2,
                          userid=i, sync=False)
        print('Waiting for traces')    
        traces = []
        queue = []
        for o in ctrl.responses():
            out.write(o)
            trace = TntTrace(o)
            tnts.add(trace)
            process_hops_pings(trace.hops, pings, queue)
            traces.append(trace)
        # queue = []
        # traces = run_initial_traces(addresses,tnts,pings,queue,ctrl,out)

        second_time = time.perf_counter()
        print(f'{len(traces)} Initial traceroutes conducted in {int(second_time-init_time)} seconds')

        print(f'Conducting {len(queue)} pings')
        # process_queue(queue, ctrl)
        # for o in ctrl.responses():
        #     out.write(o)
        #     pings.process(o)
        #     for hop in pings.blocked(o.dst):
        #         hop.process_ping(pings.get_rttl(o.dst))
        run_pings(pings,queue, ctrl, out)

        third_time = time.perf_counter()
        print(f'Pings conducted in {int(third_time-second_time)} seconds')

        queue = []
        testmap = {}
        # for i in range(len(traces)):
        #     trace = traces[i]
        #     to_trace = []
        #     # once we have all the pings, infer tunnels, which can cause
        #     # a series of subsequent pings and traceroutes
        #     trace.identify(to_trace)
        #     #associate traces with original trace
        #     for t in to_trace:
        #         dst = t.dst
        #         if dst in testmap:
        #             testmap[dst].append(i)
        #         else:
        #             testmap[dst] = [i]
        #     for t in to_trace:
        #         if t not in queue:
        #             queue.append(t)
        #     queue.extend(to_trace)
        queue = find_next_traces(traces,testmap)
        print(f'Conducting {len(queue)} additional traceroutes')
        process_queue(queue, ctrl)

        # for o in ctrl.responses():
        #     out.write(o)
        #     if isinstance(o, ScamperTrace):
        #         #Get trace from trace destination
        #         idx = testmap[o.dst]
        #         for i in idx:
        #             trace = traces[i]
        #             trace.process_trace(o, pings, queue)
        #             process_queue(queue, ctrl)
        #     elif isinstance(o, ScamperPing):
        #         pings.process(o)
        #         for hop in pings.blocked(o.dst):
        #             hop.process_ping(pings.get_rttl(o.dst))
        run_extra_traces(queue,ctrl,out,testmap,traces,pings)

        fourth_time = time.perf_counter()
        print(f'Followup probing conducted in {int(fourth_time-third_time)} seconds')


        ### END OPT



        # init_time = time.perf_counter()

        # initial_traces = []
        # for i in range(len(addresses)):
        #     ctrl.do_trace(addresses[i], wait_timeout=1, attempts=2,
        #                     userid=i, sync=False,method='icmp-paris')

        # # for o in ctrl.responses():
        # #     initial_traces.append(TntTrace(o))

        # npings = 0
        # for o in ctrl.responses():
        #     queue = []
        #     out.write(o)
        #     if isinstance(o,ScamperTrace):
        #         trace = TntTrace(o)
        #         tnts.add(trace)
        #         process_hops_pings(trace.hops, pings, queue)
        #         process_queue(queue, ctrl)
        #         initial_traces.append(TntTrace(o))
        #     elif isinstance(o,ScamperPing):
        #         pings.process(o)
        #         npings += 1
        #         for hop in pings.blocked(o.dst):
        #             hop.process_ping(pings.get_rttl(o.dst))

        # second_time = time.perf_counter()
        # print(f'Ran initial traceroutes in {second_time-init_time} seconds')
        # print(f'Have {len(initial_traces)} traces to check, processed {npings} pings')
        
        # for trace in initial_traces:
        #     queue = []
        #     # o = ctrl.do_trace(addresses[i], wait_timeout=1, attempts=2,
        #     #                 userid=i, sync=True,method='icmp-paris')
        #     # out.write(o)
        #     # trace = TntTrace(o)
        #     # tnts.add(trace)
        #     # process_hops_pings(trace.hops, pings, queue)

        #     # # figure out the unique addresses to send followup pings to
        #     # process_queue(queue, ctrl)
        #     # for o in ctrl.responses():
        #     #     out.write(o)
        #     #     pings.process(o)
        #     #     for hop in pings.blocked(o.dst):
        #     #         hop.process_ping(pings.get_rttl(o.dst))

        #     # once we have all the pings, infer tunnels, which can cause
        #     # a series of subsequent pings and traceroutes
        #     print(trace.can_identify())
        #     trace.identify(queue)
        #     process_queue(queue, ctrl)

        #     for o in ctrl.responses():
        #         out.write(o)
        #         if isinstance(o, ScamperTrace):
        #             trace.process_trace(o, pings, queue)
        #             process_queue(queue, ctrl)
        #         elif isinstance(o, ScamperPing):
        #             pings.process(o)
        #             for hop in pings.blocked(o.dst):
        #                 hop.process_ping(pings.get_rttl(o.dst))
        out.close()
        
    # print(f'Identified {len(tnts)} traces')
    # for trace in tnts.tests():
    #    print(str(trace))

    return 0

if __name__ == "__main__":
    sys.exit(main())
