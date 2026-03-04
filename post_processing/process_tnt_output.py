import argparse
import json
from multiprocessing import Pool
import sys
import bz2
from pb_amarder import Progress

class Hop:

    def __init__(self,addr,labels=[]):
        self.addr = addr

class Tunnel:

    def __init__(self, type, ingress=None, egress=None):
        self.type = type
        self.egress = {}
        self.ingress = {}
        self.lsrs = []
        self.filename = ''

    def add_ing(self,addr,tags=[]):
        self.ingress['addr'] = addr
        if len(tags) > 0:
            self.ingress['tags'] = tags
         

    def add_egr(self,addr,tags=[]):
        self.egress['addr'] = addr
        if len(tags) > 0:
            self.egress['tags'] = tags

    def add_lsr(self,addr,tags=[]):
        lsr = {}
        lsr['addr'] = addr
        lsr['tags'] = tags
        self.lsrs.append(lsr)

    def __eq__(self,other):
        if not isinstance(other,Tunnel):
            return False
        return (self.ingress == other.ingress) and (self.egress == other.egress) and (self.type == other.type)
        
    def __hash__(self):
        return hash((self.type,json.dumps(self.ingress),json.dumps(self.egress),json.dumps(self.lsrs)))
    
    def to_dict(self):
        d = {}
        d['ingress'] = self.ingress
        d['egress'] = self.egress
        d['lsrs'] = self.lsrs
        d['type'] = self.type
        d['source file'] = self.filename
        return d

    def add_filename(self,filename):
        self.filename = filename
        

def process_trace(trace):
    tunnels = set()
    if len(trace) == 0:
        return tunnels
    info = trace[0]
    hops = trace[1:]
    # hops = [h for h in hops if '*' not in h]
    if len(hops) == 0:
        return tunnels
    info = info.split()
    src = info[2]
    dst = info[4]

    revealed = []
    t = None
    for hop in hops:
        if hop.startswith('H'):
            revealed += hop
        fields = hop.split()
        if len(fields) == 2 and fields[1] == '*':
            continue
        tags = []
        for field in fields: 
            if field[0] == '[' and field[-1] == ']' and 'MPLS' in field:
                tags = field
                tags = tags[1:-1]
                tags = tags.split(',')
                # print(tags)
            #MPLS tag
        if len(tags) == 0:
            #No MPLS :(
            continue
        addr = fields[1]
        tunnel_type = tags[1]
        router_type = tags[2]
        if router_type == 'ING':
            if t != None:
                # Missing previous tunnel's egress
                tunnels.add(t)
            t = Tunnel(tunnel_type)
            t.add_ing(addr, tags[3:])
        elif router_type == 'EGR':
            if t == None:
                t = Tunnel(tunnel_type)
            t.add_egr(addr,tags[3:])
            tunnels.add(t)
            t = None
        elif router_type == 'LSR':
            # Missing this tunnel's ingress
            if t == None:
                t = Tunnel(tunnel_type)
            t.add_lsr(addr,tags[3:])
    if t != None:
        tunnels.add(t)

    return tunnels
        
    


def process_file(fname):
    # print(fname)
    if len(fname.strip()) == '':
        return set(),0
    trace = []
    tc = 0
    tunnels = set()
    if usebz2:
        try:
            with bz2.open(fname,'rt') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('trace'):
                        # previous trace is complete
                        tunnels.update(process_trace(trace))
                        tc += 1
                        trace = [line]
                    else:
                        trace.append(line)
                process_trace(trace)
                tc += 1
        except Exception as e:
            print(f'Error processing {fname}')
            return set(),0
    else:
         with open(fname,'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('trace'):
                    # previous trace is complete
                    tunnels.update(process_trace(trace))
                    tc += 1
                    trace = [line]
                else:
                    trace.append(line)
                
            process_trace(trace)
    for t in tunnels:
        t.add_filename(fname)
    return tunnels,tc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--list')
    parser.add_argument('-f','--file')
    parser.add_argument('-o','--out',default='tnt-tunnels-out.json')
    parser.add_argument('-b','--bz2',action='store_true')
    args = parser.parse_args()

    files = []
    if args.list:
        with open(args.list,'r') as f:
            files = [line.strip() for line in f if (line.strip != '' and not line.strip().startswith('#'))]
    else:
        files = [args.file]

    tunnels = set()
    global usebz2 
    usebz2 = args.bz2
    trace_count = 0
    pb = Progress(len(files), callback=lambda: f'Found {len(tunnels)}')
    with Pool(30) as p:
        for result,tc in pb.iterator(p.imap_unordered(process_file, files)):
            # npairs += len(result)
            tunnels.update(result)
            trace_count += tc
    

    # for f in files:
    #     tunnels.update(process_file(f))

    exp = [t for t in tunnels if t.type == 'EXP']
    inv = [t for t in tunnels if t.type == 'INV']
    opa = [t for t in tunnels if t.type == 'OPA']
    imp = [t for t in tunnels if t.type == 'IMP']

    print(f'Identified {len(tunnels)} tunnels from {trace_count} traces! {len(exp)} exp, {len(inv)} inv, {len(opa)} opa, and {len(imp)} imp')

    to_json = [t.to_dict() for t in tunnels]
    with open(args.out,'w+') as f:
        f.write(json.dumps(to_json))
    


if __name__=='__main__':
    main()
