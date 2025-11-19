import json
import argparse
import os


def extract_ip_list(m,fname):

    iplist = []
    for vp in m:
        ips = m[vp]
        for ip in ips:
            if ip not in iplist:
                iplist.append(ip)
    with open(fname,'w+') as f:
        for ip in iplist:
            f.write(ip + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--tunnels',default='tnt-tunnels.json')
    args = parser.parse_args()

    tunnels = []
    with open(args.tunnels,'r') as f:
        tunnels = json.load(f)
    print(f'Loaded {len(tunnels)} tunnels')
    exp = set()
    inv = set()
    imp = set()
    opa = set()
    ignored = 0
    total = 0

    vpmap = {}
    invvpmap = {}
    expvpmap = {}
    for t in tunnels:
        type = t['type']
        ing = t['ingress']
        egr = t['egress']
        if len(ing) == 0 or len(egr) == 0:
            ignored += 1
            continue
        total += 1
        ingaddr = ing['addr']
        egraddr = egr['addr']
        if type == 'EXP':
            exp.add((ingaddr,egraddr))
        elif type == 'INV':
            inv.add((ingaddr,egraddr))
        elif type == 'IMP':
            imp.add((ingaddr,egraddr))
        elif type == 'OPA':
            opa.add((ingaddr,egraddr))

        source = t['source file']
        bn = os.path.basename(source)
        vp = bn[:-8]
        # print(vp)
        # print(bn)
        # return
        if vp not in vpmap:
            vpmap[vp] = []
        if ingaddr not in vpmap[vp]:
            vpmap[vp].append(ingaddr)
        if egraddr not in vpmap[vp]:
            vpmap[vp].append(egraddr)
        lsrs = [lsr['addr'] for lsr in t['lsrs']]
        for lsr in lsrs:
            if lsr not in vpmap[vp]:
                vpmap[vp].append(lsr)
        if type == 'INV':
            if vp not in invvpmap:
                invvpmap[vp] = []
            if ingaddr not in invvpmap[vp]:
                invvpmap[vp].append(ingaddr)
            if egraddr not in invvpmap[vp]:
                invvpmap[vp].append(egraddr)
            for lsr in lsrs:
                if lsr not in invvpmap[vp]:
                    invvpmap[vp].append(lsr)
        if type == 'EXP':
            if vp not in expvpmap:
                expvpmap[vp] = []
            if ingaddr not in expvpmap[vp]:
                expvpmap[vp].append(ingaddr)
            if egraddr not in expvpmap[vp]:
                expvpmap[vp].append(egraddr)
            for lsr in lsrs:
                if lsr not in expvpmap[vp]:
                    expvpmap[vp].append(lsr)

        
    ninv = len(inv)
    nexp = len(exp)
    nopa = len(opa)
    nimp = len(imp)
    print(f'Found {ninv + nexp + nopa + nimp} tunnels, {nexp} explicit, {ninv} invisible, {nopa} opaque, and {nimp} implicit. Ignored {ignored} tunnels and examined {total} tunnels')


    print(f'total vps: {len(vpmap)}, exp vps: {len(expvpmap)}, inv vps: {len(invvpmap)}')
    with open('tunnel_ips.json','w+') as f:
        json.dump(vpmap,f)
    with open('tunnel_ips_inv.json','w+') as f:
        json.dump(invvpmap,f)
    with open('tunnel_ips_exp.json','w+') as f:
        json.dump(expvpmap,f)

    

    extract_ip_list(vpmap,'ip_list_total.txt')
    extract_ip_list(invvpmap,'ip_list_inv.txt')
    extract_ip_list(expvpmap,'ip_list_exp.txt')


    


if __name__=='__main__':
    main()
