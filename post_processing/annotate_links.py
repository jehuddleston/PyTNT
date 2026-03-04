import bz2
import os

tunnel_types = ['OPA','INV','EXP','IMP']

def main():

    datadir = '/project/tnt-dev/'
    target_file = 'found_tunnels.txt.bz2'
    filelist = []
    for i in os.listdir(datadir):
        tmpdir = os.path.join(datadir,i)
        if os.path.isdir(tmpdir) and os.access(tmpdir,os.R_OK):
            for j in os.listdir(tmpdir):
                if j == target_file:
                    fname = os.path.join(tmpdir,j)
                    filelist.append(fname)
    print(f'Found {len(filelist)} files')
    # print(filelist)

    nodesfile = '/data/topology/ITDK/ITDK-2025-08/midar-iff-snmp-tnt.nodes.bz2'
    ipnode = {}
    with bz2.open(nodesfile,'rt') as f:
        for line in f:
            if line.startswith('#'):
                continue
            if line.strip() == '':
                continue
            _, node, *ips = line.strip().split()
            node = node.replace(':','')
            for ip in ips:

                ipnode[ip] = node

    print(f'Loaded {len(ipnode)} IP Addresses')

    lines = set()
    for fname in filelist:
        with bz2.open(fname,'rt') as f:

            ing = None
            # egr = None
            tt = None
            for line in f: 
                if 'EGR' not in line and 'ING' not in line:
                    continue
                
                tags = []
                fields = line.strip().split()

                for field in fields: 
                    if field[0] == '[' and field[-1] == ']' and 'MPLS' in field:
                        tags = field
                        tags = tags[1:-1]
                        tags = tags.split(',')
                if len(tags) == 0:
                    continue
                addr = fields[1]
                ingegr = []
                ttypes = []

                for tag in tags:
                    if tag in ['ING','EGR','LSR']:
                        ingegr.append(tag)
                    elif tag in tunnel_types:
                        ttypes.append(tag)

                # if len(ttypes) > len(ingegr):
                #    print(f'ingegr: {ingegr}, types: {ttypes}')
                #    print(fname)
                #    print(line)
                if len(ingegr) >= len(ttypes):
                    if 'EXP' in ttypes:
                        ttypes = ['EXP']
                    elif 'INV' in ttypes:
                        ttypes = ['INV']
                    elif 'IMP' in ttypes:
                        ttypes = ['IMP']
                    else:
                        ttypes = ['OPA']
                # if len(ingegr) != len(ttypes):
                #     print(fname)
                #     print(line)

                if 'EGR' in ingegr:
                    if ing is not None:
                        if addr in ipnode and ing in ipnode:
                            lines.add(f'{ipnode[ing]}\t{ing}\t{ipnode[addr]}\t{addr}\t{tt}\n')
                        ing = None
                        tt = None
                if 'ING' in ingegr:
                    ing = addr
                    if len(ttypes) >1:
                        tt = ttypes[ingegr.index('ING')]
                    else:
                        tt = ttypes[0]



    outname = 'midar-iff-snmp-tnt.nodes.mpls.bz2'
    with bz2.open(outname,'wt') as o:
        for fname in filelist:
            o.write(f'# {fname}\n')
        o.write('# format: ingress node addr egress node addr type\n')
        for line in lines:
            o.write(line)


if __name__=='__main__':
    main()
