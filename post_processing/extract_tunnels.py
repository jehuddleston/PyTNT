import bz2
import argparse
import os
from tqdm import tqdm


def valid_file(fname):
    return os.path.isfile(fname) and fname.endswith('found_tunnels.txt.bz2')

def extract_tunnel(lines):
    
    ing = ''
    egr = ''
    extracted = []
    if len(lines) == 0:
        return extracted
    if 'ING' in lines[0]:
        ing  = lines[0].strip().split()[1]
    if 'EGR' in lines[-1]:
        egr = lines[0].strip().split()[1]

    for line in lines:
        try:
            line = line.strip().split()
            addr = line[1]
            tags = None
            for item in line:
                if 'MPLS' in item:
                    tags = item
                    break
            assert tags is not None

            # tags = line[6]
            tags = tags [1:-1].split(',')
            # print(tags)

            valid_ttypes = ['INV','OPA','IMP','EXP']
            valid_ntypes = ['EGR','ING','LSR']
            valid_rtypes = ['DPR','BRPR']
            valid_dtypes = ['UTURN','QTTL','RTLA','FRPLA','DUPIP','MTTL']

            rtype = ''
            dtype = ''
            ntype = ''
            ttype = ''
            label = ''

            for tag in tags:
                if tag in valid_ttypes:
                    # if ttype != '':
                    #     print(f'ERROR: double tunnel type in entry: \n\t{line}')
                    ttype = tag
                elif tag in valid_ntypes:
                    # if ntype != '':
                    #     print(f'ERROR: double node type in entry: \n\t{line}')
                    ntype = tag
                elif tag in valid_rtypes:
                    # if rtype != '':
                    #     print(f'ERROR: double revelation type in entry: \n\t{line}')
                    rtype = tag
                elif tag in valid_dtypes:
                    # if dtype != '':
                    #     print(f'ERROR: double discovery type in entry: \n\t{line}')
                    dtype = tag

            # tun_type = tags[1]
            # node_type = tags[2]
            # rev_type = ''
            # disc_type = ''
            # labels = ''
            # if tun_type == 'INV':
            #     rev_type = tags[3]
            #     if node_type == 'LSR':
            #         disc_type = tags[4]
            
            for i, item in enumerate(line):
                if item == 'Labels':
                    label += f'{line[i+1]},'
            if len(label) > 0:
                label = label[:-1]

            # if tun_type == 'IMP':
            #     rev_type = tags[3]

            # if tun_type == 'OPA' and len(tags) > 3:
            #     rev_type = tags[3]

            extracted.append(f'{addr}|{ttype}|{ntype}|{rtype}|{dtype}|{label}|{ing}|{egr}\n')
        except Exception as e:
            print(f'Caught exception for line: {line}')
            raise e
    return extracted

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-d','--dir',default='.')
    parser.add_argument('-o','--out',default='mpls_nodes.txt.bz2')
    args = parser.parse_args()

    filelist = []
    for root, _, files in os.walk(args.dir):
        for fname in files:
            filelist.append(os.path.join(root,fname))
    filelist = [f for f in filter(valid_file,filelist)]
    extracted = set()
    
    for fname in filelist:
        with bz2.open(fname,'rt') as inf:
            tunnel = []
            for line in tqdm(inf):
                if line.strip() == '':
                    # If no egress
                    if len(tunnel) > 0:
                        extracted.update(extract_tunnel(tunnel))
                        tunnel = []
                    
                elif line.startswith('#') or 'MPLS' not in line:
                    continue
                elif 'ING' in line:
                    # If no egress and we see a new ingress 
                    if len(tunnel) > 0:
                        extracted.update(extract_tunnel(tunnel))
                        tunnel = []
                    tunnel.append(line)
                elif 'EGR' in line:
                    tunnel.append(line)
                    extracted.update(extract_tunnel(tunnel))
                    tunnel = []
                else:
                    tunnel.append(line)


    with bz2.open(os.path.join(args.dir,args.out),'wt') as f:
        #TODO write headers
        for fname in filelist:
            f.write(f'# {fname}\n')
        f.write('# format: ip|tunnel type|node type|discovery type|revelation type|labels|ingress IP|egress IP\n')
        for line in extracted:
            f.write(line)


                    

                    
                    





if __name__=='__main__':
    main()
