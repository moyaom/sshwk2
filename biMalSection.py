import pefile
import argparse
import os
import pprint
import networkx
from networkx.drawing.nx_agraph import write_dot
from networkx.algorithms import bipartite

def find_section_names(file):
    l_pe=pefile.PE(file)
    l_section_names=[section.Name for section in l_pe.sections]
    return l_section_names

args = argparse.ArgumentParser("Visualize shared section_names between a directory of malware samples")
args.add_argument("target_path",help="directory with malware samples")
args.add_argument("output_file",help="file to write DOT file to")
args.add_argument("malware_projection",help="file to write DOT file to")
args.add_argument("section_name_projection",help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()

# search the target directory for valid Windows PE executable files
for root,dirs,files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root,path))
        except pefile.PEFormatError:
            continue
        full_path = os.path.join(root,path)
        section_names = find_section_names(full_path)
        if len(section_names):
            # add the nodes and edges for the bipartite network
            network.add_node(path,label=path[:32],color='black',penwidth=5,bipartite=0)
        for section_name in section_names:
            network.add_node(section_name,label=section_name,color='blue',
               penwidth=10,bipartite=1)
            network.add_edge(section_name,path,penwidth=2)
        if section_names:
            print("Extracted hostnames from:",path)
            pprint.pprint(section_names)
# write the dot file to disk
write_dot(network, args.output_file)
malware = set(n for n,d in network.nodes(data=True) if d['bipartite']==0)
section_name = set(network)-malware

# use NetworkX's bipartite network projection function to produce the malware
# and hostname projections
malware_network = bipartite.projected_graph(network, malware)
section_name_network = bipartite.projected_graph(network, section_name)

# write the projected networks to disk as specified by the user
write_dot(malware_network,args.malware_projection)
write_dot(section_name_network,args.section_name_projection)
