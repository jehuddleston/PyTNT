# PyTNT

PyTNT is a python based tool built off of Scamper to detect MPLS tunnels on Internet paths.
PyTNT uses the same MPLS discovery techniques as [TNT](https://github.com/YvesVanaubel/TNT/tree/master/TNT), but includes more recent features for integration with large topology measurement platgorms. 

PyTNT is the result of a [replication paper](https://doi.org/10.1145/3730567.3764457) presented at IMC 2025. 


## Installation

PyTNT was developed and tested with Python 3.10.12, but should be compatible with any python version that can run the [scamper API](https://www.caida.org/catalog/software/scamper/python/).
The only package outside of the python standard library is Scamper.
