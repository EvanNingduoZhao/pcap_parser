import h5py
import numpy as np
import pandas as pd
filename = "/Users/nzhao9/Desktop/BIDA_Capstone/extract_pcap/10t-10n-DDOS2019-dataset-train.hdf5"

# with h5py.File(filename, "r") as f:
#     # List all groups
#     print("Keys: %s" % f.keys())
#     a_group_key = list(f.keys())[0]
#     print(a_group_key)
#
#     # Get the data
#     data = list(f[a_group_key])
#     print(f["set_y"].map(lambda x:x==1))

df = pd.DataFrame(np.array(h5py.File(filename)['set_y']))
print(df.head)