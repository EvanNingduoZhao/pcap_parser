# from google.colab import drive
# drive.mount('/content/gdrive')
import copy
import os
import sys
import csv
import glob
import h5py
import time
import pyshark
import socket
import pickle
import random
import hashlib
import argparse
import ipaddress
import numpy as np
from lxml import etree
from collections import OrderedDict
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.utils import shuffle as sklearn_shuffle
from multiprocessing import Process, Manager, Value, Queue
pcap_file = "/Users/nzhao9/Desktop/BIDA_Capstone/extract_pcap/SAT-01-12-2018_0750"
start_time = time.time()
temp_dict = OrderedDict()
start_time_window = -1

pcap_name = pcap_file.split("/")[-1]
print("Processing file: ", pcap_name)
cap = pyshark.FileCapture(pcap_file)
for i, pkt in enumerate(cap):
    if i % 1000 == 0:
        print(pcap_name + " packet #", i)
