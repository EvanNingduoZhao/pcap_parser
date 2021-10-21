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

vector_proto = CountVectorizer()
protocols = ['arp','data','dns','ftp','http','icmp','ip','ssdp','ssl','telnet','tcp','udp']
powers_of_two = np.array([2**i for i in range(len(protocols))])

class packet_features:
    def __init__(self):
        self.id_fwd = (0,0,0,0,0) # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.id_bwd = (0,0,0,0,0)  # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.features_list = []


    def __str__(self):
        return "{} -> {}".format(self.id_fwd, self.features_list)

def parse_packet(pkt):
    pf = packet_features()
    tmp_id = [0,0,0,0,0]

    try:
        pf.features_list.append(float(pkt.sniff_timestamp))  # timestampchild.find('Tag').text
        pf.features_list.append(int(pkt.ip.len))  # packet length
        pf.features_list.append(int(hashlib.sha256(str(pkt.highest_layer).encode('utf-8')).hexdigest(),
                                    16) % 10 ** 8)  # highest layer in the packet
        pf.features_list.append(int(int(pkt.ip.flags, 16)))  # IP flags
        tmp_id[0] = str(pkt.ip.src)  # int(ipaddress.IPv4Address(pkt.ip.src))
        tmp_id[2] = str(pkt.ip.dst)  # int(ipaddress.IPv4Address(pkt.ip.dst))

        protocols = vector_proto.transform([pkt.frame_info.protocols]).toarray().tolist()[0]
        protocols = [1 if i >= 1 else 0 for i in
                     protocols]  # we do not want the protocols counted more than once (sometimes they are listed twice in pkt.frame_info.protocols)
        protocols_value = int(np.dot(np.array(protocols), powers_of_two))
        pf.features_list.append(protocols_value)

        protocol = int(pkt.ip.proto)
        tmp_id[4] = protocol
        if pkt.transport_layer != None:
            if protocol == socket.IPPROTO_TCP:
                tmp_id[1] = int(pkt.tcp.srcport)
                tmp_id[3] = int(pkt.tcp.dstport)
                pf.features_list.append(int(pkt.tcp.len))  # TCP length
                pf.features_list.append(int(pkt.tcp.ack))  # TCP ack
                pf.features_list.append(int(pkt.tcp.flags, 16))  # TCP flags
                pf.features_list.append(int(pkt.tcp.window_size_value))  # TCP window size
                pf.features_list = pf.features_list + [0, 0]  # UDP + ICMP positions
            elif protocol == socket.IPPROTO_UDP:
                pf.features_list = pf.features_list + [0, 0, 0, 0]  # TCP positions
                tmp_id[1] = int(pkt.udp.srcport)
                pf.features_list.append(int(pkt.udp.length))  # UDP length
                tmp_id[3] = int(pkt.udp.dstport)
                pf.features_list = pf.features_list + [0]  # ICMP position
        elif protocol == socket.IPPROTO_ICMP:
            pf.features_list = pf.features_list + [0, 0, 0, 0, 0]  # TCP and UDP positions
            pf.features_list.append(int(pkt.icmp.type))  # ICMP type
        else:
            pf.features_list = pf.features_list + [0, 0, 0, 0, 0, 0]  # padding for layer3-only packets
            tmp_id[4] = 0

        pf.id_fwd = (tmp_id[0], tmp_id[1], tmp_id[2], tmp_id[3], tmp_id[4])
        pf.id_bwd = (tmp_id[2], tmp_id[3], tmp_id[0], tmp_id[1], tmp_id[4])

        return pf

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        print(e)
        return None

def store_packet(pf,temp_dict,start_time_window, max_flow_len):
    if pf is not None:
        if pf.id_fwd in temp_dict and start_time_window in temp_dict[pf.id_fwd] and \
                temp_dict[pf.id_fwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[pf.id_fwd][start_time_window] = np.vstack(
                [temp_dict[pf.id_fwd][start_time_window], pf.features_list])
        elif pf.id_bwd in temp_dict and start_time_window in temp_dict[pf.id_bwd] and \
                temp_dict[pf.id_bwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[pf.id_bwd][start_time_window] = np.vstack(
                [temp_dict[pf.id_bwd][start_time_window], pf.features_list])
        else:
            if pf.id_fwd not in temp_dict and pf.id_bwd not in temp_dict:
                temp_dict[pf.id_fwd] = {start_time_window: np.array([pf.features_list]), 'label': 0}
            elif pf.id_fwd in temp_dict and start_time_window not in temp_dict[pf.id_fwd]:
                temp_dict[pf.id_fwd][start_time_window] = np.array([pf.features_list])
            elif pf.id_bwd in temp_dict and start_time_window not in temp_dict[pf.id_bwd]:
                temp_dict[pf.id_bwd][start_time_window] = np.array([pf.features_list])
    return temp_dict

pcap_file = "/Users/nzhao9/Desktop/BIDA_Capstone/extract_pcap/SAT-01-12-2018_0750"

# Offline preprocessing of pcap files for model training, validation and testing
def process_pcap(pcap_file,max_flow_len,time_window):
    start_time = time.time()
    temp_dict = OrderedDict()
    start_time_window = -1

    pcap_name = pcap_file.split("/")[-1]
    print("Processing file: ", pcap_name)

    cap = pyshark.FileCapture(pcap_file)
    for i, pkt in enumerate(cap):
        if i % 1000 == 0:
            print(pcap_name + " packet #", i)
        if i==2000:
            break

        # start_time_window is used to group packets/flows captured in a time-window
        if start_time_window == -1 or float(pkt.sniff_timestamp) > start_time_window + time_window:
            start_time_window = float(pkt.sniff_timestamp)

        pf = parse_packet(pkt)
        print(pf)
        temp_dict = store_packet(pf, temp_dict, start_time_window, max_flow_len)
    print(temp_dict)

process_pcap(pcap_file, 10, 10)
