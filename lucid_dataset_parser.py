# Copyright (c) 2020 @ FBK - Fondazione Bruno Kessler
# Author: Roberto Doriguzzi-Corin
# Project: LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
from util_functions import *

# Sample commands
# split a pcap file into smaller chunks to leverage multi-core CPUs: tcpdump -r dataset.pcap -w dataset-chunk -C 1000
# dataset parsing (first step): python3 lucid_dataset_parser.py --dataset_type SYN2020 --dataset_folder ./sample-dataset/ --packets_per_flow 10 --dataset_id SYN2020 --traffic_type all --time_window 10
# dataset parsing (second step): python3 lucid_dataset_parser.py --preprocess_folder ./sample-dataset/

IDS2018_DDOS_FLOWS = {'attackers': ['18.218.115.60', '18.219.9.1','18.219.32.43','18.218.55.126','52.14.136.135','18.219.5.43','18.216.200.189','18.218.229.235','18.218.11.51','18.216.24.42'],
                      'victims': ['18.218.83.150','172.31.69.28']}

IDS2017_DDOS_FLOWS = {'attackers': ['172.16.0.1'],
                      'victims': ['192.168.10.50']}

CUSTOM_DDOS_SYN = {'attackers': ['11.0.0.' + str(x) for x in range(1,255)],
                      'victims': ['10.42.0.2']}

DDOS2019={'attackers':['54.68.141.132', '37.157.6.247', '173.194.175.109', '72.21.91.29', '74.125.23.94', '173.194.206.157', '34.224.191.241', '172.217.197.157', '52.88.72.192', '35.166.173.139', '72.167.239.239', '54.192.49.120', '151.101.0.233', '157.56.96.157', '91.189.88.162', '23.194.140.89', '96.6.27.46', '23.46.18.11', '209.85.201.108', '216.239.32.62', '54.192.49.24', '52.37.207.140', '162.248.19.151', '13.249.44.72', '216.58.219.196', '52.84.94.109', '172.217.11.36', '34.212.55.103', '172.217.10.66', '52.41.60.30', '54.218.239.186', '172.217.10.42', '172.217.10.226', '34.208.7.98', '99.84.181.67', '216.58.219.193', '52.1.164.212', '52.43.40.243', '35.162.5.226', '52.114.128.43', '172.217.0.97', '172.217.10.1', '172.217.167.3', '172.217.11.38', '8.8.8.8', '216.58.217.129', '52.114.128.8', '35.163.114.36', '173.194.68.109', '172.217.11.33', '172.217.11.46', '54.192.49.66', '172.217.0.99', '54.201.6.28', '35.160.216.194', '35.165.95.232', '172.217.20.35', '165.254.0.88', '23.220.46.76', '173.194.204.108', '52.216.106.142', '172.217.2.170', '172.217.10.38', '52.89.179.237', '165.254.0.99', '172.217.0.110', '204.154.111.117', '172.217.12.162', '172.217.7.2', '172.217.2.98', '52.84.94.61', '99.84.127.10', '204.154.111.105', '23.196.188.109', '91.189.95.83', '34.213.248.229', '54.223.55.250', '91.189.88.149', '52.89.170.53', '172.217.10.130', '52.35.236.192', '52.89.138.72', '52.216.65.219', '204.154.111.108', '52.41.78.152', '209.170.115.51', '172.217.12.129', '94.31.29.44', '54.222.199.48', '52.36.71.24', '52.217.1.214', '38.69.238.10', '216.58.219.234', '52.40.109.206', '172.217.1.2', '52.43.17.8', '172.217.3.106', '216.58.219.194', '104.118.6.210', '173.194.204.157', '4.2.2.4', '23.194.142.15', '54.187.46.234', '74.125.192.108', '54.223.241.206', '172.217.2.162', '52.36.247.148', '74.125.200.94', '74.125.192.109', '172.217.10.36', '192.0.73.2', '35.169.33.58', '104.88.29.90', '172.217.11.2', '172.217.10.106', '54.192.49.17', '172.217.10.99', '34.203.79.136', '172.217.1.6', '104.88.60.48', '23.194.108.16', '204.154.111.122', '99.84.127.98', '209.170.115.42', '208.185.50.80', '125.56.201.105', '8.43.72.21', '52.41.177.216', '54.222.238.19', '172.217.10.35', '172.217.167.163', '52.84.94.240', '172.217.0.98', '104.19.198.151', '172.217.10.34', '172.217.12.130', '173.194.206.109', '216.58.219.198', '23.194.110.93', '165.254.0.67', '37.157.4.24', '204.154.111.133', '172.217.1.162', '172.217.9.226', '184.87.196.179', '204.154.111.134', '18.235.81.250', '54.223.220.137', '54.187.144.104', '74.208.236.171', '99.84.127.103', '157.55.240.126', '52.11.213.147', '173.241.242.143', '52.35.215.194', '209.85.232.155', '35.161.44.2', '172.217.11.50', '172.217.10.102', '99.84.181.107', '52.114.132.21', '173.194.66.155', '204.154.111.107', '172.217.0.102', '23.15.4.25', '209.85.232.109', '52.203.87.59', '54.192.49.205', '64.233.171.94', '99.84.127.48', '37.157.2.234', '99.84.127.36', '23.194.141.17', '52.24.205.129', '34.193.21.25', '172.217.12.131', '172.217.7.6', '65.55.44.108', '172.217.12.170', '37.157.4.41', '172.217.10.46', '52.114.158.52', '52.34.167.99', '23.43.56.57', '173.194.66.109', '35.167.70.180', '18.213.117.114', '52.114.88.28', '209.85.232.108', '172.217.10.10', '52.36.47.72', '52.35.21.241', '165.254.0.90', '172.217.0.106', '216.58.219.195', '37.157.6.251', '172.217.1.14', '13.249.44.68', '40.124.45.19', '204.154.111.127', '172.217.10.4', '204.154.111.119', '172.217.11.35', '54.223.42.164', '34.210.248.212', '52.84.94.138', '52.80.102.242', '34.209.108.219', '172.217.10.2', '172.217.6.202', '52.73.38.228', '23.23.71.178', '173.194.175.108', '74.125.28.94', '35.190.67.248', '173.194.206.108', '34.211.202.13', '34.193.24.97', '35.173.44.140', '204.154.111.106', '99.84.181.15', '172.217.197.154', '172.217.7.170', '216.58.218.225', '35.166.184.180', '204.154.111.130', '172.217.10.97', '172.217.11.10', '99.84.181.109', '8.43.72.47', '208.185.55.51', '35.160.187.49', '52.7.108.194', '99.84.127.44', '34.232.238.166', '172.217.0.100', '34.214.202.211', '96.6.24.119', '52.35.156.126', '52.34.90.23', '204.154.111.129', '104.18.58.178', '52.10.142.119', '54.192.49.62', '204.154.111.111', '34.204.21.102', '172.217.7.166', '216.58.219.210', '52.38.149.111', '204.154.111.104', '172.217.5.226', '216.58.219.206', '13.249.44.58', '173.194.68.108', '104.118.6.139', '23.33.85.123', '172.217.7.10', '52.39.131.77', '172.217.0.226', '23.194.142.213', '125.56.201.115', '172.217.12.194', '52.5.166.35', '23.194.140.15', '204.154.111.77', '99.84.181.10', '52.206.149.245', '34.224.115.86', '23.194.141.240', '34.223.240.82', '52.84.94.238', '204.154.111.115', '172.217.10.129', '172.217.7.14', '104.110.151.222', '52.26.72.3', '172.217.9.234', '172.217.12.138', '38.69.238.19', '96.6.26.47', '172.217.10.110', '209.85.201.109', '172.217.6.226', '192.229.210.129', '172.217.11.34', '52.85.95.223', '95.131.136.1', '108.177.112.156', '8.43.72.57', '23.15.4.11', '172.217.7.4', '52.114.88.20', '216.58.219.202', '172.217.7.3', '172.217.10.6', '54.223.73.162', '99.84.118.62', '52.34.107.172', '8.43.72.67', '172.217.1.3', '204.154.111.120', '34.216.156.21', '52.33.113.226', '35.165.209.195', '23.61.253.72', '64.233.184.94', '52.114.75.78', '172.217.3.42', '172.217.10.114', '172.217.10.14', '52.114.132.73', '35.164.138.68', '204.154.111.118', '172.217.11.42', '173.194.204.109', '172.217.0.234', '104.88.90.6', '52.200.108.113', '185.167.164.46', '172.217.10.33', '172.217.12.134', '54.223.72.245', '104.36.115.113', '23.15.4.10', '52.38.9.173', '23.196.169.249', '204.154.111.131', '204.154.111.114', '172.217.10.134', '91.189.92.41', '37.157.4.39', '172.217.10.100', '54.222.149.110', '172.217.12.132', '172.217.1.4', '172.217.10.3', '34.214.252.85', '23.15.4.24', '38.69.238.16', '104.18.59.178', '52.10.130.148', '172.217.1.1', '172.217.12.142', '173.241.244.143', '172.217.197.156', '54.192.49.191', '104.88.52.29', '52.114.6.46', '34.208.208.167', '184.86.74.35', '54.200.76.177', '173.194.66.156', '204.154.111.112', '204.154.111.116', '216.58.219.226', '34.215.13.51', '52.203.113.92', '37.157.2.239', '13.249.44.79', '8.43.72.98', '172.217.6.194', '172.217.10.98', '204.154.111.113', '185.167.164.47', '23.194.109.223', '13.249.44.62', '208.185.50.75', '209.170.115.32', '172.16.0.5', '34.217.184.213', '34.201.83.115', '54.192.49.254', '34.205.244.84', '52.25.165.23', '54.164.24.12', '108.177.112.154', '173.194.206.154', '23.194.108.123', '172.217.3.98', '107.178.246.49', '108.177.112.108', '54.223.23.213', '54.191.241.246', '54.192.49.61', '172.217.7.1', '173.194.205.108', '204.154.111.128', '31.13.71.2'],
          'victims':['192.168.50.9','192.168.50.6','192.168.50.7','192.168.50.8']}

DDOS_ATTACK_SPECS = {
    'IDS2017' : IDS2017_DDOS_FLOWS,
    'IDS2018' : IDS2018_DDOS_FLOWS,
    'SYN2020' : CUSTOM_DDOS_SYN,
    'DDOS2019': DDOS2019
}


vector_proto = CountVectorizer()
vector_proto.fit_transform(protocols).todense()

random.seed(SEED)
np.random.seed(SEED)



def get_pkt_direction(srcIP,dstIP):
    internalIP = "192.168"
    if internalIP in srcIP and internalIP in dstIP:
        return 0
    elif internalIP in srcIP:
        return 1
    elif internalIP in dstIP:
        return 2
    else:
        print ("No private address in this flow!!!!")
        return 3

class packet_features:
    def __init__(self):
        self.id_fwd = (0,0,0,0,0) # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.id_bwd = (0,0,0,0,0)  # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.features_list = []


    def __str__(self):
        return "{} -> {}".format(self.id_fwd, self.features_list)

# not useful
def get_ddos_flows(attackers,victims):
    DDOS_FLOWS = {}

    if '/' in attackers: # subnet
        DDOS_FLOWS['attackers'] = [str(ip) for ip in list(ipaddress.IPv4Network(attackers).hosts())]
    else: # single address
        DDOS_FLOWS['attackers'] = [str(ipaddress.IPv4Address(attackers))]

    if '/' in victims:  # subnet
        DDOS_FLOWS['victims'] = [str(ip) for ip in list(ipaddress.IPv4Network(victims).hosts())]
    else:  # single address
        DDOS_FLOWS['victims'] = [str(ipaddress.IPv4Address(victims))]

    return DDOS_FLOWS

# function that build the labels based on the dataset type
def parse_labels(dataset_type=None, attackers=None,victims=None):
    output_dict = {}

    if attackers is not None and victims is not None:
        DDOS_FLOWS = get_ddos_flows(attackers, victims)
    # will only enter this case
    elif dataset_type is not None and dataset_type in DDOS_ATTACK_SPECS:
        DDOS_FLOWS = DDOS_ATTACK_SPECS[dataset_type]
    else:
        return None

    for attacker in DDOS_FLOWS['attackers']:
        for victim in DDOS_FLOWS['victims']:
            ip_src = str(attacker)
            ip_dst = str(victim)
            key_fwd = (ip_src, ip_dst)
            key_bwd = (ip_dst, ip_src)

            if key_fwd not in output_dict:
                output_dict[key_fwd] = 1
            if key_bwd not in output_dict:
                output_dict[key_bwd] = 1
    # the values of this dict are all 1
    # the set of keys of this dict is all of the possible combintaions of attackers and victims ip
    return output_dict

def parse_packet(pkt):
    pf = packet_features()
    tmp_id = [0,0,0,0,0]

    try:
        pf.features_list.append(float(pkt.sniff_timestamp))  # timestampchild.find('Tag').text
        # print("timestamp:",float(pkt.sniff_timestamp))
        # local_time = time.localtime(float(pkt.sniff_timestamp))
        # print(local_time)
        pf.features_list.append(int(pkt.ip.len))  # packet length
        pf.features_list.append(int(hashlib.sha256(str(pkt.highest_layer).encode('utf-8')).hexdigest(),
                                    16) % 10 ** 8)  # highest layer in the packet
        pf.features_list.append(int(int(pkt.ip.flags, 16)))  # IP flags
        tmp_id[0] = str(pkt.ip.src)  # int(ipaddress.IPv4Address(pkt.ip.src))
        tmp_id[2] = str(pkt.ip.dst)  # int(ipaddress.IPv4Address(pkt.ip.dst))

        # protocols = vector_proto.transform([pkt.frame_info.protocols]).toarray().tolist()[0]
        # protocols = [1 if i >= 1 else 0 for i in
        #              protocols]  # we do not want the protocols counted more than once (sometimes they are listed twice in pkt.frame_info.protocols)
        # protocols_value = int(np.dot(np.array(protocols), powers_of_two))
        # pf.features_list.append(protocols_value)

        # the above code was commented out because our packets in our DDOS2019 dataset
        # doesn't have the frame_info field
        pf.features_list.append(1)

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
        return None

# Offline preprocessing of pcap files for model training, validation and testing
# pcap_file: file path of the pcap data to be processed
# dataset_type: one of the 3(IDS2017,IDS2018,SYN), chose by user in commandline
# in_labels: result of the parse_labels fuction (dict whose key set is all of the combo of attacks and victums)
# max_flow_len: chose by user in command line arg, bound the max number of rows in the flow matrix of packets (each row in the matrix is features of one packet)
# labelled_flows: used by the apply_labels func called within this func, will cover its meaning in the comment for apply_labels
# traffic_type: also used by apply_label, see comment for apply_labels
# time_window: control the length of the a time window, choose by user in command line arg
def process_pcap(pcap_file,dataset_type,in_labels,max_flow_len,labelled_flows,traffic_type='all',time_window=TIME_WINDOW):
    start_time = time.time()
    temp_dict = OrderedDict()
    start_time_window = -1

    pcap_name = pcap_file.split("/")[-1]
    print("Processing file: ", pcap_name)

    cap = pyshark.FileCapture(pcap_file)
    for i, pkt in enumerate(cap):
        if i % 1000 == 0:
            print(pcap_name + " packet #", i)

        # start_time_window is used to group packets/flows captured in a time-window
        if start_time_window == -1 or float(pkt.sniff_timestamp) > start_time_window + time_window:
            start_time_window = float(pkt.sniff_timestamp)

        pf = parse_packet(pkt)
        temp_dict = store_packet(pf, temp_dict, start_time_window, max_flow_len)

    apply_labels(temp_dict, labelled_flows, in_labels, traffic_type)
    print('Completed file {} in {} seconds.'.format(pcap_name, time.time() - start_time))

# this func is for process streaming data, not useful for our application
# Transforms live traffic into input samples for inference
def process_live_traffic(cap, dataset_type, in_labels, max_flow_len, traffic_type='all',time_window=TIME_WINDOW):
    start_time = time.time()
    temp_dict = OrderedDict()
    labelled_flows = []

    start_time_window = start_time
    time_window = start_time_window + time_window

    if isinstance(cap, pyshark.LiveCapture) == True:
        for pkt in cap.sniff_continuously():
            if time.time() >= time_window:
                break
            pf = parse_packet(pkt)
            temp_dict = store_packet(pf, temp_dict, start_time_window, max_flow_len)
    elif isinstance(cap, pyshark.FileCapture) == True:
        while time.time() < time_window:
            pkt = cap.next()
            pf = parse_packet(pkt)
            temp_dict = store_packet(pf,temp_dict,start_time_window,max_flow_len)

    apply_labels(temp_dict,labelled_flows, in_labels,traffic_type)
    return labelled_flows

# temp_dict is a dict of dict. outer dict's key is five tuple (five tuple is the
# five identifiers of a flow: src ip, dest ip, src port, dest port, protocal)
# outer dict's value is a dict. each inner dict is for a flow
# inner dict's key is the start time of each time window, value is a np matrix, where each row corresponds to a packet in this time window
# thus, each key value pair of the inner dict is for a chunk (a time window) of the entire flow
# besides the key value pairs of chunks, the inner dict also has a key named "label", if the flow is between an attack and a victum
# then the value corresponds to this "label" key should be 1, otherwise it should be 0
# Note: each inner dict is flow, and each inner dict has a "label" key, so label is at FLOW LEVEL!!!!
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

# check if the src and dest ip of a flow is a combo of attacker and victum. if it is, then label the flow as 1
# otherwise,label it as 0 (benign)
# flows: the dict of dicts returned by store_packet
# traffic_type: one out of three, all, ddos or benign, chose by user in command line arg
# labelled_flows: a list of tuples, tuple[0] is the five identifiers of a flow, tuple[1] is a inner dict specified in the comment
# of store_Packet. if traffic_type is benign, then labelled_flows stores all of the benign flows. if traffic_type is ddos, them labelled_flows
# stores all attack flows.
# labels: result of the parse_labels fuction (dict whose key set is all of the combo of attacks and victums)
def apply_labels(flows, labelled_flows, labels, traffic_type):
    for five_tuple, flow in flows.items():
        if labels is not None:
            # five_tuple[0], five_tuple[2] is the src ip and dest ip of the flow, respectively
            short_key = (five_tuple[0], five_tuple[2])  # for IDS2017/IDS2018 dataset the labels have shorter keys
            flow['label'] = labels.get(short_key, 0)
            if flow['label']==1:
                print("###################DDOS found")

        for flow_key, packet_list in flow.items():
            # relative time wrt the time of the first packet in the flow
            if flow_key != 'label':
                amin = np.amin(packet_list,axis=0)[0]
                packet_list[:, 0] = packet_list[:, 0] - amin

        if traffic_type == 'ddos' and flow['label'] == 0: # we only want malicious flows from this dataset
            continue
        elif traffic_type == 'benign' and flow['label'] > 0: # we only want benign flows from this dataset
            continue
        else:
            labelled_flows.append((five_tuple,flow))

# returns the total number of flows
def count_flows(preprocessed_flows):
    ddos_flows = 0
    total_flows = len(preprocessed_flows)
    ddos_fragments = 0
    total_fragments = 0
    for flow in preprocessed_flows:
        flow_fragments = len(flow[1]) - 1
        total_fragments += flow_fragments
        if flow[1]['label'] > 0:
            ddos_flows += 1
            ddos_fragments += flow_fragments  # the label does not count

    return (total_flows, ddos_flows, total_flows - ddos_flows), (total_fragments, ddos_fragments, total_fragments-ddos_fragments)

# balance the dataset based on the number of benign and malicious fragments of flows
def balance_dataset(flows,total_fragments=float('inf')):
    new_flow_list = []

    _,(_, ddos_fragments, benign_fragments) = count_flows(flows)

    if ddos_fragments == 0 or benign_fragments == 0:
        min_fragments = total_fragments
    else:
        min_fragments = min(total_fragments/2,ddos_fragments,benign_fragments)

    random.shuffle(flows)
    new_benign_fragments = 0
    new_ddos_fragments = 0

    for flow in flows:
        if flow[1]['label'] == 0 and (new_benign_fragments < min_fragments ):
            new_benign_fragments += len(flow[1]) - 1
            new_flow_list.append(flow)
        elif flow[1]['label'] == 1 and (new_ddos_fragments < min_fragments):
            new_ddos_fragments += len(flow[1]) - 1
            new_flow_list.append(flow)

    return new_flow_list, new_benign_fragments, new_ddos_fragments

# convert the dataset from dictionaries with 5-tuples keys into a list of flow fragments and another list of labels
def dataset_to_list_of_fragments(dataset):
    keys = []
    X = []
    y = []

    for flow in dataset:
        tuple = flow[0]
        flow_data = flow[1]
        label = flow_data['label']
        for key, fragment in flow_data.items():
            if key != 'label':
                X.append(fragment)
                y.append(label)
                keys.append(tuple)

    return X,y,keys

def train_test_split(flow_list,train_size=TRAIN_SIZE, shuffle=True):
    test_list = []
    _,(total_examples,_,_) = count_flows(flow_list)
    print("total_example:", total_examples)
    print("train_size:",train_size)
    test_examples = total_examples - total_examples*train_size

    if shuffle == True:
        random.shuffle(flow_list)

    current_test_examples = 0
    while current_test_examples < test_examples:
        flow = flow_list.pop(0)
        test_list.append(flow)
        current_test_examples += len(flow[1])-1
        print("current_test_example:", current_test_examples)


    return flow_list,test_list

def main(argv):
    command_options = " ".join(str(x) for x in argv[1:])

    help_string = 'Usage[0]: python3 lucid_dataset_parser.py --dataset_type <dataset_name> --dataset_folder <folder path> --dataset_id <dataset identifier> --packets_per_flow <n> --time_window <t>\n' \
                  'Usage[1]: python3 lucid_dataset_parser.py --preprocess_folder <folder path>'
    manager = Manager()

    parser = argparse.ArgumentParser(
        description='Dataset parser',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--dataset_folder', nargs='+', type=str,
                        help='Folder with the dataset')
    parser.add_argument('-o', '--output_folder', nargs='+', type=str,
                        help='Output folder')
    parser.add_argument('-f', '--traffic_type', default='all', nargs='+', type=str,
                        help='Type of flow to process (all, benign, ddos)')
    parser.add_argument('-p', '--preprocess_folder', nargs='+', type=str,
                        help='Folder with preprocessed data')
    parser.add_argument('--preprocess_file', nargs='+', type=str,
                        help='File with preprocessed data')
    parser.add_argument('-b', '--balance_folder', nargs='+', type=str,
                        help='Folder where balancing datasets')
    parser.add_argument('-n', '--packets_per_flow', nargs='+', type=str,
                        help='Packet per flow sample')
    parser.add_argument('-s', '--samples', default=float('inf'), type=int,
                        help='Number of training samples in the reduced output')
    parser.add_argument('-i', '--dataset_id', nargs='+', type=str,
                        help='String to append to the names of output files')

    parser.add_argument('-t', '--dataset_type', nargs='+', type=str,
                        help='Type of the dataset. Available options are: IDS2017, IDS2018, SYN2020')

    parser.add_argument('-w', '--time_window', nargs='+', type=str,
                        help='Length of the time window')

    parser.add_argument('--no_split', help='Do not split the dataset', action='store_true')

    args = parser.parse_args()

    if args.packets_per_flow is not None:
        max_flow_len = int(args.packets_per_flow[0])
    else:
        max_flow_len = MAX_FLOW_LEN

    if args.time_window is not None:
        time_window = float(args.time_window[0])
    else:
        time_window = TIME_WINDOW

    if args.dataset_id is not None:
        dataset_id = str(args.dataset_id[0])
    else:
        dataset_id = ''

    if args.traffic_type is not None:
        traffic_type = str(args.traffic_type[0])
    else:
        traffic_type = 'all'

    if args.dataset_folder is not None and args.dataset_type is not None:
        process_list = []
        flows_list = []

        if args.output_folder is not None and os.path.isdir(args.output_folder[0]) is True:
            output_folder = args.output_folder[0]
        else:
            output_folder = args.dataset_folder[0]

        # filelist = glob.glob(args.dataset_folder[0])
        filelist = glob.glob(args.dataset_folder[0]+ '/*.pcap')
        in_labels = parse_labels(args.dataset_type[0],args.dataset_folder[0])

        start_time = time.time()
        for file in filelist:
            try:
                # create an empty list that works for multi-threading
                flows = manager.list()
                # each p is a process that is for a pcap file
                p = Process(target=process_pcap,args=(file,args.dataset_type[0],in_labels,max_flow_len,flows,traffic_type,time_window))
                process_list.append(p)
                # flows will be filled as a list of tuples by the apply_labels func called within the process_pcap func
                # flows_list is a list of lists of tuple, where each inner list of tuples is for a pcap data file
                flows_list.append(flows)
            except FileNotFoundError as e:
                continue

        for p in process_list:
            p.start()

        for p in process_list:
            p.join()

        np.seterr(divide='ignore', invalid='ignore')
        print(flows_list)
        # preprocessd_flows is list of tuples, basically, we combine all the tuples in flows_list into one list
        preprocessed_flows = list(flows_list[0])

        #concatenation of the features
        for results in flows_list[1:]:
            preprocessed_flows = preprocessed_flows + list(results)

        process_time = time.time()-start_time

        if dataset_id == '':
            dataset_id = str(args.dataset_type[0])

        filename = str(int(time_window)) + 't-' + str(max_flow_len) + 'n-' + dataset_id + '-preprocess'
        output_file = output_folder + '/' + filename
        output_file = output_file.replace("//", "/") # remove double slashes when needed

        with open(output_file + '.data', 'wb') as filehandle:
            # store the data as binary data stream
            pickle.dump(preprocessed_flows, filehandle)


        (total_flows, ddos_flows, benign_flows),  (total_fragments, ddos_fragments, benign_fragments) = count_flows(preprocessed_flows)

        log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | dataset_type:" + args.dataset_type[0] + \
                     " | flows (tot,ben,ddos):(" + str(total_flows) + "," + str(benign_flows) + "," + str(ddos_flows) + \
                     ") | fragments (tot,ben,ddos):(" + str(total_fragments) + "," + str(benign_fragments) + "," + str(ddos_fragments) + \
                     ") | options:" + command_options + " | process_time:" + str(process_time) + " |\n"
        print (log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)

    # all code below here are for re-structing the data for training
    if args.preprocess_folder is not None or args.preprocess_file is not None:
        if args.preprocess_folder is not None:
            output_folder = args.output_folder[0] if args.output_folder is not None else args.preprocess_folder[0]
            filelist = glob.glob(args.preprocess_folder[0] + '/*.data')
        else:
            output_folder = args.output_folder[0] if args.output_folder is not None else os.path.dirname(os.path.realpath(args.preprocess_file[0]))
            filelist = args.preprocess_file

        # obtain time_window and flow_len from filename and ensure that all files have the same values
        time_window = None
        max_flow_len = None
        dataset_id = None
        for file in filelist:
            filename = file.split('/')[-1].strip()
            current_time_window = int(filename.split('-')[0].strip().replace('t',''))
            current_max_flow_len = int(filename.split('-')[1].strip().replace('n',''))
            current_dataset_id = str(filename.split('-')[2].strip())
            if time_window != None and current_time_window != time_window:
                print ("Incosistent time windows!!")
                exit()
            else:
                time_window = current_time_window
            if max_flow_len != None and current_max_flow_len != max_flow_len:
                print ("Incosistent flow lengths!!")
                exit()
            else:
                max_flow_len = current_max_flow_len

            if dataset_id != None and current_dataset_id != dataset_id:
                dataset_id = "IDS201X"
            else:
                dataset_id = current_dataset_id



        preprocessed_flows = []
        for file in filelist:
            with open(file, 'rb') as filehandle:
                # read the data as binary data stream
                preprocessed_flows = preprocessed_flows + pickle.load(filehandle)


        # balance samples and redux the number of samples when requested
        preprocessed_flows, benign_fragments, ddos_fragments = balance_dataset(preprocessed_flows,args.samples)

        if len(preprocessed_flows) == 0:
            print("Empty dataset!")
            exit()

        preprocessed_train, preprocessed_test = train_test_split(preprocessed_flows,train_size=TRAIN_SIZE, shuffle=True)
        preprocessed_train, preprocessed_val = train_test_split(preprocessed_train, train_size=TRAIN_SIZE, shuffle=True)

        print("preprocessd_train: ", preprocessed_train)
        X_train, y_train, _ = dataset_to_list_of_fragments(preprocessed_train)
        X_val, y_val, _ = dataset_to_list_of_fragments(preprocessed_val)
        X_test, y_test, _ = dataset_to_list_of_fragments(preprocessed_test)

        print("X_train: ", X_train)

        # normalization and padding
        X_full = X_train + X_val + X_test
        y_full = y_train + y_val + y_test
        mins,maxs = static_min_max(time_window=time_window)

        total_examples = len(y_full)
        total_ddos_examples = sum(y_full)
        total_benign_examples = len(y_full) - sum(y_full)

        output_file = output_folder + '/' + str(time_window) + 't-' + str(max_flow_len) + 'n-' + dataset_id + '-dataset'
        if args.no_split == True: # don't split the dataset
            norm_X_full = normalize_and_padding(X_full, mins, maxs, max_flow_len)
            #norm_X_full = padding(X_full,max_flow_len) # only padding
            norm_X_full_np = np.array(norm_X_full)
            y_full_np = np.array(y_full)

            hf = h5py.File(output_file + '-full.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_full_np)
            hf.create_dataset('set_y', data=y_full_np)
            hf.close()

            [full_packets] = count_packets_in_dataset([norm_X_full_np])
            log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | Total examples (tot,ben,ddos):(" + str(total_examples) + "," + str(total_benign_examples) + "," + str(total_ddos_examples) + \
                         ") | Total packets:(" + str(full_packets) + \
                         ") | options:" + command_options + " |\n"
        else:
            norm_X_train = normalize_and_padding(X_train,mins,maxs,max_flow_len)
            print("norm_X_train: ",norm_X_train)
            norm_X_val = normalize_and_padding(X_val, mins, maxs, max_flow_len)
            norm_X_test = normalize_and_padding(X_test, mins, maxs, max_flow_len)

            norm_X_train_np = np.array(norm_X_train)
            y_train_np = np.array(y_train)
            norm_X_val_np = np.array(norm_X_val)
            y_val_np = np.array(y_val)
            norm_X_test_np = np.array(norm_X_test)
            y_test_np = np.array(y_test)

            hf = h5py.File(output_file + '-train.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_train_np)
            hf.create_dataset('set_y', data=y_train_np)
            hf.close()

            hf = h5py.File(output_file + '-val.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_val_np)
            hf.create_dataset('set_y', data=y_val_np)
            hf.close()

            hf = h5py.File(output_file + '-test.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_test_np)
            hf.create_dataset('set_y', data=y_test_np)
            hf.close()

            print("norm_X_train_np: ", norm_X_train_np)
            print("norm_X_val_np: ", norm_X_val_np)
            print("norm_X_test_np: ", norm_X_test_np)
            print("[norm_X_train_np, norm_X_val_np, norm_X_test_np]: ",[norm_X_train_np, norm_X_val_np, norm_X_test_np])
            [train_packets, val_packets, test_packets] = count_packets_in_dataset([norm_X_train_np, norm_X_val_np, norm_X_test_np])
            log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | examples (tot,ben,ddos):(" + str(total_examples) + "," + str(total_benign_examples) + "," + str(total_ddos_examples) + \
                         ") | Train/Val/Test sizes: (" + str(norm_X_train_np.shape[0]) + "," + str(norm_X_val_np.shape[0]) + "," + str(norm_X_test_np.shape[0]) + \
                         ") | Packets (train,val,test):(" + str(train_packets) + "," + str(val_packets) + "," + str(test_packets) + \
                         ") | options:" + command_options + " |\n"

        print(log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)

    if args.balance_folder is not None and args.output_folder is not None:
        output_folder = args.output_folder[0] if args.output_folder is not None else args.balance_folder[0]
        datasets = []
        for folder in args.balance_folder:
            datasets += glob.glob(folder + '/*.hdf5')
        train_filelist = {}
        val_filelist = {}
        test_filelist = {}
        min_samples_train = float('inf')
        min_samples_val = float('inf')
        min_samples_test = float('inf')

        output_filename_prefix = None

        for file in datasets:
            filename = file.split('/')[-1].strip()
            dataset = h5py.File(file, "r")
            X = np.array(dataset["set_x"][:])  # features
            Y = np.array(dataset["set_y"][:])  # labels
            if 'train' in filename:
                key = filename.split('dataset')[0].strip() + 'dataset-balanced-train.hdf5'
                if output_filename_prefix ==None:
                    output_filename_prefix = filename.split('IDS')[0].strip()
                else:
                    if filename.split('IDS')[0].strip() != output_filename_prefix:
                        print ("Inconsistent datasets!")
                        exit()
                train_filelist[key] = (X,Y)
                if X.shape[0] < min_samples_train:
                    min_samples_train = X.shape[0]
            elif 'val' in filename:
                key = filename.split('dataset')[0].strip() + 'dataset-balanced-val.hdf5'
                if output_filename_prefix ==None:
                    output_filename_prefix = filename.split('IDS')[0].strip()
                else:
                    if filename.split('IDS')[0].strip() != output_filename_prefix:
                        print ("Inconsistent datasets!")
                        exit()
                val_filelist[key] = (X,Y)
                if X.shape[0] < min_samples_val:
                    min_samples_val = X.shape[0]
            elif 'test' in filename:
                key = filename.split('dataset')[0].strip() + 'dataset-balanced-test.hdf5'
                if output_filename_prefix ==None:
                    output_filename_prefix = filename.split('IDS')[0].strip()
                else:
                    if filename.split('IDS')[0].strip() != output_filename_prefix:
                        print ("Inconsistent datasets!")
                        exit()
                test_filelist[key] = (X, Y)
                if X.shape[0] < min_samples_test:
                    min_samples_test = X.shape[0]

        final_X = {'train':None,'val':None,'test':None}
        final_y = {'train':None,'val':None,'test':None}

        for key,value in train_filelist.items():
            X_short = value[0][:min_samples_train,...]
            y_short = value[1][:min_samples_train,...]

            if final_X['train'] is None:
                final_X['train'] = X_short
                final_y['train'] = y_short
            else:
                final_X['train'] = np.vstack((final_X['train'],X_short))
                final_y['train'] = np.hstack((final_y['train'],y_short))

        for key,value in val_filelist.items():
            X_short = value[0][:min_samples_val,...]
            y_short = value[1][:min_samples_val,...]

            if final_X['val'] is None:
                final_X['val'] = X_short
                final_y['val'] = y_short
            else:
                final_X['val'] = np.vstack((final_X['val'],X_short))
                final_y['val'] = np.hstack((final_y['val'],y_short))


        for key,value in test_filelist.items():
            X_short = value[0][:min_samples_test,...]
            y_short = value[1][:min_samples_test,...]

            if final_X['test'] is None:
                final_X['test'] = X_short
                final_y['test'] = y_short
            else:
                final_X['test'] = np.vstack((final_X['test'],X_short))
                final_y['test'] = np.hstack((final_y['test'],y_short))

        for key,value in final_X.items():
            filename = output_filename_prefix + 'IDS201X-dataset-balanced-' + key + '.hdf5'
            hf = h5py.File(output_folder + '/' + filename, 'w')
            hf.create_dataset('set_x', data=value)
            hf.create_dataset('set_y', data=final_y[key])
            hf.close()

        total_flows = final_y['train'].shape[0]+final_y['val'].shape[0]+final_y['test'].shape[0]
        ddos_flows = sum(final_y['train'])+sum(final_y['val'])+sum(final_y['test'])
        benign_flows = total_flows-ddos_flows
        [train_packets, val_packets, test_packets] = count_packets_in_dataset([final_X['train'], final_X['val'], final_X['test']])
        log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | total_flows (tot,ben,ddos):(" + str(total_flows) + "," + str(benign_flows) + "," + str(ddos_flows) + \
                     ") | Packets (train,val,test):(" + str(train_packets) + "," + str(val_packets) + "," + str(test_packets) + \
                     ") | Train/Val/Test sizes: (" + str(final_y['train'].shape[0]) + "," + str(final_y['val'].shape[0]) + "," + str(final_y['test'].shape[0]) + \
                     ") | options:" + command_options + " |\n"

        print(log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)


    if args.dataset_folder is None and args.preprocess_folder is None and args.preprocess_file is None and args.balance_folder is None:
        print (help_string)
    if args.dataset_type is None and args.dataset_folder is not None:
        print("Please specify the dataset type (IDS2017, IDS2018, SYN2020)!")
        print(help_string)
    if args.output_folder is None and args.balance_folder is not None:
        print("Please specify the output folder!")
        print(help_string)

if __name__ == "__main__":
    main(sys.argv)