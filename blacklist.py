from scapy.all import rdpcap
import os

INPUT_FOLDER = "WiFi/"
THRESHOLD = 20

files = os.listdir(INPUT_FOLDER)
print(len(files))

dict_globally = dict()
dict_locally = dict()

for f in files:
    try:
        capture = rdpcap(INPUT_FOLDER + f)
    except:
        print("Error in reading pcap")
        continue
    dict_file = set()
    for i, packet in enumerate(capture):
        probe_req = packet.getlayer("Dot11ProbeReq")
        src = packet.addr2
        first_octet = int(float.fromhex(src.split(":")[0][1]))
        if src in dict_file:
            continue
        else:
            dict_file.add(src)
        # Check the nature of MAC address
        if (first_octet & 2) == 0:
            # Globally unique
            if src not in dict_globally:
                dict_globally[src] = 1
            else:
                dict_globally[src] += 1
        else:
            if src not in dict_locally:
                dict_locally[src] = 1
            else:
                dict_locally[src] += 1
    
dict_globally_recurrent = dict(filter(lambda x: x[1] >= THRESHOLD, dict_globally.items()))
dict_locally_recurrent = dict(filter(lambda x: x[1] >= THRESHOLD, dict_locally.items()))

dict_globally_unique = dict(filter(lambda x: x[1] == 1, dict_globally.items()))
dict_locally_unique = dict(filter(lambda x: x[1] == 1, dict_locally.items()))

print("Global MAC addresses seen in multiple files (at least 10):", len(dict_globally_recurrent.keys()))
print("Locally administered MAC addresses seen in multiple files (at least 10):", len(dict_locally_recurrent.keys()))
# print(dict_globally_recurrent)
# print(dict_locally_recurrent)

recurrent_keys = list(dict_locally_recurrent.keys()) + list(dict_globally_recurrent.keys())
with open("blacklist.txt", "w") as fw:
    for k in recurrent_keys:
        fw.write(f"{k}\n")


