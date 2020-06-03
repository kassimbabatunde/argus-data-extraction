import os
import csv
import sys
import subprocess as sp


"""
Note: To use this srcipt Argus client must be install before this can work

To install argus on Ubuntu use the following command

sudo apt-get install argus-server && sudo apt-get install argus-client

This script will process pcap file using argus network tool

@author: Tunde
"""


read_exten = '.pcap'

basedir = "/home/cyraacloud/flowScript"


pkSeqID = []
Stime = []
Flags = []
Flags_Number = []
Proto = []
Proto_Number = []
saddr = []
sport = []
daddr = []
dport = []
pkts = []
pkts1 = []
byts = []
byts1 = []
state = []
Ltime = []
aSeq = []
Dur = []
Mean = []
Stddev = []
aSum = []
aMin = []
aMax = []
spkts = []
dpkts = []
sByt = []
dByt = []
aRate = []
adRate = []
aSRate = []
aDRate = []

def read_pcap_file():

    """
        This function will process the pcap file with run_argus command
    """
    getAllFiles = os.listdir(basedir)
    for pfile in getAllFiles:
        if pfile.endswith(read_exten):
            try:
                run_argus = "argus -r {pcapfile} \
                            -w - | ra -s srcid stime flgs proto saddr daddr pkts bytes state \
                            ltime seq dur mean stddev sum min max spkts dpkts sbytes dbytes \
                            rate srate drate sport dport".format(pcapfile=os.path.join(basedir,pfile))
                proc = sp.Popen(run_argus, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
                read_out = proc.stdout.readlines()
                save_to_csv(read_out)
            except RuntimeError as er:
                print(er)


def save_to_csv(stringFile):
    """
        This function will split the list string 
        from the network flow data into individaul 
        list, covert it to list dictionary 
        which is store as csv file
    """
    for line in stringFile:
        line_split = line.split()
        if len(line_split)== 20:
            pkSeqID.append(line_split[0].decode("utf-8"))
            #Stime.append(list_values[0].decode("utf-8"))
            #Flags.append(list_values[0].decode("utf-8"))
            #Flags_Number.append(list_values[0].decode("utf-8"))
            Proto.append(line_split[1].decode("utf-8"))
            saddr.append(line_split[2].decode("utf-8"))
            daddr.append(line_split[3].decode("utf-8"))
            pkts.append(line_split[4].decode("utf-8"))
            pkts1.append(line_split[5].decode("utf-8"))
            byts.append(line_split[6].decode("utf-8"))
            byts1.append(line_split[7].decode("utf-8"))
            #state.append(line_split[0].decode("utf-8"))
            #Ltime.append(line_split[0].decode("utf-8"))
            aSeq.append(line_split[8].decode("utf-8"))
            Dur.append(line_split[9].decode("utf-8"))
            #Mean.append(line_split[10].decode("utf-8"))
            #Stddev.append(line_split[11].decode("utf-8"))
            #aSum.append(line_split[12].decode("utf-8"))
            #aMin.append(line_split[13].decode("utf-8"))
            #aMax.append(line_split[14].decode("utf-8"))
            spkts.append(line_split[10].decode("utf-8"))
            dpkts.append(line_split[11].decode("utf-8"))
            sByt.append(line_split[12].decode("utf-8"))
            dByt.append(line_split[13].decode("utf-8"))
            aRate.append(line_split[14].decode("utf-8"))
            adRate.append(line_split[15].decode("utf-8"))
            aSRate.append(line_split[16].decode("utf-8"))
            aDRate.append(line_split[17].decode("utf-8"))
            
            if line_split[18].decode("utf-8") == None:
                sport.append("null")
            else:
                sport.append(line_split[18].decode("utf-8"))

            if line_split[19].decode("utf-8") == None:
                dport.append("null")
            else:
                dport.append(line_split[19].decode("utf-8"))

            if line_split[1].decode("utf-8") == "udp":
                Proto_Number.append(17) 
            elif line_split[1].decode("utf-8") == "tcp":
                Proto_Number.append(6)
            elif line_split[1].decode("utf-8") == "arp":
                Proto_Number.append(1)
            else:
                print(line_split[1].decode("utf-8"))
    
    data_dict = [{ "srcid":a, "protocol":b, "protocol_num":c, 
                "src_add":d, "src_port":e, "dest_add":f, "dest_port":g, 
                "packet0":h, "packet1": i,"byte0":j,"byte1": k,"seq_num":l,
                "duration":m,"src_packet":n,"dest_packet":o,"src_byte":p,
                "dest_byte":q,"rate0":r,"rate1":s,"src_rate":t,"dst_rate":u}
             for a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u in zip(pkSeqID,
            Proto, Proto_Number, saddr, sport, daddr, dport,
            pkts, pkts1, byts, byts1, aSeq, Dur, spkts, dpkts,
            sByt, dByt, aRate, adRate, aSRate, aDRate)
            ]
    with open("aDataFile.csv", "w") as csvfile:

        headerName = [
            "srcid", "protocol", "protocol_num", "src_add",
            "src_port", "dest_add", "dest_port", "packet0",
            "packet1", "byte0", "byte1", "seq_num","duration",
            "src_packet", "dest_packet", "src_byte", "dest_byte",
            "rate0", "rate1", "src_rate", "dst_rate"
        ]
        writer = csv.DictWriter(csvfile, headerName)
        writer.writeheader()
        for data in data_dict:
            writer.writerow(data)


if __name__ == "__main__":
    read_pcap_file()