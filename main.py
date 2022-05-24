import socket, os
from PCAPFile import *
from Trame import *

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    pcap,name_file = Create_pcapfile()
    cpt = 1
    print("Appuyez sur Ctrl+C poru arretez la capture... ")
    time.sleep(1)
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)
            print(f"{BWhite}\n------------- Trame n° {cpt} ------------- {Reset}")
            Trame(raw_data.hex())
            cpt += 1
    except KeyboardInterrupt:
        print(Reset)
        print(f"{BWhite} le fichier {name_file} à été crée ici : /root/sniff/ " )
        pcap.close()
        return 0

def Create_pcapfile():
    t = time.localtime()
    current_time = time.strftime(f"%m-%d-%Y_%H:%M:%S", t)
    try:
        os.system("cd /root/sniffer/ 2> /dev/null")
        pcap = PCAPFile(f"/root/sniffer/sniff_{current_time}.pcap")
    except:
        os.mkdir("/root/sniffer")
        pcap = PCAPFile(f"/root/sniffer/sniff_{current_time}.pcap")
    return pcap, f"sniff_{current_time}.pcap"

if __name__ == '__main__':
    main()
