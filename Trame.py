import os.path

Reset = "\033[0m"  # Text Reset

Red = "\033[0;31m"  # Red
Green = "\033[0;32m"  # Green
Yellow = "\033[0;33m"  # Yellow
Blue = "\033[0;34m"  # Blue
Purple = "\033[0;35m"  # Purple
Cyan = "\033[0;36m"  # Cyan
White = "\033[0;37m"  # White

BRed = "\033[1;31m"  # Red
BGreen = "\033[1;32m"  # Green
BYellow = "\033[1;33m"  # Yellow
BBlue = "\033[1;34m"  # Blue
BPurple = "\033[1;35m"  # Purple
BCyan = "\033[1;36m"  # Cyan
BWhite = "\033[1;37m"  # White

class Trame:
    def __init__(self, Data):
        self.IP_Source = ""
        self.IP_Dest = ""
        self.Frame_Header(Data)
    def Frame_Header(self, Data):
        size_of_frame = 28
        MACdest = self.MAC_Addr_Converter(Data[0:12])
        MACSource = self.MAC_Addr_Converter(Data[12:24])
        print(f"{White} MAC Dest : {BGreen}", MACdest, end="")
        print(f" {White} | MAC source : {BGreen}", MACSource, end="")
        EtherType = "0x" + Data[24:28]
        Ox7373 = "0x7373 (Broadcast)"
        Ox0806 = f"{BYellow}ARP"
        Ox86dd = f"{BWhite}IPv6"
        if (EtherType == "0x0800"):
            Packet_data = Data[size_of_frame:len(Data)]
            self.IPV4_Packet_Header(Packet_data)
        elif (EtherType == "0x0806"):
            print(f"{White} | Protocol : ", Ox0806, end="")
            Packet_data = Data[size_of_frame:len(Data)]
            self.ARP_Header(Packet_data)
        elif (EtherType == "0x86dd"):
            Packet_data = Data[size_of_frame:len(Data)]
            self.IPv6_Packet_Header(Packet_data)
        elif (EtherType == "0x7373"):
            print(f"{White} | Protocol : {Red}{Ox7373}", end="")
        else:
            print(f"{White} unknown : {BRed}", EtherType, end="")

    def MAC_Addr_Converter(self, HexMAC): 
        MAC = ""
        for i in range(len(HexMAC)):
            if (i % 2 == 0 and i != 0):
                MAC += ":"
            MAC += HexMAC[i]
        return MAC

    def ARP_Header(self, Data):
        Protocol_Type = "0x"+Data[4:8]
        if(Protocol_Type == "0x0800"):
            Opcode = int(Data[12:16], base=16)
            if(Opcode == 1):
                print(" (Request)", end="")
            if(Opcode == 2):
                print(" (Reply)", end="")
            Sender_MAC = self.MAC_Addr_Converter(Data[16:28])
            Sender_Ip = self.ipv4_conversion(Data[28:36])
            print(f"{White} | Sender_Mac : {BGreen}", Sender_MAC, end="")
            print(f"{White} | Sender_Ip : {BCyan}", Sender_Ip, end="")
            Target_MAC = self.MAC_Addr_Converter(Data[36:48])
            Target_Ip = self.ipv4_conversion(Data[48:56])
            print(f"{White} | Target_Mac : {BGreen}",Target_MAC, end="")
            print(f"{White} | Target_Ip : {BCyan}", Target_Ip, end="")

    def IPV4_Packet_Header(self, Data):
        Size = int(Data[1:2]) * 8
        Protocol = "0x" + Data[18:20]
        Ox01 = f"{BCyan}ICMP"
        Ox06 = f"{BBlue}TCP"
        Ox11 = f"{BBlue}UDP"
        Unknown  = f"{White} | Unknown : {BRed}"
        if (Protocol == "0x01"):
            Protocol = Ox01
            print(f"{White} | Protocol : ", Protocol, end="")
            self.IP_Source = f"{BGreen}" + self.ipv4_conversion(Data[24:32])
            self.IP_Dest = f"{BGreen}" + self.ipv4_conversion(Data[32:40])
            print(f"{White} | IpSrc : ", self.IP_Source, end="")
            print(f"{White} | IpDst : ", self.IP_Dest, end="")
        elif (Protocol == "0x06"):
            Protocol = Ox06
            print(f"{White} | Protocol : ", Protocol, end="")
            self.IP_Source = f"{BGreen}" + self.ipv4_conversion(Data[24:32])
            self.IP_Dest = f"{BGreen}" + self.ipv4_conversion(Data[32:40])
            self.TCP_Header(Data[Size:len(Data)])
        elif (Protocol == "0x11"):
            Protocol = Ox11
            print(f"{White} | Protocol : ", Protocol, end="")
            self.IP_Source = f"{BGreen}" + self.ipv4_conversion(Data[24:32])
            self.IP_Dest = f"{BGreen}" + self.ipv4_conversion(Data[32:40])
            self.UDP_Header(Data[Size:len(Data)])
        else:
            Protocol = Unknown  + Protocol
            print(f"{White} | Protocol : ", Protocol, end="")

    def ipv4_conversion(self, HexIp):
        ipv4 = ""
        for n in range(0, len(HexIp), 2):
            if (n % 2 == 0 and n != 0):
                ipv4 += "."
            ipv4 += str(int(HexIp[n:n + 2], base=16))
        return ipv4

    def IPv6_Packet_Header(self,Data):
        Next_Header = "0x" + Data[12:14] #It's the protocol like ipv4
        Ox3a = f"{BCyan}ICMPV6"
        Ox06 = f"{BBlue}TCP"
        Ox11 = f"{BBlue}UDP"
        Unknown = f"{White} | Unknown : {BRed}"
        if (Next_Header == "0x3a"):
            Protocol = Ox3a
            print(f"{White} | Protocol : ", Protocol, end="")
            self.IP_Source = f"{BPurple}" + self.ipv6_conversion(Data[16:48])
            self.IP_Dest = f"{BPurple}" + self.ipv6_conversion(Data[48:80])
            print(f"{White} | IpSrc : ", self.IP_Source, end="")
            print(f"{White} | IpDst : ", self.IP_Dest, end="")

        elif (Next_Header == "0x06"):
            Protocol = Ox06
            print(f"{White} | Protocol : ", Protocol, end="")
            self.IP_Source = f"{BPurple}" + self.ipv6_conversion(Data[16:48])
            self.IP_Dest = f"{BPurple}" + self.ipv6_conversion(Data[48:80])
            self.TCP_Header(Data[80:len(Data)])

        elif (Next_Header == "0x11"):
            Protocol = Ox11
            print(f"{White} | Protocol : ", Protocol, end="")
            self.IP_Source = f"{BPurple}" + self.ipv6_conversion(Data[16:48])
            self.IP_Dest = f"{BPurple}" + self.ipv6_conversion(Data[48:80])
            self.UDP_Header(Data[80:len(Data)])
        else:
            Protocol = Unknown  + Next_Header
            print(f"{White} | Protocol : ", Protocol, end="")

    def ipv6_conversion(self,HexIp):
        ipv6 = ""
        first_zero = False
        for n in range(0, len(HexIp), 4):
            check = n
            if (HexIp[check] == "0"):
                first_zero = True
            for next in range(n, n + 4, 1):
                if (HexIp[check] == "0" and first_zero):
                    ipv6 += ""
                    check += 1
                else:
                    ipv6 += HexIp[next]
            ipv6 += ":"
        cpt_semi_colon_start = 0
        cpt_semi_colon_end = 0
        Not_find = True
        for i in range(len(ipv6) - 1):
            if (ipv6[i] == ":" and Not_find):
                if (ipv6[i + 1] == ":"):
                    cpt_semi_colon_start = i
                    Not_find = False

            if (Not_find == False and ipv6[i + 1] != ":"):
                cpt_semi_colon_end = i - 1
                break 
        new_ipv6 = ipv6[:cpt_semi_colon_start] + ipv6[cpt_semi_colon_end:]
        return new_ipv6.removesuffix(":")

    def UDP_Header(self, Data):
        SrcPort = int(Data[0:4], base=16)
        DstPort = int(Data[4:8], base=16)
        if(SrcPort < 5062):
            protocol = self.Protocol_Analyze(SrcPort)
            print(f" ({protocol})", end="")
        else:
            protocol = self.Protocol_Analyze(DstPort)
            print(f" ({protocol})", end="")

        SrcPort = f"{BCyan}" + str(SrcPort )
        DstPort = f"{BCyan}" + str(DstPort)

        print(f"{White} | SrcPort : ", SrcPort, end="")
        print(f"{White} | IpSrc : ", self.IP_Source, end="")
        print(f"{White} | DstPort : ", DstPort, end="")
        print(f"{White} | IpDst : ", self.IP_Dest, end="")

    def TCP_Header(self, Data):
        SrcPort = int(Data[0:4], base=16)
        DstPort = int(Data[4:8], base=16)
        if (SrcPort < 5062):
            protocol = self.Protocol_Analyze(SrcPort)
            print(f" ({protocol})", end="")
        else:
            protocol = self.Protocol_Analyze(DstPort)
            print(f" ({protocol})", end="")

        SrcPort = f"{BCyan}" + str(SrcPort)
        DstPort = f"{BCyan}" + str(DstPort)

        print(f" {White} | SrcPort : ", SrcPort, end="")
        print(f"{White} | IpSrc : ", self.IP_Source, end="")
        print(f" {White} | DstPort : ", DstPort, end="")
        print(f"{White} | IpDst : ", self.IP_Dest, end="")

    def Protocol_Analyze(self, Port):
        script_dir = os.path.dirname(__file__)
        List = open(f"{script_dir}/List_Port.txt", "r")
        for line in List:
            index = line.index(" ")
            if(int(line[0:index]) == Port):
                return line[index+1:len(line)].rstrip("\n")
        return str(Port)

    def print_(self, data):
        print(data)
