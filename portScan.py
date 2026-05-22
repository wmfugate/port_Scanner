import socket, threading, time
from datetime import datetime
from struct import pack, unpack
from random import randint

def getInp(type):
    if(type == "str"):
        while(1):
            try:
                return str(input("Choice:"))
            except:
                print("Input must be a string\n")
    elif(type == "int"):
        while(1):
            try:
                return int(input("Choice:"))
            except:
                print("Input must be an integer\n")
    else:
        print("Type is currently not implemented\n")

#from binarytides.com, computes tcp checksum (need to show message not corrupted over transit)
def checksum(msg):
    s = 0
    if len(msg) % 2:    #if msg is odd, so no error with i+1 on last run of loop
        msg += b'\x00'
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

def conn(minport, maxport, timeout, protocol, returnType, resultStore, retries, target):
    if(protocol == 1):  #TCP
        for i in range(minport, maxport+1): #+1 as exclusive of end value
            #sockets must be recreated each loop as can only do one connection per socket (can be outside for UDP as connectionless)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   #1st parameter = IPv4, 2nd = TCP
            s.settimeout(timeout)
            try:
                if(s.connect((target, i)) == None):   #no response because handshake completed + listening
                    if((returnType == 2) or (returnType == 3) or (returnType == 4) or (returnType == 6)):
                        print("Port", i, "is open.\n")
                    if((returnType == 1) or (returnType == 3) or (returnType == 5) or (returnType == 6)):
                        resultStore.append((i, "open"))
            except ConnectionRefusedError as error: #reached host, but no listening
                if((returnType == 2) or (returnType == 3)):
                    print("Port", i, "is closed.\n")
                if((returnType == 1) or (returnType == 3)):
                    resultStore.append((i, "closed"))
            except socket.timeout as error: #either packet dropped (Fw) or timed out
                if((returnType == 2) or (returnType == 3)):
                    print("Port", i, "is filtered or slow.\n")
                if((returnType == 1) or (returnType == 3)):
                    resultStore.append((i, "filtered|slow"))
            except: #other error
                if((returnType == 2) or (returnType == 3)):
                    print("Port", i, "is unknown.\n")
                if((returnType == 1) or (returnType == 3)):
                    resultStore.append((i, "unknown"))
            s.close()
    elif(protocol == 2):   #UDP
        #Have same responses as TCP?
        #different: hard to distinguish between open and filtered as port may not send anything back if open (no handshack, ACK, etc.)
        #why reordered down below?
        #nmap throws in -sv which sends some custom packets to elicit better responses
        #nmap also uses TTL values on packets to try and get better results - not possible with socket's recvfrom with UDP as only returns payload and source address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   #1st parameter = IPv4, 2nd = UDP
        s.settimeout(timeout)
        for i in range(minport, maxport+1): #+1 as exclusive of end value
            for tries in range(retries):
                try:
                    #send specific packets for some ports to try and get better response (special packets are AI generated)
                    #for others, just empty packet
                    if(i == 37):    #Time Protocol
                        s.sendto(b"\x00", (target, i))
                    elif(i == 53):        #DNS, dns query
                        s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", (target, i))
                    elif((i == 66) or (i == 67)):   #DHCP, discover message
                        s.sendto(b"\x01\x01\x06\x00" + b"\x39\x03\xf3\x26" + b"\x00"*16 + b"\x00"*192 + b"\x63\x82\x53\x63" + b"\x35\x01\x01", (target, i))
                    elif(i == 69):      #TFTP, read request
                        s.sendto(b"\x00\x01test\x00octet\x00", (target, i))
                    elif(i == 88):  #Kerberos
                        s.sendto(b"\x6a\x81\x30\x30\x81\x2d\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a", (target, i))
                    elif(i == 123):     #NTP, ntp packet
                        s.sendto(b'\x1b' + 47 * b'\0', (target, i))
                    elif(i == 137):     #NetBIOS-ns, name query
                        s.sendto(b"\x12\x34\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01", (target, i))
                    elif(i == 161):     #SNMP, snmp public
                        s.sendto(bytes.fromhex("30 26 02 01 01 04 06 70 75 62 6c 69 63 a0 19 02 04 71 b4 b5 68 02 01 00 02 01 00 30 0b 30 09 06 05 2b 06 01 02 01 05 00"), (target, i))
                    elif(i == 500):     #ISAKMP, IKE handshake mimic
                        s.sendto(b"\x00"*16 + b"\x01\x10\x02\x00" + b"\x00"*8 + b"\x00"*16, (target, i))
                    elif(i == 520): #RIP (routing info)
                        s.sendto(b"\x01\x01\x00\x00" + b"\x00"*20, (target, i))
                    elif(i == 554): #RTSP (real time streaming)
                        s.sendto(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", (target, i))
                    elif(i == 631): #IPP, printing
                        s.sendto(b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n", (target, i))
                    elif(i == 1434):    #mssql
                        s.sendto(b"\x02", (target, i))
                    elif(i == 1900):    #SSDP, M-Search discovery request
                        s.sendto(b"M-SEARCH * HTTP/1.1\r\nST:ssdp:all\r\nMX:1\r\nMAN:\"ssdp:discover\"\r\n\r\n", (target, i))
                    elif(i == 5355):    #LLMNR, name resolution
                        s.sendto(b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x00\x00\x01\x00\x01", (target, i))
                    elif(i == 11211):   #Memcached
                        s.sendto(b"stats\r\n", (target, i))
                    elif(i == 33434):   #traceroute, UDP
                        s.sendto(b"\x00", (target, i))
                    else:
                        s.sendto(b"", (target, i))  #open but silent or filtered + dropped
                    try:
                        s.recvfrom(1024)   #any response? open
                        if((returnType == 2) or (returnType == 3) or (returnType == 4) or (returnType == 6)):
                            print("Port", i, "is open.\n")
                        if((returnType == 1) or (returnType == 3) or (returnType == 5) or (returnType == 6)):
                            resultStore.append((i, "open"))
                        break
                    except socket.timeout as error: #nothing? timeout = dropped or possibly open but no response?
                        if(tries == retries - 1):   #will only write/print if still happens on final try
                            if((returnType == 2) or (returnType == 3)):
                                print("Port", i, "is filtered or open.\n")
                            if((returnType == 1) or (returnType == 3)):
                                resultStore.append((i, "filtered|open"))
                except ConnectionRefusedError as error: #unreachable port (ICMP)
                    if((returnType == 2) or (returnType == 3)):
                        print("Port", i, "is closed.\n")
                    if((returnType == 1) or (returnType == 3)):
                        resultStore.append((i, "closed"))
                    break
                except OSError as error:
                    if((returnType == 2) or (returnType == 3)):
                        print("Port", i, "is unknown.\n")
                    if((returnType == 1) or (returnType == 3)):
                        resultStore.append((i, "unknown"))
                    break
        s.close()
    else:
        #TCP SYN scan, must use raw sockets (must make packet ourselves), run with sudo
        #getting accurate my_ip (socket.gethostname was returning local 127.#.#.# address)
        temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp.connect(("8.8.8.8", 80))
        my_ip = temp.getsockname()[0]
        temp.close()

        #setting up socket and packet
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)  #IPPROTO_RAW only sends packets, must create new socket to recieve
        s_recv.settimeout(timeout)

        for i in range(minport, maxport + 1):
            recv_port = randint(49152, 65535)    #choosing ephermal port to recieve traffic
            #recieve response + interpret
            tcp_head = pack('!HHLLBBHHH', recv_port, i, 454, 0, (5 << 4) + 0, 2, 5840, 0, 0)
            #pack(pack format string for network order, src port, dest port, sequence #, ack #, tcp data offset, syn flag, window size, checksum, urg ptr)
            #flags are binary in order: Urg|Ack|Psh|RST|SYN|FIN; sending SYN only so: 000010 or 2
            ip_head = pack('!BBHHHBBH4s4s', (4 << 4) + 5, 0, 20 + len(tcp_head), 54321, 0, 255, socket.IPPROTO_TCP, 0, socket.inet_aton(my_ip), socket.inet_aton(target))
            #pack(pack format string for network order, IP ihl, IP version, IP type of service, IP total length, ID of packet, fragmentation bit, TTL of packet, protocol, checksum, src addr, dest addr)
            #socket.inet_aton converts IP address to 32 byte form
            pseudo_head = pack('!4s4sBBH', socket.inet_aton(my_ip), socket.inet_aton(target), 0, socket.IPPROTO_TCP, len(tcp_head))
            pseudo_head = pseudo_head + tcp_head
            tcp_checksum = checksum(pseudo_head)
            tcp_head =  pack('!HHLLBBH', recv_port, i, 454, 0, (5 << 4) + 0, 2, 5840) + pack('H', tcp_checksum) + pack('!H', 0)
            #remaking TCP header with checksum (not flipped with '!' in front of H as already done in checksum func)
            packet = ip_head + tcp_head
            s.sendto(packet, (target, 0))

            while True:
                try:
                    data, addr = s_recv.recvfrom(65535) #max packet size
                    ip_head_unpack = unpack('!BBHHHBBH4s4s', data[:20])  #first part of packet(s) recveived is header
                    ip_head_len = (ip_head_unpack[0] & 0xF)* 4
                    tcp_head_unpack = unpack('!HHLLBBHHH', data[ip_head_len:ip_head_len + 20])
                    #tcp_head_upack = (src_port, dst_port, seq, ack, offset, flags, window, checksum, urg)

                    if((socket.inet_ntoa(ip_head_unpack[8]) == target) and (tcp_head_unpack[0] == i) and (tcp_head_unpack[1] == recv_port)):
                        #only want to see relevant packets (coming from target IP's port i to my chosen recv_port)
                        #flags are in Urg|Ack|Psh|RST|SYN|FIN order; looking for SYN ACK (open)
                        #using bitwise for comparisons, can check if specific bit is 1 (since other flags may be flipped to 1 as well; not checking multiple values)
                        if((tcp_head_unpack[5] & 0x12) == 0x12):   #SYN ACK = open, 00010010 = 18
                            if((returnType == 2) or (returnType == 3) or (returnType == 4) or (returnType == 6)):
                                print("Port", i, "is open.\n")
                            if((returnType == 1) or (returnType == 3) or (returnType == 5) or (returnType == 6)):
                                resultStore.append((i, "open"))
                            break
                        elif(tcp_head_unpack[5] & 0x04):  #RST = closed, anything with RST bit flipped
                            if((returnType == 2) or (returnType == 3)):
                                print("Port", i, "is closed.\n")
                            if((returnType == 1) or (returnType == 3)):
                                resultStore.append((i, "closed"))
                            break
                except socket.timeout as error:
                    if((returnType == 2) or (returnType == 3)):
                        print("Port", i, "is filtered or slow.\n")
                    if((returnType == 1) or (returnType == 3)):
                        resultStore.append((i, "filtered|slow"))
                    break
        s.close()
        s_recv.close()


def main():
    resultStore = []
    targetc = 0
    target = ""
    portc = 0
    minport = 1
    maxport = 1024  #up to 65535
    timeout = 500   #ms
    protocol = 0    #1 = TCP, 2 = UDP
    scanm = 0   #1 = sequential, #2 = concurrent
    returnType = 0  #1 = just storing >> file output; 2 = just print; 3 = both

    print("Welcome to the port scanner.\n")


    #1) Getting Inputs + Setup Phase
    #finding target
    while((targetc < 1) or (targetc > 2)):
        print("Target format:\n" \
        "(1) IP Address\n" \
        "(2) Domain Name\n")
        targetc = getInp("int")
    if(targetc == 1):
        print("Enter IP Address in ###.###.###.### form.")
        target = getInp("str")
    else:
        while(1):
            print("Enter Domain Name.")
            target = getInp("str")
            #if no input >> localhost scan
            try:
                target = socket.gethostbyname(target)
                print("Found IP Address", target, "for entered Domain Name.\n")
                break
            except socket.gaierror as error:
                print("Invalid Domain Name or DNS failure\n")

    #ports to scan
    while((portc < 1) or (portc > 4)):
        print("Ports to scan:\n"
        "(1) Top ~1000 ports\n" \
        "(2) All ports\n" \
        "(3) Range of ports\n" \
        "(4) Specific port\n")
        portc = getInp("int")
    if(portc == 1):
        minport = 1
        maxport = 1024
    elif(portc == 2):
        minport = 1
        maxport = 65535
    elif(portc == 3):
        maxport = -1
        while((minport > maxport) or (minport < 1) or (minport > 65535)):
            print("Ports range between 1 and 65535.\n" \
                "Enter starting port.\n")
            minport = getInp("int")
            print("Enter ending port.\n")
            maxport = getInp("int")
    else:
        minport = 0
        maxport = 65536
        while((minport < 1) or (minport > 65535)):
            print("Ports range between 1 and 65535.\n" \
            "Enter specific port")
            minport = getInp("int")
        maxport = minport   #to prevent loop continuing after specific port

    #timeout
    print("Please enter how long to wait for response when scanning (between 1 and 100,000 ms).\n")
    timeout = getInp("int")
    if((timeout < 1) or (timeout > 100000)):
        print("Timeout value must be > 0 and < 100,001.")
        timeout = getInp("int")
    #speed options?

    #protocol choose
    #1 = normal/full TCP scan
    #2 = UDP scan
    #3 = TCP SYN scan
    retries = 0
    while((protocol < 1) or (protocol > 2)):
        print("Choose protocol to scan with:\n"
        "(1) TCP\n" \
        "(2) UDP\n"  \
        "(Keep in mind that UDP is generally less accurate and revealing than TCP)\n")
        protocol = getInp("int")
    if(protocol == 1):
        protocol = 0
        while((protocol < 1) or (protocol > 2)):
            print("Choose TCP type:\n"
            "(1) Normal TCP scan\n"
            "(2) TCP SYN scan (stealthier)\n")
            protocol = getInp("int")
        if(protocol == 2):
            protocol = 3
    if(protocol == 2):
        while(retries <= 0):
            print("UDP is lossy. How many retries per port (> 0)?\n")
            retries = getInp("int")

    #scanning method >> seq or concurrent
    while((scanm < 1) or (scanm > 2)):
        print("Choose scanning method:\n" \
        "(1) Scan ports one-by-one (possibly slow)\n" \
        "(2) Scan multiple at once\n")
        scanm = getInp("int")

    #getting return type:
    #returnType breakdown:
    # 1 = write everything to file
    # 2 = print everything locally
    # 3 = write and print everything
    # 4 = print only opens
    # 5 = write only opens
    # 6 = write and print only opens
        while((returnType < 1) or (returnType > 3)):
            print("Choose return method:\n" \
            "(1) Write to File\n" \
            "(2) Print locally\n" \
            "(3) Do both\n")
            returnType = getInp("int")
        if(returnType == 2):    #specifics on print >> only likely opens or all results
            returnType = 0
            while((returnType < 1) or (returnType > 2)):
                print("Choose what is printed:\n" \
                "(1) Print only opens\n" \
                "(2) Print everything\n")
                returnType = getInp("int")
            if(returnType == 1):
                returnType = 4
            else:
                returnType = 2
        elif(returnType == 1):    #same with what is saved to file; also gets filename
            returnType = 0
            while((returnType < 1) or (returnType > 2)):
                print("Choose what is saved:\n" \
                "(1) Save only opens\n" \
                "(2) Save everything\n")
                returnType = getInp("int")
            if(returnType == 1):
                returnType = 5
            else:
                returnType = 1
            print("Please enter file name to save under (with no extension):\n")
            outFile = getInp("str") + ".txt"
        elif(returnType == 3):
            while((returnType < 1) or (returnType > 2)):
                print("Choose what is printed and saved:\n" \
                "(1) Only opens\n" \
                "(2) Everything\n")
                returnType = getInp("int")
            if(returnType == 1):
                returnType = 6
            else:
                returnType = 3
            print("Please enter file name to save under (with no extension):\n")
            outFile = getInp("str") + ".txt"


    #2) Scanning Phase
    #create socket
    #attempt to connect
    #interpret result
    #close
    if((scanm == 2) and (maxport == minport)):  #catch for only 1 port and want concurrency >> just use sequential
        print("You only want to scan 1 port. Use sequential.")
        scanm = 1
    if(scanm == 2):
        #concurrency >> thread pool or asyn I/O?
        print("You want to scan", maxport - minport + 1, "ports.\n")
        threadCount = 0
        while((threadCount < 2) or (threadCount > 10)):
            print("How many threads do you want to work? (Suggested: 2-4)\n")
            threadCount = getInp("int")
        portsPerThr = (maxport-minport+1)//threadCount
        while(portsPerThr < 1): #if more threads than ports, decreases thread count til each has at least 1 port
            threadCount-=1
            portsPerThr = (maxport-minport+1)//threadCount
        threads = []
        start = time.time()
        for i in range (0, threadCount):
            if(i == threadCount-1):   #because rounding down with portsPerThr >> to catch excess ports
                print("Thread", i + 1, "has ports", minport + i * portsPerThr, "through", maxport, "\n")
                t = threading.Thread(target=conn, args=(minport + i*portsPerThr, maxport, timeout/1000, protocol, returnType, resultStore, retries, target))
                threads.append(t)
            else:
                print("Thread", i + 1, "has ports", minport + i * portsPerThr, "through", minport + (i+1)*portsPerThr - 1, "\n")
                t = threading.Thread(target=conn, args=(minport + i*portsPerThr, minport + (i+1)*portsPerThr - 1, timeout/1000, protocol, returnType, resultStore, retries, target))
                threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print("Scan completed in", time.time() - start, "seconds\n")
    if(scanm == 1):
        #sequential
        start = time.time()
        conn(minport, maxport, timeout/1000, protocol, returnType, resultStore, retries, target)
        print("Scan completed in", time.time() - start, "seconds\n")


    #3) Results + Output Phase
    #print output happens in conn
    #for file output
    if((returnType == 1) or (returnType == 3) or (returnType == 5) or (returnType == 6)):
        header = "Scan of " + target + " on " + str(datetime.now()) +"\n"
        with open(outFile, "a") as f:
            f.write(header)
            for port, status in resultStore:
                f.write("Port " + str(port) + " | " + str(status) + "\n")

cont = "y"
while(cont == "y"):
    main()
    print("Would you like to continue? (enter 'y' to continue)\n")
    cont = getInp("str")
    
#Sources:
    #For more on sockets, TCP, UDP:
        #https://www.geeksforgeeks.org/python/socket-programming-python/
        #https://www.w3tutorials.net/blog/python-socket-connection-timeout/
        #https://docs.python.org/3/library/socket.html#socket.socket.connect
        #https://pythontic.com/modules/socket/sendto
    #More on UDP responses + how to better:
        #https://nmap.org/book/scan-methods-udp-scan.html
    #For threading in python:
        #https://www.geeksforgeeks.org/python/multithreading-python-set-1/
    #For testing:
        #http://scanme.nmap.org/
    #SYN scan:
        #https://nmap.org/book/synscan.html
        #https://www.cyberly.org/en/what-is-a-syn-scan-and-how-does-it-work/index.html
        #https://github.com/LordEvron/PythonRawSocketSniffers/tree/master
        #https://www.binarytides.com/raw-socket-programming-in-python-linux/
        #https://pyquesthub.com/exploring-raw-sockets-in-python-a-practical-example
        #https://jumpcloud.com/it-index/what-is-an-ephemeral-port
