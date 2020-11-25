from socket import *
import os
import sys
import struct
import time
import select
import binascii
 
ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
 
def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
 
    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2
 
    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff
 
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
 
def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.
 
    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    pid = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, pid, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, pid, 1)

    # Don't send the packet yet, just return the final packetin this function.
    # Fill in end
 
    # So the function ending should look like this

    packet = header + data
    return packet
 
def get_route(dest_hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces
    #print("dest_hostname: ", dest_hostname)
    destAddr = gethostbyname(dest_hostname)
    #print("destAddr: ", destAddr)
 
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
 
            #Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            tracelist1 = []
            #Fill in end
 
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (dest_hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1 = [str(ttl), "*", "Request timed out"]
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                    #print(tracelist1)
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1 = [str(ttl), "*", "Request timed out"]
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                    #print(tracelist1)
                    #Fill in end
            except timeout:
                continue
 
            else:
                #Fill in start
                ms = str(round(howLongInSelect * 1000)) + "ms"

                #Fetch the icmp type from the IP packet
                ipHeader = recvPacket[0:20]
                ipHeaderStruct = struct.unpack("!BBHHHBBHBBBBBBBB", ipHeader)

                ipHeader0 = ipHeaderStruct[0]
                #print(f"field0: {ipHeader0:#x}")
                ipVersion = ipHeader0 // 16
                ihl = ipHeader0 % 16
                #print(f"ipVersion: {ipVersion}")
                #print(f"ihl: {ihl}")

                ipHeader1 = ipHeaderStruct[1]
                #print(f"field1: {ipHeader1:#x}")

                #print(f"raw: {ipHeaderStruct[0]:#x} {ipHeaderStruct[1]:#x} {ipHeaderStruct[2]:#x} {ipHeaderStruct[3]:#x}")
                ipTotalLength = ipHeaderStruct[2]
                #print(f"ipTotalLength: {ipTotalLength}")
                recvTtl = ipHeaderStruct[5]
                #print(f"ttl: {recvTtl}")

                protocol = ipHeaderStruct[6]
                #print(f"protocol: {protocol:#x}")
                #print(f"protocol: {protocol}")

                sourceOctet1 = ipHeaderStruct[8]
                sourceOctet2 = ipHeaderStruct[9]
                sourceOctet3 = ipHeaderStruct[10]
                sourceOctet4 = ipHeaderStruct[11]
                sourceIP = f"{sourceOctet1:d}.{sourceOctet2:d}.{sourceOctet3:d}.{sourceOctet4:d}"
                #print(f"source ip: {sourceOctet1:#x} {sourceOctet2:#x} {sourceOctet3:#x} {sourceOctet4:#x}")
                #print(f"source ip: {sourceOctet1:d}.{sourceOctet2:d}.{sourceOctet3:d}.{sourceOctet4:d}")

                destOctet1 = ipHeaderStruct[12]
                destOctet2 = ipHeaderStruct[13]
                destOctet3 = ipHeaderStruct[14]
                destOctet4 = ipHeaderStruct[15]
                destIP = f"{destOctet1:d}.{destOctet2:d}.{destOctet3:d}.{destOctet4:d}" 
                #print(f"dest ip: {destOctet1:#x} {destOctet2:#x} {destOctet3:#x} {destOctet4:#x}")
                #print(f"dest ip: {destOctet1:d}.{destOctet2:d}.{destOctet3:d}.{destOctet4:d}")
                #print(f"dest ip: {destIP}")

                icmpHeader = recvPacket[20:28]        
                icmpHeaderStruct = struct.unpack("bbHHh", icmpHeader)
                types = icmpHeaderStruct[0]
                #print ("received type: ", types)
                code = icmpHeaderStruct[1]
                #print("received code: ", code)
                checksum = icmpHeaderStruct[2]
                #print(f'checksum: {checksum:#x}')
                #Fill in end
                try: #try to fetch the hostname
                    #Fill in start
                    #print("hostname: ", gethostbyaddr(sourceIP))
                    if types == 0:
                        #print("destAddr: ", destAddr)
                        #print("sourceIP: ", sourceIP)
                        hostname = gethostbyaddr(destAddr)[0]
                    else:
                        hostname = gethostbyaddr(sourceIP)[0]
                    #print("host: ", hostname)                    
                    #Fill in end
                except herror:   #if the host does not provide a hostname
                    #Fill in start
                    hostname="hostname not returnable"
                    #print("hostname not available")
                    #Fill in end
 
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #print("timeSent: ", timeSent)
                    #print("howLongInSelect: ", howLongInSelect)
                    #print("ms: ", ms)
                    #Fill in start
                    #You should add your responses to your lists here
                    tracelist1 = [str(ttl), ms, sourceIP, hostname]
                    tracelist2.append(tracelist1)
                    #print(tracelist1)
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here 
                    tracelist1 = [str(ttl), ms, sourceIP, hostname]
                    tracelist2.append(tracelist1)
                    #print(tracelist1)
                    #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here and return your list if your destination IP is met
                    tracelist1 = [str(ttl), ms, sourceIP, hostname]
                    tracelist2.append(tracelist1)
                    #print(tracelist1)
                    return tracelist2
                    #Fill in end
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your list here
                    tracelist1 = [str(ttl), ms, sourceIP, hostname]
                    tracelist2.append(tracelist1)
                    #print(tracelist1)
                    #Fill in end
                break
            finally:
                mySocket.close()
            

    print(tracelist2)
    return tracelist2

# if __name__ == '__main__':
#     returned_list = get_route("www.google.com")
#     print(returned_list)

    # for item_list in returned_list:
    #     item = item_list[0]
    #     print(item[0], "\t", item[1], "\t", item[2], end="")
    #     if len(item) > 3:
    #         print("\t", item[3])
    #     else:
    #         print()
        