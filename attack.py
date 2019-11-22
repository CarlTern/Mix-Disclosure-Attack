import sys
from pcapfile import savefile
def getParameters():
    try:
        nazirIp = sys.argv[1]
        mixIp = sys.argv[2]
        numberOfPartners = sys.argv[3]
        filePath = sys.argv[4]
        if (nazirIp is False or mixIp is False or numberOfPartners is False or filePath is False):
            print("Invalid parameters")
            #print("Usage:", '"MicroMintSimulator u k c w"')
            #print("For example:", '"python3 MicroMintSimulator.py 16 2 10000 22"')
            exit()
        else:
            return {"nIp":nazirIp, "mixIp":mixIp, "nbr":numberOfPartners, "path": filePath}
    except:
        print("Invalid parameters")
        #print("Usage:", '"MicroMintSimulator u k c w"')
        #print("For example:", '"python3 MicroMintSimulator.py 16 2 10000 22"')
        exit()

def getFile(filePath):
    try:
        testcap = open(filePath, "rb")
        capfile = savefile.load_savefile(testcap, layers=2, verbose=True)
        testcap.close()
        return capfile
    except:
        print("Invalid file path")
        exit()

if __name__ == "__main__":
    parameters = getParameters()
    nazirIp = parameters['nIp']
    mixIp = parameters['mixIp']
    numberOfPartners = parameters['nbr']
    capFile = getFile(parameters['path'])
    # print the packets
    print ('timestamp\teth src\t\t\teth dst\t\t\tIP src\t\tIP dst')
    for pkt in capFile.packets:
        timestamp = pkt.timestamp
        # all data is ASCII encoded (byte arrays). If we want to compare with strings
        # we need to decode the byte arrays into UTF8 coded strings
        eth_src = pkt.packet.src.decode('UTF8')
        eth_dst = pkt.packet.dst.decode('UTF8')
        ip_src = pkt.packet.payload.src.decode('UTF8')
        ip_dst = pkt.packet.payload.dst.decode('UTF8')
        if(ip_dst == mixIp):
            ip_dst = "Mix"
        if(ip_src == mixIp):
            ip_src = "Mix"
        if(ip_dst == nazirIp):
            ip_dst == "Nazir"
        if(ip_src == nazirIp):
            ip_src = "Nazir"    
        print ('{}\t\t{}\t{}\t{}\t{}'.format(timestamp, eth_src, eth_dst, ip_src, ip_dst))
