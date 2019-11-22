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
    nazirSent = False
    sets = []
    srcList = []
    dstList = []
    for index in range(len(capFile.packets)):
        timestamp = capFile.packets[index].timestamp
        # all data is ASCII encoded (byte arrays). If we want to compare with strings
        # we need to decode the byte arrays into UTF8 coded strings
        eth_src = capFile.packets[index].packet.src.decode('UTF8')
        eth_dst = capFile.packets[index].packet.dst.decode('UTF8')
        ip_src = capFile.packets[index].packet.payload.src.decode('UTF8')
        ip_dst = capFile.packets[index].packet.payload.dst.decode('UTF8')
        srcList.append(ip_src)
        dstList.append(ip_dst)
        if(index % 12 == 0 and index is not 0):
            if (nazirSent):
                sets.append(list(dstList))   
                nazirSent = False
            for srcIp in srcList:
                if (srcIp == nazirIp):
                    nazirSent = True
                    break
            dstList.clear()
            srcList.clear()
    for s in sets:
        print("set:", s)