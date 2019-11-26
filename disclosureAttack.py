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
            print("Usage:", '"disclosureAttack srcIp mixIp n filepath"')
            print("For example:", '"python3 disclosureAttack.py 127.0.0.1 255.255.255.255 2 ./pcapFile.pcap"')
            exit()
        else:
            return {"nIp":nazirIp, "mixIp":mixIp, "nbr":numberOfPartners, "path": filePath}
    except:
        print("Invalid parameters")
        print("Usage:", '"disclosureAttack srcIp mixIp n filepath"')
        print("For example:", '"python3 disclosureAttack.py 127.0.0.1 255.255.255.255 2 ./pcapFile.pcap"')
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

def isDisjoint(setToBeCompared, sets):
    for s in sets:
        if(s == setToBeCompared and len(s) == len(setToBeCompared)): # We dont want to compare a set to itself. 
            continue
        if(len(setToBeCompared.intersection(s)) is not 0): # Intersection between the sets => not disjoint

            return False

    return True

def learningPhase(packets, nazirIp):
    sets = []
    srcList = []
    dstList = []
    nazirSent = False
    for index in range(len(packets)):
        timestamp = packets[index].timestamp
        # all data is ASCII encoded (byte arrays). If we want to compare with strings
        # we need to decode the byte arrays into UTF8 coded strings
        eth_src = packets[index].packet.src.decode('UTF8')
        eth_dst = packets[index].packet.dst.decode('UTF8')
        ip_src = packets[index].packet.payload.src.decode('UTF8')
        ip_dst = packets[index].packet.payload.dst.decode('UTF8')
        srcList.append(ip_src)
        dstList.append(ip_dst)
        if(len(srcList) == 12):
            if (nazirSent and isDisjoint(set(dstList), sets)): # if true => save set.
                print("Found disjoint set:", set(dstList))
                sets.append(set(dstList))   
                nazirSent = False
            elif(nazirSent and isDisjoint(set(dstList), sets) == False):  # else if nazir sent but not disjoint => nazirSent = false
                nazirSent = False
            else:
                for srcIp in srcList:
                    if (srcIp == nazirIp):
                        nazirSent = True
                        break
            dstList.clear()
            srcList.clear()

    return sets

def excludingPhase(disjointSets):
    excludedSet = set()
    for disjointSet in disjointSets:
        if (isDisjoint(excludedSet ,disjointSet)):
            excludedSet.add(disjointSet)
    pass

if __name__ == "__main__":
    parameters = getParameters()
    nazirIp = parameters['nIp']
    mixIp = parameters['mixIp']
    numberOfPartners = parameters['nbr']
    capFile = getFile(parameters['path'])
    packets = capFile.packets
    disjointSets = learningPhase(packets, nazirIp)
    