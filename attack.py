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
        file = open(filePath, "rb")
        capfile = savefile.load_savefile(testcap, layers=2, verbose=True)
        file.close()
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
    print("working!")
