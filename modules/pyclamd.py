import pyclamd

def spawnClamAVDaemon():
    cd = pyclamd.ClamdUnixSocket()
    try:
        #print(cd.ping())
        pass
    except pyclamd.ConnectionError:
        cd = pyclamd.ClamdNetworkSocket()
    return cd

## This scans a file at rest on the disk
def scanFileClamAV(clamDaemon, filePath):
    result = clamDaemon.scan_file(filePath)
    #file = open(filePath, "r", encoding="utf-8")
    return result