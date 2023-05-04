import clamd

def spawnClamAVDaemon():
    clamDaemonSocket = clamd.ClamdUnixSocket()
    try:
        pass#print(clamDaemonSocket.ping())
    except clamd.ConnectionError:
        clamDaemonSocket = clamd.ClamdNetworkSocket()
    return clamDaemonSocket

## This scans a file at rest on the disk
def scanFileClamAV(clamDaemon, filePath):
    result = clamDaemon.scan(filePath)
    return result

