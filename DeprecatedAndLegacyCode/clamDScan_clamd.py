#pyclamd lib - clamd is deprecated and so is this file as of now
#USER "clamav" NEEDS PERMISSIONS FOR THIS TO RUN - Add it to the ROOT group in /etc/passwd


#import pyclamd 

#cd = pyclamd.ClamdUnixSocket()
#try:
    #print(cd.ping())
#    pass
#except pyclamd.ConnectionError:
#    cd = pyclamd.ClamdNetworkSocket()
    #print(cd.ping())

#strEICAR = cd.EICAR()
#strEICAR = str(strEICAR)

#print(cd.version().split()[0])
#print(cd.reload())
#print(cd.stats().split()[0])
#
#print("EICAR SCAN:")
#open('/tmp/EICAR','w').write(strEICAR)
#print(cd.scan_file('/tmp/EICAR'))

#print("\n\nNO EICAR SCAN:")
#open('/tmp/NO_EICAR','w').write('no virus in this file')
#print(cd.scan_file('/tmp/NO_EICAR') is None)

#print("\n\nFinal Results")
#print(cd.scan_stream(cd.EICAR()))

def spawnClamAVDaemon():
    import clamd
    clamDaemon = clamd.ClamdUnixSocket()
    return clamDaemon

def scanFileClamAV(clamDaemon, filePath):
    scanResult = clamDaemon.scan(filePath)
    return scanResult


#print(scanFileClamAV(spawnClamAVDaemon(), "/home/eddy/final-year-project/ScanHere/eicar.com"))
