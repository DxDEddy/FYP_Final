from modules.yarawork import *
from modules.clamd import *
import pandas as pd
from tabulate import tabulate

scanDirectory = "/filesToScan/*"

print("\n---------------------------------------YARA---------------------------------------\n\n")

#yaraScanDirectoryAndPrint needs two arguments - The list of files to scan and the list of yara rule files
yaraResults = yaraScanDirectoryAndPrint(
    glob.glob(scanDirectory),                       # This creates a list of all of the files in the directory that needs to be scanned
    yaraRulesDiscover("./detection/yaraRules")      # This provides the list of all of the yara rule files so that they can be compiled individually
) #yaraResults returns a dictionary

# This iterates over every file in the dictionary and removes the path to that file, leaving only the name
yaraResults =  {k.replace("/filesToScan/",""): v for k, v in yaraResults.items()}

# This prints the dictionary in table format with headers for the filename and which yara rules matched
print(tabulate(zip(yaraResults.keys(), yaraResults.values()), headers=["FILE", "YARA RULE MATCH"], tablefmt="psql"))

print("\n\n---------------------------------------CLAM---------------------------------------\n\n")

#This is the object that represents the connection to the clam daemon
clamDaemon = spawnClamAVDaemon()

#An empty dict object is created so that the results can be placed into a table
clamResults = {}

# This iterates over every file in the directory containing the files to scan
for givenFile in glob.glob(scanDirectory):
    # The dictionary is updated with the name of the file as well as which signature matched to it, if any
    # This returns a string in format "FILENAME,SIGNATURE" which needs to be split 
    clamResults.update(scanFileClamAV(clamDaemon, givenFile))

# This iterates over every filename in the dictionary and removes the path
clamResults =  {k.replace("/filesToScan/",""): v for k, v in clamResults.items()}

# An empty list is created for use in the table to present the results
clamResultsFiltered = []
# This loop iterates over every dictionary entry and splits the string containing both the filename and the signature match 
for result in clamResults.values():
    resultSplit = str(result).split(",")
    # The signature is isolated from the split string and put into the list
    clamResultsFiltered.append(resultSplit[1].translate({ord(i): None for i in ')\"\''}))

# The results are tabulated by getting the keys of the dictionary and the list of results and merging them into a dictionary again
print(tabulate(zip(clamResults.keys(), clamResultsFiltered), headers=["FILE", "SIGNATURE MATCH"], tablefmt="psql"))

print("\n\n--Classification of executable files in the scan directory using machine learning--\n\n")