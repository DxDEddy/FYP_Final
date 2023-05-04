import os
from datetime import datetime

def CreateFolder(foldername):
    Date = datetime.today().strftime("%d-%y__")
    Time = datetime.now().strftime("%H:%M")

    DateTimeVar = foldername + Date + Time


    CurrentWorkingDirectory = os.getcwd()
    DestinationFolder = CurrentWorkingDirectory+"/DataStructures/"+DateTimeVar
    CreateDirectoryDestination = os.path.join(CurrentWorkingDirectory, DestinationFolder)

    if not os.path.exists(CreateDirectoryDestination):
        os.makedirs(CreateDirectoryDestination)

CreateFolder("SCAN__")