# # Multi-Classification Machine Learning for Malware Analysis
# ## 9 Types of Malware in this dataset:
# 1. Ramnit         - RAT
# 2. Lollipop       - Adware
# 3. Kelihos_ver3   - RAT
# 4. Vundo          - Adware
# 5. Simda          - Botnet
# 6. Tracur         - Malicious Browser Plugin
# 7. Kelihos_ver1   - RAT
# 8. Obfuscator.ACY - Obfuscates other malware/information
# 9. Gatak          - RAT
# 
# ## Game Plan:
# 
# - Look into creating more metrics to show off my model
# - Improve the way I import data for the model
# - Explain my code and solution in detail
# - Port into the main program/script
# 
# 

import sys
import os
import re
import csv
import shutil
import heapq
import codecs
import json
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path #Convert all directory accesses to this
from functools import reduce
import glob

import pandas as pd
import numpy as np

from sklearn import metrics
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.inspection import permutation_importance
from sklearn import svm
from sklearn.model_selection import train_test_split

import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

import pickle
import warnings


pd.options.mode.chained_assignment = None  # default='warn'
warnings.simplefilter(action='ignore', category=pd.errors.PerformanceWarning)
warnings.simplefilter(action='ignore', category=FutureWarning)


####################################################################################################################
####################################################################################################################
####################################################################################################################

def createFullDirectory(mainDirectory,subDirectory):
    #
    # This function is used to concatenate two directories
    #
    return str(mainDirectory+subDirectory)

def createFullPathToFile(fullDirectory, fileName):
    #
    # This function is used to concatenate a directory and filename
    #
    return str(fullDirectory+fileName)

def listFilesInDirectory(directoryContainingFiles):
    #
    # This returns a list() of the names of files in a directory
    #
    return glob.glob(directoryContainingFiles) 

def stripFilePathAndExtension(filePath):
    #
    # This returns the filename without the path and extension
    #
    return Path(filePath).stem

def replaceFilePathAndExtension(filePath, prefixToInsert, suffixToInsert):#filePath, prefixToStrip, prefixToInsert, suffixToStrip, suffixToInsert):
    #
    # This replaces the file path and extension with the given replacements
    #
    filePath = Path(filePath).stem
    filePath = prefixToInsert+filePath+suffixToInsert
    return filePath

def printDataFrame(dataframe):
    #
    # This pretty prints a dataframe
    #
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        print(dataframe)

def zeroOutDataframe(dataframe):
    #
    # This fills null cells in a dataframe with zeros
    #
    dataframe = dataframe.fillna(0)
    return dataframe

def countEntriesInDataframe(dataframe):
    #
    # This counts the amount of non-zero cells in a dataframe
    #
    return np.count_nonzero(dataframe)

def sortDictionary(dictionary):
    #
    # This sorts a dictionary in ascending order
    #
    returnVal = sorted(dict(Counter(dictionary)).items(), key=lambda kv:
                 (kv[1], kv[0]))
    return returnVal

def fileNewlineIntoList(filePath):
    #
    # This takes a filepath as a parameter and returns the contents of the file in a list, seperated by newline
    #
    lineList = []
    with open(filePath) as openFile:
        for line in openFile:
            temp = line.strip()
            lineList.append(temp)
    return lineList

def stripNewlineAndWhitespace(textStringToStrip):
    #
    # This removes the whitespace and newlines from a string
    #
    textStringToStrip = textStringToStrip.replace("\t","")
    textStringToStrip = textStringToStrip.replace("\n","")
    textStringToStrip = textStringToStrip.replace(" ","")
    return textStringToStrip

def stripNewlineAndWhitespaceFromList(listToStrip):
    #
    # This removes the whitespace and newlines from every string in a list
    #
    for i in range(0,len(listToStrip)):
        listToStrip[i] = stripNewlineAndWhitespace(listToStrip[i])
    return listToStrip

def regexSearchFile(filePath, regexPattern):
    #
    # This returns all of the matches in a file that match the given regex pattern
    #
    with open(filePath) as openFile:
        matches = re.findall(regexPattern, openFile.read())
    openFile.close()
    return matches

def cleanFileNameList(fileNameList,malwareClass, sortedDatasetDirectory): #NEED TO PORT THIS
    #
    # NEED TO FIX THIS
    #
    filePathToNameDict = {}
    for i in range(0, len(fileNameList)): 
        strippedFile = stripFilePathAndExtension(fileNameList[i]) #FIX THIS TO ALLOW FOR DIFFERENT CLASSES
        filePathToNameDict[strippedFile] = fileNameList[i]
        fileNameList[i] = strippedFile
    return fileNameList

def generateClassDataFrame(listColumnsToUse,listRowsToUse):
    #
    # This creates an empty dataframe using two lists for the columns and index respectively
    #
    return zeroOutDataframe(pd.DataFrame(columns=listColumnsToUse,index=listRowsToUse))

def moveFilesToClassFolders(backupFileList, fullFileNamesListFromCSV, unsortedDataset,sortedDataset):
    #
    # This reads the CSV mapping filenames to classes
    # It iterates through the CSV's index to run an operation on every file
    # The operation gets the filename alone and tries to copy it to it's folder
    # The folder is determined by using a lookup of that clean filename in the index and checking the cell value of that index
    #
    fullFileNamesListFromCSV.set_index("Id",inplace=True)
    for fileIndex in range(0,len(backupFileList)): # file is the full path to the file, fileClean is just the name of the file without extension
        fileClean = stripFilePathAndExtension(backupFileList[fileIndex],unsortedDataset,".asm")
        try:
            shutil.copyfile(backupFileList[fileIndex],sortedDataset+"class-"+str(fullFileNamesListFromCSV.loc[fileClean,"Class"])+"/"+str(fullFileNamesListFromCSV.loc[fileClean].name)+".asm")
        except:
            fileIndex = fileIndex + 1

def generateFilenameToDirectoryDict(listOfFiles):
    #
    # This takes a list of files in a directory
    # It then creates a dictionary that maps the clean names to the paths
    #
    filePathToNameDict = {}
    for file in listOfFiles:
        filePathToNameDict[Path(file).stem] = file
    return filePathToNameDict

def populateMalwareDataframe(fileDirectoryTopLevel,instructionList):
    #
    # FILL THIS IN
    #
    filePathToNameDict = generateFilenameToDirectoryDict(listFilesInDirectory(fileDirectoryTopLevel))
    dataFrame = zeroOutDataframe(pd.DataFrame(columns=instructionList,index=filePathToNameDict.keys()))

    for file in filePathToNameDict.keys(): # Go through every file in our directory
        fileDirectory = filePathToNameDict[file] # Convert using dict here
        instructionsForThisFile = stripNewlineAndWhitespaceFromList(regexSearchFile(fileDirectory,"(?:\t{3,7}       (?!db|dd)[a-zA-Z]{2,6} {1,})")) # cleaning and pulling instructions

        pandasSeriesTest = pd.Series(instructionsForThisFile).value_counts().index, pd.Series(instructionsForThisFile).value_counts().values # Counting each instruction up   
        for i in range(0, len(pandasSeriesTest[0])):
            dataFrame.loc[file,pandasSeriesTest[0][i]] = pandasSeriesTest[1][i]  #0 = instruction and 1 = count columns ||| Second value is index within that column
        
        #Optional cleaning options for my DF to merge dupe columns and group them up
        dataFrame = dataFrame.groupby(axis=1, level=0).sum() # Merges dupe columns
        #dataFrame = dataFrame.loc[:, (dataFrame != 0).any(axis=0)] # Removes columns with no values
    return dataFrame

def classDataFrameCompletion(instructionList,sortedDataset,classList,classInteger):
    #
    # FILL THIS IN
    #

    #print(sortedDataset+classList[classInteger-1]+"/*.asm")
    #print(listFilesInDirectory(sortedDataset+classList[classInteger-1]+"/*.asm"))

    
    dataFrameInFunction = generateClassDataFrame(
        instructionList,      # This is the instruction list
        cleanFileNameList(    # This is the list of files
            listFilesInDirectory(sortedDataset+classList[classInteger-1]+"/*.asm"),  # This is the directory containing the files
            classInteger,
            sortedDataset))  #This is the malware class for cleanFileNameList
    
    dataFrameInFunction = populateMalwareDataframe(
                            sortedDataset+classList[classInteger-1]+"/*.asm",
                            instructionList)

    dataFrameInFunction = zeroOutDataframe(dataFrameInFunction)
    
    dataFrameInFunction.loc[~(dataFrameInFunction==0).all(axis=1)]
    
    dataFrameInFunction.insert(0,"class",classInteger)

    print(sortedDataset+classList[classInteger-1]+"/*.asm")

    return dataFrameInFunction

def removeNanValuesFromDataframe(dataframeToSanitise):
    #
    # This sanitises the DF be replacing NAN values with zero
    #
    dataframeToSanitise = dataframeToSanitise.replace(np.nan,0)
    return dataframeToSanitise

def normaliseData(dataframeToNormalise):
    #
    # This is the normalisation function that can be used to normalise data before it is fed into the model
    #

    #return (data -trainStats["mean"]) / trainStats['std'] #Works fine, experimenting with the OTHER
    #return data.div(data.sum(axis=1), axis=0)

    dataframeToNormalise = removeNanValuesFromDataframe(dataframeToNormalise)
    return dataframeToNormalise
    
def modelSVMClassifierCreate(cValue, kernelType):
    #
    # This returns an SVM model object using the C value and the kernel type
    #
    return svm.SVC(C=cValue, kernel=kernelType)
    
def svmModelFit(modelToFit,trainingDataframe, trainingDatasetLabels):
    #
    # This fits an SVM model to a dataset alongside the labels for training
    #
    return modelToFit.fit(trainingDataframe, trainingDatasetLabels)

def svmModelPredict(modelForPrediction, dataframeToPredictWith):
    #
    # This takes a model and a dataframe to make predictions for each of the values in the dataframe
    #
    return modelForPrediction.predict(dataframeToPredictWith)

def svmModelTrain(cValue, kernelType, trainingDataframe, trainingLabels):
    #
    # This creates and fits a model by taking the c value, kernel type and the training data
    #
    return svmModelFit(
                modelSVMClassifierCreate(
                    cValue, 
                    kernelType), 
                trainingDataframe, 
                trainingLabels)
     
def trainAndPredictModel(cValue, kernelType, trainingDataframe, trainingLabels):
    #
    # This trains the model using the previous functions and creates a prediction, returning the prediction and the model
    #
    model = modelSVMClassifierCreate(cValue, kernelType)
    model = svmModelFit(model, trainingDataframe, trainingLabels)
    modelPrediction = svmModelPredict(model, trainingDataframe)

    print(kernelType+" training accuracy: ",metrics.accuracy_score(trainingLabels,modelPrediction))

    return modelPrediction, model

def createSVMConfusionMatrix(predictResults, fileClassList):
    #
    # This creates a confusion matrix for a given set of results, with the fileClassList for the tick labels
    #

    for i in range(0, len(fileClassList)): fileClassList[i] = fileClassList[i][-1]#; fileClassList[i] = int(fileClassList[i])

    ax = plt.subplot()
    cm = confusion_matrix(predictResults,predictResults)

    ax.set_xlabel("Predicted Labels") # Doesn't work
    ax.set_ylabel("True Labels") # Doesn't work
    ax.set_title("Confusion Matrix - Linear")

    sns.heatmap(cm, annot=True, ax=ax, yticklabels=fileClassList, xticklabels=fileClassList); #Semicolon removes the annoying text above the graph

def classificationReportGenerateGraph(testLabels,svmTestDatasetPrediction):
    #
    # This creates a graph to show off the classification report for the model
    #
    classificationReportDF = pd.DataFrame(classification_report(testLabels,svmTestDatasetPrediction,output_dict=True)).transpose()[:9]
    classificationReportF1Supp = classificationReportDF
    classificationReportF1Supp = classificationReportF1Supp[classificationReportF1Supp.columns[2:4]]
    classificationReportF1Supp["support"] = classificationReportF1Supp["support"].astype(int).div(100)

    fig = plt.figure()
    ax = fig.add_subplot(111)

    ax.bar(
        x=classificationReportF1Supp.index.values.tolist(), 
        height=classificationReportF1Supp["f1-score"], 
        width=0.5, 
        align='center')

    ax.bar(
        x=classificationReportF1Supp.index.values.tolist(), 
        height=classificationReportF1Supp["support"], 
        width=0.35, 
        align='center')

    f1ScoreBar = mpatches.Patch(color='blue', label="f1 score")
    supportScoreBar = mpatches.Patch(color='orange', label="support")
    ax.legend(handles=[f1ScoreBar, supportScoreBar],bbox_to_anchor=(0.5, -0.055), loc="upper center",ncol=2)
    ax.set_title("A graph demonstrating the relationship between F1 scores and support")

    plt.tight_layout()
    plt.show()

def permutationImportanceGraphPlot(model, normalisedTrainDF, trainLabels, finalDF):
    #
    # This takes the model and relevant data to derive the permutation importance for a linear SVM Model
    #
    permutationImportance = permutation_importance(model, normalisedTrainDF, trainLabels)
    featuresList = np.array(list(normalisedTrainDF.columns))
    sortedIDX = permutationImportance.importances_mean.argsort()
    mostImportantIndexesPermutation = [list(permutationImportance.importances_mean[sortedIDX]).index(i) for i in heapq.nlargest(30, permutationImportance.importances_mean[sortedIDX])]

    ### Showing the largest features
    newFeaturesList = []
    newPermutationImportanceList = []

    for i in mostImportantIndexesPermutation[::-1]:
        newFeaturesList.append(featuresList[sortedIDX][i])
        newPermutationImportanceList.append(permutationImportance.importances_mean[sortedIDX][i])

    occurancesQuantity={}
    for i in newFeaturesList[::-1]:
        occurancesQuantity.update({i:str(int(finalDF[i].mean()))})


    from sklearn import preprocessing
    plt.subplot(1, 2, 1)
    plt.barh(newFeaturesList, newPermutationImportanceList);
    plt.xlabel("Permutation Importance/Feature");
    plt.margins(x=0)
    plt.xticks([0,0.1,0.2,0.3,0.4,0.5],["0","0.2","0.4","0.6","0.8","1"])

    plt.subplot(1, 2, 2)
    plt.barh(list(occurancesQuantity.keys())[::-1], preprocessing.minmax_scale(list(occurancesQuantity.values())[::-1],feature_range=(0,0.5)));
    plt.xlabel("Mean Relative occurances/Feature");
    plt.xticks([0,0.1,0.2,0.3,0.4,0.5],["0","0.2","0.4","0.6","0.8","1"])
    plt.margins(x=0)
    plt.tight_layout()

def setupSanitisedDatasetSubset(sortedDataset, classList):
    #
    # This is used to limit the amount of files in a given class to 250 or less to maintian a manageable dataset
    #
    for fileClass in classList:
        directory = str(sortedDataset+fileClass+"/*")
        fileList = listFilesInDirectory(directory) #glob.glob(directory)

        print(fileClass)
        print(len(fileList))

        i = 0
        for i in range(0,len(fileList)):
            if(i >= 250):
                os.remove(fileList[i])
        print(len(listFilesInDirectory(sortedDataset+classList[0]+"/*.asm")))

def pickleSaveModel(model, modelSaveLocation):
    #
    # This serialises a model and saves it to the disk
    #
    pickle.dump(model, open(modelSaveLocation, "wb"))

def pickleLoadModel(modelLoadLocation):
    #
    # This is used to read a serialised model and import a trained SVM model
    #
    return pickle.load(open(modelLoadLocation,"rb"))

def collectTrainingData(workingDirectory, sortedDataset, classList):
    #
    # This returns an array of the populated datasets for each of the nine classes
    #
    #instructionList = fileNewlineIntoList(workingDirectory+"instructionListComplete.txt")
    instructionList = fileNewlineIntoList(workingDirectory+"instructionListSubset.txt")
    instructionList = [instruction.lower() for instruction in instructionList] # Making all instructions lowercase
    dataframeClassOne = classDataFrameCompletion(instructionList, sortedDataset, classList, 1)
    dataframeClassTwo = classDataFrameCompletion(instructionList, sortedDataset, classList, 2)
    dataframeClassThree = classDataFrameCompletion(instructionList, sortedDataset, classList, 3)
    dataframeClassFour = classDataFrameCompletion(instructionList, sortedDataset, classList, 4)
    dataframeClassFive = classDataFrameCompletion(instructionList, sortedDataset, classList, 5)
    dataframeClassSix = classDataFrameCompletion(instructionList, sortedDataset, classList, 6)
    dataframeClassSeven = classDataFrameCompletion(instructionList, sortedDataset, classList, 7)
    dataframeClassEight = classDataFrameCompletion(instructionList, sortedDataset, classList, 8)
    dataframeClassNine = classDataFrameCompletion(instructionList, sortedDataset, classList, 9)

    return [dataframeClassOne,dataframeClassTwo,dataframeClassThree,dataframeClassFour,dataframeClassFive,dataframeClassSix,dataframeClassSeven,dataframeClassEight,dataframeClassNine]

def collectCustomTrainingData(workingDirectory, customTrainingFilesList):
    #
    # EXPERIMENTAL
    # This is an attempt to allow for additions to the training set in a modular way
    #
    instructionList = fileNewlineIntoList(workingDirectory+"instructionListSubset.txt")
    instructionList = [instruction.lower() for instruction in instructionList]

    classifyDF = zeroOutDataframe(pd.DataFrame(columns=instructionList,index=list(customTrainingFilesList)))

    return classifyDF


def constructFinalDF(dataframesList, pickleName):
    #
    # This combines all of the datasets in the dataframe list into one
    # The function merges all of the duplicate columns, cleans any nan values and prints some basic information about the final dataframe
    #
    finalDF = pd.concat(dataframesList).drop_duplicates()
    finalDF = zeroOutDataframe(finalDF)
    finalDF.loc[~(finalDF==0).all(axis=1)]
    finalDF = finalDF.loc[:, (finalDF != 0).any(axis=0)] # Removes columns with no values
    finalDF = finalDF.sample(frac=1)
    finalDF.info()
    finalDF.to_pickle("./"+pickleName+".pickle")
    return finalDF

def createTrainTestValidSplits(finalDF, trainTestSplitSize, testToValidRatio):
    #
    # This returns train, test and valid dataframes in ratio 60 : 20 : 20
    #
    trainDF, testAndValidDF = train_test_split(finalDF, test_size=trainTestSplitSize) # previously 0.4 for 40% test+valid
    testDF, validDF = train_test_split(testAndValidDF, test_size=testToValidRatio) # previously 0.5 for 50-50 test-valid split of the original 40%

    print(f"Training Dataset rows and columns: {trainDF.shape}")
    print(f"Test Dataset rows and columns: {testDF.shape}")
    print(f"Validation Dataset rows and columns: {validDF.shape}")
    return trainDF, validDF, testDF

def writeTrainingStats(trainDF, writeLocation):
    #
    # Creates some basic training statistics for the training dataset
    #
    trainStats = trainDF.describe()
    trainStats.pop("class")
    trainStats = trainStats.transpose()
    trainStats.to_csv(writeLocation)

def createExamplePrediction(normalisedTestDF, model):
    #
    # This takes the first 10 entries in the test dataframe and gets predictions for them 
    #
    exampleSubsetDF = normalisedTestDF[:10]
    exampleResult = model.predict(exampleSubsetDF)
    dataFrameExampleResult = pd.Series(list(exampleSubsetDF.index),index=exampleResult)
    dataFrameExampleResult.head(10)
    
def createSetLabels(dataframe, nameOfDataframe):
    #
    # Given a dataframe, this function can create a set of labels by removing them from the original dataframe
    #
    createdLabels = dataframe.pop("class")
    print(nameOfDataframe+" data rows: "+str(len(createdLabels)))
    return createdLabels, dataframe

def stripInstructions(filePath):
    #
    # POSSIBLE EXPERIMENTAL
    # This function is used to pull all of the assembly instructions from a file
    # Possible not needed anymore with the objdump development 
    #
    pattern = re.compile("(?:^[a-zA-Z]{2,6}\s)")

    matches = []

    for line in enumerate(open(filePath)):
        for match in re.finditer(pattern, line):
            currentMatch = match.group()
            currentMatch = currentMatch.strip()
            matches.append(currentMatch)

def setupModelTrainingData(sortedDataset, classList, workingDirectory, unsortedDataset, baseDirectory, customDataset, readPickleFinalDF, readPickleTrainDF):
    #
    # This is the complete function to move all of the asm training data into the right place
    # It then copies the custom dataset into the training set
    # it splits the dataset into the relevant splits
    # It pickles the three dataframes after normalising then
    #
    #moveFilesToClassFolders(listFilesInDirectory(unsortedDataset+"*"),pd.read_csv(baseDirectory+"trainLabels.csv"),unsortedDataset,sortedDataset)


    shutil.copytree(customDataset,sortedDataset,dirs_exist_ok=True)
    #setupSanitisedDatasetSubset(sortedDataset, classList)
    

    
    if(readPickleFinalDF == True):
        finalDF = pd.read_pickle("./finalDF.pickle")
        finalDFCustom = pd.read_pickle("./finalDFCustom.pickle")
    else:
        dataframesList = collectTrainingData(workingDirectory,sortedDataset,classList)
        finalDF = constructFinalDF(dataframesList, "finalDF")
        dataframesListCustom = collectTrainingData(workingDirectory,customDataset,classList)
        finalDFCustom = constructFinalDF(dataframesListCustom, "finalDFCustom")

    #print(finalDF)
    print(finalDFCustom)

    trainDF, validDF, testDF = createTrainTestValidSplits(finalDF, float(0.1), float(0.1))

    normalisedTrainDF = normaliseData(trainDF)
    normalisedValidDF = normaliseData(validDF)
    normalisedTestDF = normaliseData(testDF)

    if(readPickleTrainDF == True):
        normalisedTrainDF.to_pickle("./trainDF.pickle")
        normalisedValidDF.to_pickle("./validDF.pickle")
        normalisedTestDF.to_pickle("./testDF.pickle")

    return normalisedTrainDF, normalisedValidDF, normalisedTestDF

def loadModelTrainingDataFromPickle():
    #
    # This loads the pickle files for the three types of dataframes
    #
    trainingData = pd.read_pickle(workingDirectory+"/trainDF.pickle")
    validationData = pd.read_pickle(workingDirectory+"/validDF.pickle")
    testingData = pd.read_pickle(workingDirectory+"/testDF.pickle")
    return trainingData, validationData, testingData


####################################################################################################################
####################################################################################################################
####################################################################################################################


#workingDirectory = os.getcwd()
workingDirectory = "/home/eddy/finalyearproject/machine-learning"
workingDirectory = workingDirectory+"/"
baseDirectory = workingDirectory+"data/"

classList = ["class-1","class-2","class-3","class-4","class-5","class-6","class-7","class-8","class-9"]
unsortedDataset = createFullDirectory(baseDirectory,"dataset-training-full-sanitised/")
sortedDataset = createFullDirectory(baseDirectory,"dataset-training-subset-sorted/")
customDataset = createFullDirectory(baseDirectory,"custom-dataset-sanitised/")
classifyFilesDataset = createFullDirectory(baseDirectory,"filesToClassify/")
instructionList = fileNewlineIntoList(workingDirectory+"instructionListSubset.txt")


####################################################################################################################
####################################################################################################################
####################################################################################################################


trainDF, validDF, testDF = setupModelTrainingData(sortedDataset, classList, workingDirectory, unsortedDataset, baseDirectory, customDataset, True, True)
#trainDF, validDF, testDF = loadModelTrainingDataFromPickle()


trainLabels, trainDF = createSetLabels(trainDF, "Train data")
validLabels, validDF = createSetLabels(validDF, "Valid data")
testLabels, testDF = createSetLabels(testDF, "Test data")


#svmTestDatasetPrediction, model = trainAndPredictModel(1.5, "linear", trainDF, trainLabels)
#svmPolyModelPrediction, modelPoly = trainAndPredictModel(1.5, "poly", trainDF, trainLabels)
#svmRBFModelPrediction, modelRBF = trainAndPredictModel(1.5, "rbf", trainDF, trainLabels)
#svmSigmoidModelPrediction, modelSig = trainAndPredictModel(1.5, "sigmoid", trainDF, trainLabels)




##############################################################################################################################
#model = svmModelTrain(1.5, "linear", trainDF, trainLabels)
#svmTestDatasetPrediction = svmModelPredict(model, trainDF)
#print("Linear Train Accuracy: ",metrics.accuracy_score(trainLabels,svmTestDatasetPrediction))
#svmValidationDatasetPrediction = svmModelPredict(model, validDF)
#print("Linear Validation Accuracy: ",metrics.accuracy_score(validLabels,svmValidationDatasetPrediction))
#svmTestDatasetPrediction = svmModelPredict(model, testDF)
#print("Linear Test Accuracy: ",metrics.accuracy_score(testLabels,svmTestDatasetPrediction))
##############################################################################################################################










#print(classification_report(testLabels,svmTestDatasetPrediction))
#pickleSaveModel(model,baseDirectory+"model-pickle/svmMalwareClassificationModel")


#matches = pullInstructionsFromFile(baseDirectory+"custom-dataset-sanitised/class-1/nano.asm")

#customDataframeList = collectTrainingData(workingDirectory,customDataset,classList)
#print(customDataframeList[0])
#print(printDataFrame(customDataframeList[0]))

pass#print(generateDataframeFromList("nano", matches, instructionList))
