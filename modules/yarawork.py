import yara
import glob
    
def yaraRulesDiscover(directory):
    # Suffixes the directory with a wildcard for use with glob
    wildcardDirectory = directory+"/*"
    # This creates and returns a list of rule files
    completeRuleList = glob.glob(wildcardDirectory)
    return completeRuleList

def yaraScanDirectoryAndPrint(fileList, ruleList):
    # Empty dictionary defined here
    yaraMatches = {}    
    # Iterating over every file in the directory
    for fileToScan in fileList:
        # For the file in this iteration of the loop, check if it matches any rules
        yaraScanResult = yaraScanSingleFileAndPrint(fileToScan, ruleList)
        # Append the name of the file and whether it matched with anything to the dictionary
        yaraMatches.update({fileToScan:yaraScanResult})
    # Return the dictionary
    return yaraMatches

def yaraScanSingleFileAndPrint(fileToScan, ruleList):
    # Creating an empty matches list
    matches = []    
    # Iterating over every rule in the list so that they can be applied to the file
    for rule in ruleList:
        # Compiling the individual rule so that yara can interpret it
        ruleCompiled = yaraRulesCompile(rule)
        # Using the scanFile function to check for rule matches
        yaraScanResult = yaraScanFile(ruleCompiled, fileToScan)
        # Add the name of the rule to a returned list if it matches
        if(yaraScanResult != []):
                matches += yaraScanResult 
    # Return a list of rules that matched for this file
    return matches

def yaraRulesCompile(ruleDirectory):
    # Compile the rule file into an object that yara can interpret
    rules = yara.compile(ruleDirectory) 
    return rules

def yaraScanFile(rules, file):
    # This checks if a given rule matches a given file and returns the result
    yaraMatch = rules.match(file)
    return yaraMatch