import yara
import glob
import os

##
## This is an alternate approach to my normal YARA scanner, this is to circumvent potential permissions issues using another way of scanning and locating files
##


path = "/"
files = []

#completeRuleList = ["./yararulesComplete.yara","./yararulesBinary.yara"]
completeRuleList = glob.glob("/home/eddy/final-year-project/YaraRules/*")

for ruleDirectory in completeRuleList:
    print("\n\n STARTING RULES FOR {0}".format(str(ruleDirectory)))
    for r, d, f in os.walk(path):
        for file in files:
            rules = yara.compile(ruleDirectory)

            match = rules.match(file) #I'd like to find away to point it to a process via PID, this should be possible and allow for dynamic analysis
            
            if(match != []):
                print("{1}   --TRIGGERED BY--   {0}".format(str(file),str(match)))
            else:
                #print("NO TRIGGERS FOR FILE--   {0}".format(str(file)))
                pass

print(path)
print(files)