# Final Year Project - UP939720

## How to build the container (Linux)

From the root directory of the project, run this command:
docker build --pull --rm -f "Dockerfile" -t finalyearproject:latest "."

## How to run the container (Linux)

Run this command to import the container to docker:
docker run --rm -it  finalyearproject:latest

## How to save the container (Linux)

A functioning installation of docker is required in advance.
The container must also be built at least once on the host system.
Run the following command to save the built container to the disk:
docker save finalyearproject:latest > finalyearproject.tar

## Rebuilding the dataset - Advanced

Manually rebuilding the dataset is almost always unnecessary and ill-advised, although if it must be rebuilt, these steps should be followed.

Extract all of the .asm files from the dataset ZIP downloaded from the source into this folder:
"/machine-learning/data/dataset-training-full-unsanitised"

The files extracted from the dataset will be encoded in binary, this WILL cause errors in the model, so they must be sanitised and converted
Navigate to "/machine-learning/data/" and execute the "santiseData.sh" script from that folder to start the sanitisation process.

Once the script has executed, if the pickle files are absent, the docker container can be built or the machine learning script will re-build the dataset when run outside of the container.

Compiling a docker container with the full dataset is ill-advised due to the size of the uncompressed dataset, executing the machine learning file outside of the container will automatically generate sensible subsets if the pickle files are absent.

## Parameters that can be modified

| File Path (Relative to project root)            | Purpose                                                                                                               |
|-------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| /detection/clamAVSigs/                          | main.cvd and daily.cvd files can be placed in here to override the files downloaded during container setup            |
| /detection/scanHere/                            | Any files to be scanned and classified are placed inside this directory so they are built into the container          |
| /detection/yaraRules/                           | Yara rules are placed in this directory so that they can be deployed during a scan                                    |
| /machine-learning/data/custom-dataset-sanitised/| ASCII or UTF formatted .asm files can be placed in class folders to train the machine learning model using extra data |
| /machine-learning/data/filesToClassify/         | .asm files can be placed here for classification without going through the scan process                               |


## Key directories and their purpose

| Directory (Relative to project root) | Purpose                                                                                     |
|--------------------------------------|---------------------------------------------------------------------------------------------|
| /detection/                          | Contains yara rules, files that need to be scanned by the application and clamAV Signatures |
| /machine-learning/                   | Contains all of the data and code required for the machine learning model to function       |
| /modules/                            | This contains the clam and yara python module files that I programmed                       |

## Key files and their purpose

| File Path (Relative to project root)        | Purpose                                                                                                          |
|---------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| /Dockerfile                                 | This is the docker manifest that is used to build the container                                                  |
| /mainProgram.py                             | This is the python script that executes the detection component of the program                                   |
| /README.md                                  | This is the manual for the program                                                                               |
| /setup.sh                                   | This is an auxilliary script used to execute commands inside the container after the dockerfile is completed     |
| /machine-learning/finalDF.pickle            | This is the dataset used to train the model - It is pre-processed and using this data is strongly for timeliness |
| /machine-learning/finalDFCustom.pickle      | This is a custom dataset used to train the model, it is regenerated when the container is run                    |
| /machine-learning/generate.sh               | This is used to generate a test case as a safe demonstration of the model's classification capabilities          |
| /machine-learning/instructionListSubset.txt | This is a list of 350 instructions that are used as features for the model                                       |
| /machine-learning/machineLearning.ipynb     | This is the jupyter script that is maintained alongside the main python script for data visualisation            |
| /machine-learning/machineLearning.py        | This is the main python script that performs the machine learning tasks for the artefact                         |
| /AnExampleofArtefactOutput.txt              | This is an example of the output created by the artefact when the docker container is run                        |
