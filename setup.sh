#cp /detection/clamAVSigs/* /var/lib/clamav

sourceFiles="/filesToScan/*"
destinationDirectory="machine-learning/data/filesToClassify/"

for FILE in $sourceFiles
do
    fileMimeType=$(file --mime $FILE)
    if [[ $fileMimeType == *"application/"*"exec"* ]]; then
        cleanName=$(basename -- "$FILE")
        objdump -d $FILE | sed  '/[^\t]*\t[^\t]*\t/!d' | cut -f 3 | sed 's/ .*$//' > ${destinationDirectory}CUSTOM_${cleanName}.asm
    fi
done

/etc/init.d/clamav-daemon start

python3 mainProgram.py

cd machine-learning/
python3 machineLearning.py
cd ..