sourceFiles="/bin/*"
destinationDirectory="/home/eddy/finalyearproject/machine-learning/data/custom-dataset-sanitised/class-5/"
for file in $sourceFiles
do
	 cleanName=$(basename -- "$file")
	 objdump -d $file | sed  '/[^\t]*\t[^\t]*\t/!d' | cut -f 3 | sed 's/ .*$//' > ${destinationDirectory}CUSTOM_${cleanName}.asm

done
