sourceFiles="./dataset-training-full-unsanitised/*.asm"
destinationDirectory="./dataset-training-full-sanitised/"
for file in $sourceFiles
do
	 cleanName=$(basename -- "$file")
	 strings $file > $destinationDirectory$cleanName
	 rm $file
	 #echo $destinationDirectory$cleanName
done
