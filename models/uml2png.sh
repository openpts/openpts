#!/bin/sh

BIOS_UMLS="bios_pcr0.uml bios_pcr1.uml bios_pcr2.uml bios_pcr3.uml bios_pcr4.uml bios_pcr5.uml bios_pcr6.uml bios_pcr7.uml"
GRUB_UMLS="grub_pcr4.uml grub_pcr5.uml grub_pcr8.uml grub_pcr8knoppix.uml grub_pcr8vmm.uml"
IMA_UMLS="ima_pcr10.uml ima_pcr10wog.uml f12_ima_pcr10.uml"
VMM_UMLS="vmm_pcr17.uml"

for modelfile in $BIOS_UMLS; do
	modelfile=`basename $modelfile .uml`
	../src/uml2dot -o $modelfile.dot $modelfile.uml
    cat $modelfile.dot | sed -e "s/, digest/\\\\ndigest/g" > $modelfile.dot2
	dot -Tpng $modelfile.dot2 -o $modelfile.png
	#eog $modelfile.png
done


for modelfile in $GRUB_UMLS; do
	modelfile=`basename $modelfile .uml`
	../src/uml2dot -o $modelfile.dot $modelfile.uml
    cat $modelfile.dot | sed -e "s/, digest/\\\\ndigest/g" > $modelfile.dot2
	dot -Tpng $modelfile.dot2 -o $modelfile.png
	#eog $modelfile.png
done

for modelfile in $IMA_UMLS; do
	modelfile=`basename $modelfile .uml`
	../src/uml2dot -o $modelfile.dot $modelfile.uml
	dot -Tpng $modelfile.dot -o $modelfile.png
	#eog $modelfile.png
done

for modelfile in $VMM_UMLS; do
	modelfile=`basename $modelfile .uml`
	../src/uml2dot -o $modelfile.dot $modelfile.uml
	dot -Tpng $modelfile.dot -o $modelfile.png
	#eog $modelfile.png
done




