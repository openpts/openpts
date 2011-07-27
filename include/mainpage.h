/** @mainpage OpenPTS (C version) Documents
*
*
* @author Seiji Munetoh <munetoh@users.sourceforge.jp>
* @date 2010-10-15
*
* @section intro Introduction
* 
* OpenPTS is an implemantation of TCG Platform Trust Services.
*
* @section arch Architecture
*
* Refer the Design Document (design.pdf)
*
* @section model FSM Models (x86 PC)
* 
* OpenPTS uses Finite State Models which describe a transitive trust sequences.
*
* <TABLE>
*   <TR> 
*     <TD>PCR index</TD>
*     <TD>Level</TD>
*     <TD>Name</TD>
*     <TD>State Diagram (in PNG)</TD>
*   </TR>
*   <TR> 
*     <TD>0</TD>
*     <TD>0</TD>
*     <TD>BIOS CRTM</TD>
*     <TD><A href="../images/bios_pcr0.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>1</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr1.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>2</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr2.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>3</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr3.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>4</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr4.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>5</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr5.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>6</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr6.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>7</TD>
*     <TD>0</TD>
*     <TD>BIOS</TD>
*     <TD><A href="../images/bios_pcr7.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>4</TD>
*     <TD>1</TD>
*     <TD>GRUB IPL (common)</TD>
*     <TD><A href="../images/grub_pcr4.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>4</TD>
*     <TD>1</TD>
*     <TD>GRUB IPL (standalone, HDD)</TD>
*     <TD><A href="../images/grub_pcr4hdd.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>4</TD>
*     <TD>1</TD>
*     <TD>GRUB IPL (standalone, CD)</TD>
*     <TD><A href="../images/grub_pcr4cd.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>5</TD>
*     <TD>1</TD>
*     <TD>GRUB IPL</TD>
*     <TD><A href="../images/grub_pcr5.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>8</TD>
*     <TD>1</TD>
*     <TD>GRUB IPL</TD>
*     <TD><A href="../images/grub_pcr8.png">Image</A></TD>
*   </TR>
*   <TR> 
*     <TD>10</TD>
*     <TD>1</TD>
*     <TD>Linux IMA (Fedora12)</TD>
*     <TD><A href="../images/f12_ima_pcr10.png">Image</A></TD>
*   </TR>
* </TABLE>
*
*
*
*/

// $ cp models/*.png doc/html/
// $ convert -sample 50%x50% doc/html/bios_pcr0.png  doc/html/bios_pcr0_small.png
// $ doxygen doxygen.conf
