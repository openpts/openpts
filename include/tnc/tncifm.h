/*
 
Based on TNC IF-M: TLV Binding Specification
http://www.trustedcomputinggroup.org/resources/tnc_ifm_tlv_binding_specification

The Trusted Network Connect Work Group (TNC-WG) has defined an 
open solution architecture that enables network operators to 
enforce policies regarding the security state of endpoints in 
order to determine whether to grant access to a requested 
network infrastructure. 



 */

#ifndef _TNCIFM_H_
#define _TNCIFM_H_

/*
                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                             IF-TNCCS Header                   |
       |                          Includes Overall Length              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          IF-TNCCS Message of type TNCCS-IF-M-Message          |
       |         Includes IF-M Vendor ID, IF-M Subtype and other       |
       |         fields used by TNCC and TNCS for message routing      |
==============================================================================
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         IF-M Message Header                   |
       |                  Includes Version & Message ID                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                             IF-M Attribute                    |
       |                     (e.g. Product Information)                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                             IF-M Attribute                    |
       |                     (e.g. Operational Status)                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           . . . . . .                         |
              Overview of an IF-TNCCS batch that contains an IF-M Message

 */

/*

SMI Network Management Private Enterprise Codes
http://www.iana.org/assignments/enterprise-numbers


*/



#endif // _TNCIFM_H_
