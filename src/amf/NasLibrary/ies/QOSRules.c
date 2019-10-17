#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "QOSRules.h"

int encode_qos_rules ( QOSRules qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	uint8_t *lenqosrule = NULL;
	uint8_t lenmoment = 0;
	uint8_t bitstream = 0;
	uint16_t lenqosrule_16 = 0;
    uint32_t encoded = 0;
    int encode_result = 0;
	int i = 0,j = 0;

    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,QOS_RULES_MINIMUM_LENGTH , len);
    

	if( iei > 0 )
	{
		*buffer=iei;
		encoded++;
	}
	
	*(buffer + encoded) = qosrules.lengthofqosrulesie/(1<<8);
	encoded++;
	*(buffer + encoded) = qosrules.lengthofqosrulesie%(1<<8);
	encoded++;

	for(i=0;i<qosrules.lengthofqosrulesie;i++)
	{
		ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].qosruleidentifer,encoded);
		
		lenqosrule = buffer + encoded;
		encoded++;
    	encoded++;
		lenmoment = encoded;

		bitstream = (uint8_t)(qosrules.qosrulesie[i].ruleoperationcode << 5);
		bitstream |= (uint8_t)(qosrules.qosrulesie[i].dqrbit << 4);
		bitstream |= (uint8_t)qosrules.qosrulesie[i].numberofpacketfilters;
		ENCODE_U8(buffer+encoded,bitstream,encoded);

		if((bitstream >> 5) == MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS)
		{
			for(j = 0;j < (bitstream & 0x0f);j++)
			{
				ENCODE_U8(buffer+encoded,(uint8_t)qosrules.qosrulesie[i].packetfilterlist.modifyanddelete[j].packetfilteridentifier,encoded);
			}
			ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].qosruleprecedence,encoded);
			ENCODE_U8(buffer+encoded,(uint8_t)((qosrules.qosrulesie[i].segregation<<6) | (qosrules.qosrulesie[i].qosflowidentifer & 0x3f)),encoded);
		}
		else if(((bitstream >> 5) == CREATE_NEW_QOS_RULE) || ((bitstream >> 5) == MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS) || ((bitstream >> 5) == MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS))
		{
			for(j = 0;j < (bitstream & 0x0f);j++)
			{
				ENCODE_U8(buffer+encoded,(uint8_t)((qosrules.qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfilterdirection << 4)|(qosrules.qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfilteridentifier & 0x0f)),encoded);

				uint8_t *lenghtofpacketfiltercontents = buffer + encoded;
				encoded++;

				ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfiltercontents.component_type,encoded);
				
				if(qosrules.qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfiltercontents.component_type != QOS_RULE_MATCHALL_TYPE)
				{
					if ((encode_result = encode_bstring (qosrules.qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfiltercontents.component_value, buffer + encoded, len - encoded)) < 0)
        				return encode_result;
					else
		    			encoded += encode_result;
				}
        		
				*lenghtofpacketfiltercontents = encode_result+1;
			}
			ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].qosruleprecedence,encoded);
			ENCODE_U8(buffer+encoded,(uint8_t)((qosrules.qosrulesie[i].segregation<<6) | (qosrules.qosrulesie[i].qosflowidentifer & 0x3f)),encoded);
		}
		lenqosrule_16 = encoded - lenmoment;
		*lenqosrule = lenqosrule_16/(1<<8);
		lenqosrule++;
		*lenqosrule = lenqosrule_16%(1<<8);
	}
   
    return encoded;
}

int decode_qos_rules ( QOSRules * qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint16_t ielen=0;
	int decode_result = 0;
	uint16_t numberrules = 0;
	uint8_t *buffer_tmp = NULL;
	uint16_t lenqosrule = 0;
	uint8_t bitstream = 0;
	int i=0,j=0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    numberrules = *(buffer + decoded);
    decoded++;
    numberrules = ( numberrules << 8)+*(buffer + decoded);
    decoded++;
	
	buffer_tmp = buffer + decoded;
	for(i=0;i<numberrules;i++)
	{
		ielen = *(buffer + ielen + 1) + 1;
	}
	
    CHECK_LENGTH_DECODER (len - decoded, ielen);

	qosrules->lengthofqosrulesie = numberrules;

	qosrules->qosrulesie = (QOSRulesIE *)calloc(numberrules,sizeof(QOSRulesIE));
	for(i=0;i<numberrules;i++)
	{
		DECODE_U8(buffer+decoded,qosrules->qosrulesie[i].qosruleidentifer,decoded);

		decoded++;
		decoded++;
		/*lenqosrule = *(buffer + decoded);
		decoded++;
		lenqosrule = (lenqosrule << 8)+*(buffer + decoded);
    	decoded++;
		lenmoment = encoded;
*/		
		DECODE_U8(buffer+decoded,bitstream,decoded);
		qosrules->qosrulesie[i].ruleoperationcode = (bitstream>>5);
		qosrules->qosrulesie[i].dqrbit = (bitstream>>4)&0x01;
		qosrules->qosrulesie[i].numberofpacketfilters = bitstream&0x0f;

		if(qosrules->qosrulesie[i].ruleoperationcode == MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS)
		{
			qosrules->qosrulesie[i].packetfilterlist.modifyanddelete = (ModifyAndDelete *)calloc(qosrules->qosrulesie[i].numberofpacketfilters,sizeof(ModifyAndDelete));
			for(j = 0;j < qosrules->qosrulesie[i].numberofpacketfilters;j++)
			{
				DECODE_U8(buffer+decoded,bitstream,decoded);
				qosrules->qosrulesie[i].packetfilterlist.modifyanddelete[j].packetfilteridentifier = bitstream&0x0f;
			}
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].qosruleprecedence = bitstream;
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].segregation = (bitstream>>6)&0x01;
			qosrules->qosrulesie[i].qosflowidentifer = bitstream&0x3f;
		}
		else if((qosrules->qosrulesie[i].ruleoperationcode == CREATE_NEW_QOS_RULE) || (qosrules->qosrulesie[i].ruleoperationcode == MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS) || (qosrules->qosrulesie[i].ruleoperationcode == MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS))
		{
			qosrules->qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace = (Create_ModifyAndAdd_ModifyAndReplace *)calloc(qosrules->qosrulesie[i].numberofpacketfilters,sizeof(Create_ModifyAndAdd_ModifyAndReplace));
			for(j = 0;j < qosrules->qosrulesie[i].numberofpacketfilters;j++)
			{
				DECODE_U8(buffer+decoded,bitstream,decoded);
				qosrules->qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfilterdirection = (bitstream>>4)&0x03;
				qosrules->qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfilteridentifier = bitstream&0x0f;
				
				uint8_t *lenghtofpacketfiltercontents = *(buffer + decoded)-1;
				decoded++;

				DECODE_U8(buffer+decoded,bitstream,decoded);
				qosrules->qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfiltercontents.component_type = bitstream;
				
				if(qosrules->qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfiltercontents.component_type != QOS_RULE_MATCHALL_TYPE)
				{
					if ((decode_result = decode_bstring (&qosrules->qosrulesie[i].packetfilterlist.create_modifyandadd_modifyandreplace[j].packetfiltercontents.component_value, lenghtofpacketfiltercontents, buffer + decoded, len - decoded)) < 0)
	        			return decode_result;
	    			else
	        			decoded += decode_result;
				}
				
			}
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].qosruleprecedence = bitstream;
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].segregation = (bitstream>>6)&0x01;
			qosrules->qosrulesie[i].qosflowidentifer = bitstream&0x3f;
		}
	}
	
	return decoded;
}

