/*
    This file is part of EvoNetflowCollector.

    EvoNetflowCollector is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    EvoNetflowCollector is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with EvoNetflowCollector.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Core/Core.h>

using namespace Upp;

#include "Netflow9.h"
#include "NetflowParser.h"
#include "UtilityFunctions.h"

// Parses a Netflow v9 options template.
const bool ParseNetflow9OptionsTemplate(const PNETFLOW9_OPTIONS_TEMPLATE_HEADER optionsHeader, const unsigned int length)
{
	// Check the boundaries of the buffer, we don't want to run outside of the buffer in case of a corrupt packet.
	//if (set.FieldCount * sizeof(NETFLOW9_TEMPLATE_RECORD) > length) // scope fields + option fields!
	//{
	//	return false;
	//}
	
	return true;
}

// Parses a Netflow v9 data template.
const bool ParseNetflow9DataTemplate(const PNETFLOW9_TEMPLATE_FLOWSET_HEADER templateHeader, const unsigned int length, Vector<TemplateFieldEntry>& fields)
{
	const unsigned short fieldCount = ntohs(templateHeader->FieldCount);

	// Check the boundaries of the buffer, we don't want to run outside of the buffer in case of a corrupt packet.
	if (fieldCount * sizeof(NETFLOW9_TEMPLATE_RECORD) > length)
	{
		return false;
	}
	
	// Iterate through all template field records.
	PNETFLOW9_TEMPLATE_RECORD record = (PNETFLOW9_TEMPLATE_RECORD)((char*)templateHeader + sizeof(NETFLOW9_TEMPLATE_FLOWSET_HEADER));
	for (int i = 0; i < fieldCount; ++i, ++record)
	{
		// Save the template record.
		TemplateFieldEntry entry;
		entry.FieldType = ntohs(record->FieldType);
		entry.FieldLength = ntohs(record->FieldLength);
		fields << entry;
	}
	
	return true;
}

// Attemps to parse a Netflow v9 field using its field type and length. Output will be dynamically returned.
// The length of the buffer passed as output should be at least 64 bytes in size.
const bool ParseNetflow9Field(const unsigned short fieldType, const unsigned short fieldLength, const void* fieldData, String& output)
{
	// Decide how to parse the specified field based on the length of the field, and secondly,
	// on the type of field. For example, parse IPv4 addresses differently from packet count.
	if (fieldLength == 1)
	{
		const unsigned char value = *(unsigned char*)fieldData;
		
		// There are multiple options for size 1.
		if (fieldType == PROTOCOL)
		{
			output = NetflowParser::GetProtocolStringFromNumber(value);
			return true;
		}
		else if (fieldType == TCP_FLAGS)
		{
			
		}
		else if (fieldType == SRC_MASK || fieldType == DST_MASK || fieldType == IPV6_SRC_MASK || fieldType == IPV6_DST_MASK
				|| fieldType == ENGINE_ID || fieldType == FLOW_SAMPLER_ID || fieldType == FLOW_SAMPLER_MODE
				|| fieldType == MIN_TTL || fieldType == MAX_TTL || fieldType == SRC_TOS || fieldType == DST_TOS)
		{
			// Just give numeric output.
			output = IntStr(value);
			return true;
		}
		else if (fieldType == MUL_IGMP_TYPE)
		{
			
		}
		else if (fieldType == SAMPLING_ALGORITHM)
		{
			// Choose the sampling algorithm string representation according to the specified value.
			if (value == DETERMISTIC_SAMPLING)
			{
				output = "Deterministic Sampling";				
			}
			else if (value == RANDOM_SAMPLING)
			{
				output = "Random Sampling";
			}
			else
			{
				output = "Unknown";
			}
			
			return true;
		}
		else if (fieldType == ENGINE_TYPE)
		{
			// Choose the engine type string representation according to the specified value.
			if (value == ENGINE_TYPE_RP)
			{
				output = "RP";
			}
			else if (value == ENGINE_TYPE_LINE_CARD)
			{
				output = "VIP/Linecard";
			}
			else
			{
				output = "Unknown";
			}
			
			return true;
		}
		else if (fieldType == MPLS_TOP_LABEL_TYPE)
		{
			// Choose the MPLS top label type string representation according to the specified value.
			if (value == MPLS_TOP_LABEL_TYPE_TEMIDPT)
			{
				output = "TEMIDPT";
			}
			else if (value == MPLS_TOP_LABEL_TYPE_ATOM)
			{
				output = "ATOM";
			}
			else if (value == MPLS_TOP_LABEL_TYPE_VPN)
			{
				output = "VPN";
			}
			else if (value == MPLS_TOP_LABEL_TYPE_BGP)
			{
				output = "BGP";
			}
			else if (value == MPLS_TOP_LABEL_TYPE_LDP)
			{
				output = "LDP";
			}
			else
			{
				output = "Unknown";
			}
			
			return true;
		}
		else if (fieldType == IP_PROTOCOL_VERSION)
		{
			// Choose the IP version string representation according to the specified value.
			if (value == IPV6)
			{
				output = "IPv6";
			}
			else
			{
				output = "IPv4";
			}
			
			return true;
		}
		else if (fieldType == DIRECTION)
		{
			// Choose the flow direction string representation according to the specified value.
			if (value == DIRECTION_INGRESS)
			{
				output = "Ingress";
			}
			else if (value == DIRECTION_EGRESS)
			{
				output = "Egress";
			}
			else
			{
				output = "Unknown";
			}
			
			return true;
		}
	}
	else if (fieldLength == 2)
	{
		const unsigned short value = ntohs(*(unsigned short*)fieldData);
		
		// There are multiple options for size 2.
		if (fieldType == L4_SRC_PORT || fieldType == L4_DST_PORT || fieldType == SRC_AS || fieldType == DST_AS
			|| fieldType == MIN_PKT_LENGTH || fieldType == MAX_PKT_LENGTH || fieldType == FLOW_ACTIVE_TIMEOUT
			|| fieldType == FLOW_INACTIVE_TIMEOUT || fieldType == SRC_VLAN || fieldType == DST_VLAN)
		{
			// Just give numeric output.
			output = IntStr(value);
			return true;
		}
		else if (fieldType == ICMP_TYPE)
		{
			
		}
		else if (fieldType == IPV4_IDENT)
		{
			
		}
		else if (fieldType == INPUT_SNMP || fieldType == OUTPUT_SNMP)
		{
			
		}
	}
	else if (fieldLength == 3)
	{
		// There are multiple options for size 3.
		switch (fieldType)
		{
			case IPV6_FLOW_LABEL:
				break;
			case MPLS_LABEL_1:
			case MPLS_LABEL_2:
			case MPLS_LABEL_3:
			case MPLS_LABEL_4:
			case MPLS_LABEL_5:
			case MPLS_LABEL_6:
			case MPLS_LABEL_7:
			case MPLS_LABEL_8:
			case MPLS_LABEL_9:
			case MPLS_LABEL_10:
				break;
		}
	}
	else if (fieldLength == 4)
	{
		const unsigned long value = ntohl(*(unsigned long*)fieldData);
		
		// There are multiple options for size 4.
		if (fieldType == SRC_AS || fieldType == DST_AS || fieldType == IN_BYTES || fieldType == IN_PKTS
			|| fieldType == MUL_DST_PKTS || fieldType == MUL_DST_BYTES || fieldType == OUT_BYTES
			|| fieldType == OUT_PKTS || fieldType == SAMPLING_INTERVAL || fieldType == TOTAL_BYTES_EXP
			|| fieldType == TOTAL_PKTS_EXP || fieldType == TOTAL_FLOWS_EXP || fieldType == FLOW_SAMPLER_RANDOM_INTERVAL
			|| fieldType == IN_PERMANENT_BYTES || fieldType == IN_PERMANENT_PKTS || fieldType == FLOWS
			|| fieldType == LAST_SWITCHED || fieldType == FIRST_SWITCHED)
		{
			// Just give numeric output.
			output = IntStr(value);
			return true;
		}
		else if (fieldType == IPV4_SRC_ADDR || fieldType == IPV4_DST_ADDR || fieldType == IPV4_DST_ADDR
			|| fieldType == IPV4_NEXT_HOP || fieldType == BGP_IPV4_NEXT_HOP|| fieldType == IPV4_SRC_PREFIX
			|| fieldType == IPV4_DST_PREFIX|| fieldType == MPLS_TOP_LABEL_IP_ADDR)
		{
			// Parse the data as an IPv4 address. (byte swapping should not be done here!)
			output = Ipv4ToString(*(unsigned long*)fieldData);
			return true;
		}
		else if (fieldType == INPUT_SNMP || fieldType == OUTPUT_SNMP)
		{
			
		}
		else if (fieldType == IPV6_OPTION_HEADERS)
		{
			
		}
		else if (fieldType == INPUT_SNMP || fieldType == OUTPUT_SNMP)
		{
			
		}
	}
	else if (fieldLength == 6)
	{
		// Length 6 can only be a MAC address.
		output = MacAddressToString((unsigned char*)fieldData);
		return true;
	}
	else if (fieldLength == 16)
	{
		// Length 16 can only be an IPv6 address.
		output = Ipv6ToString(*(IPV6ADDRESS*)fieldData);
		return true;
	}
	else
	{
		// No fixed-size field matched the specified field, so it is probably a string.
		if (fieldType == IF_NAME || fieldType == IF_DESC || SAMPLER_NAME)
		{
			output.Cat((char*)fieldData, fieldLength);
			return true;
		}
	}
	
	// The field could not be parsed!
	return false;
}