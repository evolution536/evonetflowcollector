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

#include "Netflow9.h"

// Parses a Netflow v9 options template.
const bool ParseNetflow9OptionsTemplate(const PNETFLOW9_OPTIONS_TEMPLATE_HEADER optionsHeader)
{
	return true;
}

// Parses a Netflow v9 data template.
const bool ParseNetflow9DataTemplate(const PNETFLOW9_TEMPLATE_FLOWSET_HEADER optionsHeader)
{
	return true;
}

// Attemps to parse a Netflow v9 field using its field type and length. Output will be dynamically returned.
// The length of the buffer passed as output should be at least 64 bytes in size.
const bool ParseNetflow9Field(const unsigned short fieldType, const unsigned short fieldLength, const void* fieldData, void* const output)
{
	// Decide how to parse the specified field based on the length of the field, and secondly,
	// on the type of field. For example, parse IPv4 addresses differently from packet count.
	if (fieldLength == 1)
	{
		// There are multiple options for size 1.
		switch (fieldType)
		{
			case PROTOCOL:
				break;
			case SRC_TOS:
			case DST_TOS:
				break;
			case TCP_FLAGS:
				break;
			case SRC_MASK:
			case DST_MASK:
				break;
			case IPV6_SRC_MASK:
			case IPV6_DST_MASK:
				break;
			case MUL_IGMP_TYPE:
				break;
			case SAMPLING_ALGORITHM:
				break;
			case ENGINE_TYPE:
				break;
			case ENGINE_ID:
				break;
			case MPLS_TOP_LABEL_TYPE:
				break;
			case FLOW_SAMPLER_ID:
				break;
			case FLOW_SAMPLER_MODE:
				break;
			case MIN_TTL:
			case MAX_TTL:
				break;
			case IP_PROTOCOL_VERSION:
				break;
			case DIRECTION:
				break;
		}
	}
	else if (fieldLength == 2)
	{
		// There are multiple options for size 2.
		switch (fieldType)
		{
			case L4_SRC_PORT:
			case L4_DST_PORT:
				break;
			case SRC_AS:
			case DST_AS:
				break;
			case MIN_PKT_LENGTH:
			case MAX_PKT_LENGTH:
				break;
			case ICMP_TYPE:
				break;
			case FLOW_ACTIVE_TIMEOUT:
			case FLOW_INACTIVE_TIMEOUT:
				break;
			case IPV4_IDENT:
				break;
			case SRC_VLAN:
			case DST_VLAN:
				break;
			case INPUT_SNMP:
			case OUTPUT_SNMP:
				break;
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
		// There are multiple options for size 4.
		switch (fieldType)
		{
			case SRC_AS:
			case DST_AS:
				break;
			case IN_BYTES:
			case IN_PKTS:
			case MUL_DST_PKTS:
			case MUL_DST_BYTES:
			case OUT_BYTES:
			case OUT_PKTS:
			case SAMPLING_INTERVAL:
			case TOTAL_BYTES_EXP:
			case TOTAL_PKTS_EXP:
			case TOTAL_FLOWS_EXP:
			case FLOW_SAMPLER_RANDOM_INTERVAL:
			case IN_PERMANENT_BYTES:
			case IN_PERMANENT_PKTS:
				break;
			case FLOWS:
				break;
			case IPV4_SRC_ADDR:
			case IPV4_DST_ADDR:
			case IPV4_NEXT_HOP:
			case BGP_IPV4_NEXT_HOP:
			case IPV4_SRC_PREFIX:
			case IPV4_DST_PREFIX:
			case MPLS_TOP_LABEL_IP_ADDR:
				break;
			case LAST_SWITCHED:
			case FIRST_SWITCHED:
				break;
			case IPV6_OPTION_HEADERS:
				break;
			case INPUT_SNMP:
			case OUTPUT_SNMP:
				break;
		}
	}
	else if (fieldLength == 6)
	{
		// Length 6 can only be a MAC address.
	}
	else if (fieldLength == 16)
	{
		// Length 16 can only be an IPv6 address.
	}
	else
	{
		// No fixed-size field matched the specified field, so it is probably a string.
		switch (fieldType)
		{
			case IF_NAME:
			case IF_DESC:
			case SAMPLER_NAME:
				break;
		}
	}
	
	// The field could not be parsed!
	return false;
}