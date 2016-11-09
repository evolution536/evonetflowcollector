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

#ifndef EVO_NETFLOW_H
#define EVO_NETFLOW_H

#include <Core/Core.h>

using namespace Upp;

// http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
// https://www.plixer.com/support/netflow_v9.html

// Represents an IPv4 address in long format.
typedef unsigned long IPV4ADDRESS;

// Structure for storage of an IPv6 address in long format.
typedef struct _IPV6ADDRESS
{
	unsigned long Lower1;
	unsigned long Lower2;
	unsigned long Upper1;
	unsigned long Upper2;
} IPV6ADDRESS, *PIPV6ADDRESS;

// Represents an IPv4 or IPv6 address, which can be used to store the IP address of the exporter.
union UNIVERSAL_IPADDRESS
{
	IPV4ADDRESS IpAddress4;
	IPV6ADDRESS IpAddress6;
};

// Represents a MAC address in bytes.
typedef struct _MACADDRESS
{
	unsigned char FirstPart;
	unsigned char SecondPart;
	unsigned char ThirdPart;
	unsigned char FourthPart;
	unsigned char FifthPart;
	unsigned char SixthPart;
} MACADDRESS, *PMACADDRESS;

// Represents a field in a Netflow v9 or IPFIX template.
struct TemplateFieldEntry : Moveable<TemplateFieldEntry>
{
	// The field type.
	unsigned short FieldType;
	
	// The field length.
	unsigned short FieldLength;
};

#endif