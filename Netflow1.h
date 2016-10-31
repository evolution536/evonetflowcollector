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

#ifndef _EvoNetflowCollector_Netflow1_h_
#define _EvoNetflowCollector_Netflow1_h_

#include "EvoNetflow.h"

// Netflow v1 packet header.
typedef struct _NETFLOW1_HEADER
{
	unsigned short Version;
	unsigned short FlowCount;
	unsigned long SysUptime;
	unsigned long UnixSeconds;
	unsigned long UnixResidualSeconds;
} NETFLOW1_HEADER, *PNETFLOW1_HEADER;

// Netflow v1 flow record header.
typedef struct _NETFLOW1_FLOW_RECORD
{
	IPV4ADDRESS SourceIpAddress;
	IPV4ADDRESS DestinationIpAddress;
	IPV4ADDRESS NextHop;
	unsigned short InputSnmp;
	unsigned short OutputSnmp;
	unsigned int PacketCount;
	unsigned int BytesCount;
	unsigned long SysUptimeFirst;
	unsigned long SysUptimeLast;
	unsigned short SourcePort;
	unsigned short DestinationPort;
	unsigned short Padding1;
	unsigned char Protocol;
	unsigned char IpTypeOfService;
	unsigned char TcpFlags;
	unsigned char Padding[3];
	unsigned long Reserved;
} NETFLOW1_FLOW_RECORD, *PNETFLOW1_FLOW_RECORD;

#endif