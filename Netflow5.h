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

#ifndef _EvoNetflowCollector_Netflow5_h_
#define _EvoNetflowCollector_Netflow5_h_

#include "EvoNetflow.h"

// Netflow v5 standard packet header.
typedef struct _NETFLOW5_HEADER
{
	unsigned short Version;
	unsigned short FlowCount;
	unsigned long SysUptime;
	unsigned long UnixSeconds;
	unsigned long UnixResidualSeconds;
	unsigned long FlowSequence;
	unsigned char EngineType;
	unsigned char EngineId;
	unsigned short SamplingInterval;
} NETFLOW5_HEADER, *PNETFLOW5_HEADER;

// Netflow v5 flow record header.
typedef struct _NETFLOW5_FLOW_RECORD
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
	unsigned char Padding1;
	unsigned char TcpFlags;
	unsigned char Protocol;
	unsigned char IpTypeOfService;
	unsigned short SourceAutonomousSystemNumber;
	unsigned short DestinationAutonomousSystemNumber;
	unsigned char SourceMask;
	unsigned char DestinationMask;
	short Padding2;
} NETFLOW5_FLOW_RECORD, *PNETFLOW5_FLOW_RECORD;

#endif