#ifndef EVO_NETFLOW_H
#define EVO_NETFLOW_H

// http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108

typedef unsigned long IPV4ADDRESS;

typedef struct _NETFLOW5_HEADER
{
	unsigned short Version;
	unsigned short FlowCount;
	unsigned long SysUptime;
	unsigned long UnixSeconds;
	unsigned long UnixResidualSeconds;
	unsigned int FlowSequence;
	unsigned char EngineType;
	unsigned char EngineId;
	unsigned short SamplingInterval;
} NETFLOW5_HEADER, *PNETFLOW5_HEADER;

#define IPPROTOCOLTYPE_TCP 6
#define IPPROTOCOLTYPE_UDP 17

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