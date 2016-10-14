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

// http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
// https://www.plixer.com/support/netflow_v9.html

typedef unsigned long IPV4ADDRESS;

typedef struct _IPV6ADDRESS
{
	unsigned long Lower1;
	unsigned long Lower2;
	unsigned long Upper1;
	unsigned long Upper2;
} IPV6ADDRESS, *PIPV6ADDRESS;

typedef struct _MACADDRESS
{
	unsigned char FirstPart;
	unsigned char SecondPart;
	unsigned char ThirdPart;
	unsigned char FourthPart;
	unsigned char FifthPart;
	unsigned char SixthPart;
} MACADDRESS, *PMACADDRESS;

// Netflow v5 standard packet header.
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

// Netflow v9 flow record header.
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

// Netflow v9 standard packet header.
typedef struct _NETFLOW9_HEADER
{
	unsigned short Version;
	unsigned short FlowCount;
	unsigned long SysUptime;
	unsigned long UnixSeconds;
	unsigned long PackageSequence;
	unsigned long SourceID;
} NETFLOW9_HEADER, *PNETFLOW9_HEADER;

// Netflow v9 field definitions
#define IN_BYTES						1
#define IN_PKTS							2
#define FLOWS							3
#define PROTOCOL						4
#define SRC_TOS							5
#define TCP_FLAGS						6
#define L4_SRC_PORT						7
#define IPV4_SRC_ADDR					8
#define SRC_MASK						9
#define INPUT_SNMP						10
#define L4_DST_PORT						11
#define IPV4_DST_ADDR					12
#define DST_MASK						13
#define OUTPUT_SNMP						14
#define IPV4_NEXT_HOP					15
#define SRC_AS							16
#define DST_AS							17
#define BGP_IPV4_NEXT_HOP				18
#define MUL_DST_PKTS					19
#define MUL_DST_BYTES					20
#define LAST_SWITCHED					21
#define FIRST_SWITCHED					22
#define OUT_BYTES						23
#define OUT_PKTS						24
#define MIN_PKT_LENGTH					25
#define MAX_PKT_LENGTH					26
#define IPV6_SRC_ADDR					27
#define IPV6_DST_ADDR					28
#define IPV6_SRC_MASK					29
#define IPV6_DST_MASK					30
#define IPV6_FLOW_LABEL					31
#define ICMP_TYPE						32
#define MUL_IGMP_TYPE					33
#define SAMPLING_INTERVAL				34
#define SAMPLING_ALGORITHM				35
#define FLOW_ACTIVE_TIMEOUT				36
#define FLOW_INACTIVE_TIMEOUT			37
#define ENGINE_TYPE						38
#define ENGINE_ID						39
#define TOTAL_BYTES_EXP					40
#define TOTAL_PKTS_EXP					41
#define TOTAL_FLOWS_EXP					42
#define VENDOR_PROPRIETARY_1			43
#define IPV4_SRC_PREFIX					44
#define IPV4_DST_PREFIX					45
#define MPLS_TOP_LABEL_TYPE				46
#define MPLS_TOP_LABEL_IP_ADDR			47
#define FLOW_SAMPLER_ID					48
#define FLOW_SAMPLER_MODE				49
#define FLOW_SAMPLER_RANDOM_INTERVAL	50
#define VENDOR_PROPRIETARY_2			51
#define MIN_TTL							52
#define MAX_TTL							53
#define IPV4_IDENT						54
#define DST_TOS							55
#define IN_SRC_MAC						56
#define OUT_DST_MAC						57
#define SRC_VLAN						58
#define DST_VLAN						59
#define IP_PROTOCOL_VERSION				60
#define DIRECTION						61
#define IPV6_NEXT_HOP					62
#define BPG_IPV6_NEXT_HOP				63
#define IPV6_OPTION_HEADERS				64
#define VENDOR_PROPRIETARY_3			65
#define VENDOR_PROPRIETARY_4			66
#define VENDOR_PROPRIETARY_5			67
#define VENDOR_PROPRIETARY_6			68
#define VENDOR_PROPRIETARY_7			69
#define MPLS_LABEL_1					70
#define MPLS_LABEL_2					71
#define MPLS_LABEL_3					72
#define MPLS_LABEL_4					73
#define MPLS_LABEL_5					74
#define MPLS_LABEL_6					75
#define MPLS_LABEL_7					76
#define MPLS_LABEL_8					77
#define MPLS_LABEL_9					78
#define MPLS_LABEL_10					79
#define IN_DST_MAC						80
#define OUT_SRC_MAC						81
#define IF_NAME							82
#define IF_DESC							83
#define SAMPLER_NAME					84
#define IN_PERMANENT_BYTES				85
#define IN_PERMANENT_PKTS				86
#define VENDOR_PROPRIETARY_8			87

// Cisco specific field definitions.
#define FRAGMENT_OFFSET					88
#define FORWARDING_STATUS				89
#define MPLS_PAL_RD						90
#define MPLS_PREFIX_LEN					91
#define SRC_TRAFFIC_INDEX				92
#define DST_TRAFFIC_INDEX				93
#define APPLICATION_DESCRIPTION			94
#define APPLICATION_TAG					95
#define APPLICATION_NAME				96
#define postipDiffServCodePoint			98
#define replication_factor				99
#define DEPRECATED						100
#define layer2packetSectionOffset		102
#define layer2packetSectionSize			103
#define layer2packetSectionData			104

// Generic Netflow v9 flowset header.
typedef struct _NETFLOW9_FLOWSET_HEADER
{
	unsigned short FlowsetID;
	unsigned short Length;
} NETFLOW9_FLOWSET_HEADER, *PNETFLOW9_FLOWSET_HEADER;

// Netflow v9 template flowset header.
typedef struct _NETFLOW9_TEMPLATE_FLOWSET_HEADER
{
	unsigned short TemplateID;
	unsigned short FieldCount;
} NETFLOW9_TEMPLATE_FLOWSET_HEADER, *PNETFLOW9_TEMPLATE_FLOWSET_HEADER;

// Netflow v9 data flowset header.
typedef struct _NETFLOW9_DATA_FLOWSET_HEADER
{
	unsigned char FieldCollection[4];
} NETFLOW9_DATA_FLOWSET_HEADER, *PNETFLOW9_DATA_FLOWSET_HEADER;

// Netflow v9 options template header.
typedef struct _NETFLOW9_OPTIONS_TEMPLATE_HEADER
{
	unsigned short TemplateID;
	unsigned short OptionsScopeLength;
	unsigned short OptionsLength;
	unsigned short ScopeFieldType;
	unsigned short ScopeFieldLength;
	unsigned short OptionFieldType;
	unsigned short OptionFieldLength;
	unsigned short Padding1;
} NETFLOW9_OPTIONS_TEMPLATE_HEADER, *PNETFLOW9_OPTIONS_TEMPLATE_HEADER;

// IPFIX field definitions.
// Source: http://www.iana.org/assignments/ipfix/ipfix.xhtml
#define octetDeltaCount					1
#define packetDeltaCount				2
#define deltaFlowCount					3
#define protocolIdentifier				4
#define ipClassOfService				5
#define tcpControlBits					6
#define sourceTransportPort				7
#define sourceIPv4Address				8
#define sourceIPv4PrefixLength			9
#define ingressInterface				10
#define destinationTransportPort		11
#define destinationIPv4Address			12
#define destinationIPv4PrefixLength		13
#define egressInterface					14
#define ipNextHopIPv4Address			15
#define bgpSourceAsNumber				16
#define bgpDestinationAsNumber			17
#define bgpNextHopIPv4Address			18
#define postMCastPacketDeltaCount		19
#define postMCastOctetDeltaCount		20
#define flowEndSysUpTime				21
#define flowStartSysUpTime				22
#define postOctetDeltaCount				23
#define postPacketDeltaCount			24
#define minimumIpTotalLength			25
#define	maximumIpTotalLength			26
#define sourceIPv6Address				27
#define destinationIPv6Address			28
#define	sourceIPv6PrefixLength			29
#define destinationIPv6PrefixLength		30
#define flowLabelIPv6					31
#define icmpTypeCodeIPv4				32
#define igmpType						33
#define samplingInterval				34
#define samplingAlgorithm				35
#define flowActiveTimeout				36
#define flowIdleTimeout					37
#define engineType						38
#define engineId						39
#define exportedOctetTotalCount			40
#define exportedMessageTotalCount		41
#define exportedFlowRecordTotalCount	42
#define ipv4RouterSc					43
#define sourceIPv4Prefix				44
#define destinationIPv4Prefix			45
#define mplsTopLabelType				46
#define mplsTopLabelIPv4Address			47
#define samplerId						48
#define samplerMode						49
#define samplerRandomInterval			50
#define classId							51
#define minimumTTL						52
#define maximumTTL						53
#define fragmentIdentification			54
#define postIpClassOfService			55
#define sourceMacAddress				56
#define postDestinationMacAddress		57
#define vlanId							58
#define postVlanId						59
#define ipVersion						60
#define flowDirection					61
#define ipNextHopIPv6Address			62
#define bgpNextHopIPv6Address			63
#define ipv6ExtensionHeaders			64
#define mplsTopLabelStackSection		70
#define mplsLabelStackSection2			71
#define mplsLabelStackSection3			72
#define mplsLabelStackSection4			73
#define mplsLabelStackSection5			74
#define mplsLabelStackSection6			75
#define mplsLabelStackSection7			76
#define mplsLabelStackSection8			77
#define mplsLabelStackSection9			78
#define mplsLabelStackSection10			79
#define destinationMacAddress			80
#define postSourceMacAddress			81
#define interfaceName					82
#define interfaceDescription			83
#define samplerName						84
#define octetTotalCount					85
#define packetTotalCount				86
#define flagsAndSamplerId				87
#define fragmentOffset					88
#define forwardingStatus				89
#define mplsVpnRouteDistinguisher		90
#define mplsTopLabelPrefixLength		91
#define srcTrafficIndex					92
#define dstTrafficIndex					93
#define applicationDescription			94
#define applicationId					95
#define applicationName					96
#define postIpDiffServCodePoint			98
#define multicastReplicationFactor		99
#define className						100
#define classificationEngineId			101
#define layer2packetSectionOffset		102
#define layer2packetSectionSize			103
#define layer2packetSectionData			104
#define bgpNextAdjacentAsNumber			128
#define bgpPrevAdjacentAsNumber			129
#define exporterIPv4Address				130
#define exporterIPv6Address				131
#define droppedOctetDeltaCount			132
#define droppedPacketDeltaCount			133
#define droppedOctetTotalCount			134
#define droppedPacketTotalCount			135
#define flowEndReason					136
#define commonPropertiesId				137
#define observationPointId				138
#define icmpTypeCodeIPv6				139
#define mplsTopLabelIPv6Address			140
#define lineCardId						141
#define portId							142
#define meteringProcessId				143
#define exportingProcessId				144
#define templateId						145
#define wlanChannelId					146
#define wlanSSID						147
#define flowId							148
#define observationDomainId				149
#define flowStartSeconds				150
#define flowEndSeconds					151
#define flowStartMilliseconds			152
#define flowEndMilliseconds				153
#define flowStartMicroseconds			154
#define flowEndMicroseconds				155
#define	flowStartNanoseconds			156
#define flowEndNanoseconds				157
#define flowStartDeltaMicroseconds		158
#define flowEndDeltaMicroseconds		159
#define systemInitTimeMilliseconds		160
#define flowDurationMilliseconds		161
#define flowDurationMicroseconds		162
#define observedFlowTotalCount			163
#define ignoredPacketTotalCount			164
#define ignoredOctetTotalCount			165
#define notSentFlowTotalCount			166
#define notSentPacketTotalCount			167
#define notSentOctetTotalCount			168
#define destinationIPv6Prefix			169
#define sourceIPv6Prefix				170
#define postOctetTotalCount				171
#define postPacketTotalCount			172
#define flowKeyIndicator				173
#define postMCastPacketTotalCount		174
#define postMCastOctetTotalCount		175
#define icmpTypeIPv4					176
#define icmpCodeIPv4					177
#define icmpTypeIPv6					178
#define icmpCodeIPv6					179
#define udpSourcePort					180
#define udpDestinationPort				181
#define tcpSourcePort					182
#define tcpDestinationPort				183
#define tcpSequenceNumber				184
#define tcpAcknowledgementNumber		185
#define tcpWindowSize					186
#define tcpUrgentPointer				187
#define tcpHeaderLength					188
#define ipHeaderLength					189
#define totalLengthIPv4					190
#define payloadLengthIPv6				191
#define ipTTL							192
#define nextHeaderIPv6					193
#define mplsPayloadLength				194
#define ipDiffServCodePoint				195
#define ipPrecedence					196
#define fragmentFlags					197
#define octetDeltaSumOfSquares			198
#define octetTotalSumOfSquares			199
#define mplsTopLabelTTL					200

#endif