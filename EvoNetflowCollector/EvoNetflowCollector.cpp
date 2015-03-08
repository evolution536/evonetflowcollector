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

#include "EvoNetflowCollector.h"
#include "UtilityFunctions.h"
#include "EvoProcessingDispatcher.h"
#include "EvoNetflow9TemplateCache.h"

#ifdef _WIN32
	#include <Mstcpip.h>
	#pragma comment(lib, "ws2_32.lib")
#else
	#include <unistd.h>
	#include <string.h>
	#include <netinet/in.h>
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR -1
#endif

EvoProcessingDispatcher eventDispatcher;
EvoNetflow9TemplateCache* v9TemplateCacheInstance = NULL;

EvoNetflowCollector::EvoNetflowCollector()
{
	this->mRunning = false;

#ifdef _WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	// Create a datagram socket to listen for packets.
	this->ListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
}

EvoNetflowCollector::~EvoNetflowCollector()
{
#ifdef _WIN32
	closesocket(this->ListenSocket);
	WSACleanup();
#else
	close(this->ListenSocket);
#endif
}

const bool EvoNetflowCollector::Bind(const int port)
{
	if (this->ListenSocket == INVALID_SOCKET)
	{
		return false;
	}

	sockaddr_in info;
	info.sin_addr.s_addr = htonl(INADDR_ANY);
	info.sin_family = AF_INET;
	info.sin_port = htons(port);
	const int infolen = sizeof(sockaddr_in);

	// Bind the socket to listen on the configured port.
	return bind(this->ListenSocket, (sockaddr*)&info, infolen) != SOCKET_ERROR;
}

const bool EvoNetflowCollector::BeginListen()
{
	if (this->ListenSocket == INVALID_SOCKET)
	{
		return false;
	}

	// Start listening for Netflow input on a separate thread.
	this->mRunning = true;
	this->mSocketThread = std::thread(&EvoNetflowCollector::ListenerThread, this);

	// Set a timeout on the socket so that it does not block execution infinitely.
	unsigned long timeout = 25;
	setsockopt(this->ListenSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(unsigned long));

	return true;
}

void EvoNetflowCollector::StopListening()
{
	this->mRunning = false;
	this->mSocketThread.join();
}

void EvoNetflowCollector::ListenerThread()
{
	sockaddr_in clientinfo;
	unsigned int clientinfolen = sizeof(sockaddr_in);

	while (this->mRunning)
	{
		// Start receiving data from the listening socket.
		char buffer[2048];
#ifdef _WIN32
		int bytesRead = recvfrom(this->ListenSocket, buffer, sizeof(buffer), 0, (sockaddr*)&clientinfo, (int*)&clientinfolen);
#else
		int bytesRead = recvfrom(this->ListenSocket, buffer, sizeof(buffer), 0, (sockaddr*)&clientinfo, &clientinfolen);
#endif
		if (bytesRead > 0)
		{
			// To avoid missing packets, dispatch the processing of each to another worker.
			char* safeBuffer = new char[sizeof(buffer)];
			memcpy(safeBuffer, buffer, sizeof(buffer));
			eventDispatcher.QueuePacket(safeBuffer);
		}
	}
}

// --------------------------------------------------------------------------------------------------------

const int CheckNetflowPacketVersion(const char* buffer)
{
	return buffer ? (int)*(unsigned short*)buffer : 0;
}

const bool ParseNetflow5Packet(const char* buffer, std::vector<unsigned int>& outSequences, std::vector<NETFLOW5_FLOW_RECORD>& outRecords)
{
	if (!buffer)
	{
		return false;
	}

	// Retrieve flows from the packet.
	const PNETFLOW5_HEADER nfHeader = (PNETFLOW5_HEADER)buffer;
#ifdef _WIN32
	const int flowCount = SwapBytes(&nfHeader->FlowCount);
	outRecords.reserve(flowCount);
	PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(buffer + sizeof(NETFLOW5_HEADER));
	unsigned int seq = SwapBytes(&nfHeader->FlowSequence);
	for (int i = 0; i < flowCount; ++i, ++flowRecord)
	{
		outSequences.push_back(seq + i);
		NETFLOW5_FLOW_RECORD newRecord;
		newRecord.SourceIpAddress = SwapBytes(&flowRecord->SourceIpAddress);
		newRecord.DestinationIpAddress = SwapBytes(&flowRecord->DestinationIpAddress);
		newRecord.NextHop = SwapBytes(&flowRecord->NextHop);
		newRecord.InputSnmp = SwapBytes(&flowRecord->InputSnmp);
		newRecord.OutputSnmp = SwapBytes(&flowRecord->OutputSnmp);
		newRecord.PacketCount = SwapBytes(&flowRecord->PacketCount);
		newRecord.BytesCount = SwapBytes(&flowRecord->BytesCount);
		newRecord.SysUptimeFirst = SwapBytes(&flowRecord->SysUptimeFirst);
		newRecord.SysUptimeLast = SwapBytes(&flowRecord->SysUptimeLast);
		newRecord.SourcePort = SwapBytes(&flowRecord->SourcePort);
		newRecord.DestinationPort = SwapBytes(&flowRecord->DestinationPort);
		newRecord.TcpFlags = SwapBytes(&flowRecord->TcpFlags);
		newRecord.Protocol = SwapBytes(&flowRecord->Protocol);
		newRecord.IpTypeOfService = SwapBytes(&flowRecord->IpTypeOfService);
		newRecord.SourceAutonomousSystemNumber = SwapBytes(&flowRecord->SourceAutonomousSystemNumber);
		newRecord.DestinationAutonomousSystemNumber = SwapBytes(&flowRecord->DestinationAutonomousSystemNumber);
		newRecord.SourceMask = SwapBytes(&flowRecord->SourceMask);
		newRecord.DestinationMask = SwapBytes(&flowRecord->DestinationMask);
		outRecords.push_back(newRecord);
	}
#else
	outSequences.push_back(nfHeader->FlowSequence);
	outRecords.reserve(nfHeader->FlowCount);
	PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(buffer + sizeof(NETFLOW5_HEADER));
	for (int i = 0; i < nfHeader->FlowCount; ++i, ++flowRecord)
	{
		outSequences.push_back(nfHeader->FlowSequence + i);
		outRecords.push_back(*flowRecord);
	}
#endif

	return true;
}

const bool ProcessNetflow9FieldValue(const unsigned int fieldType, const unsigned int fieldLength, const char* fieldVal, std::string& outVal)
{
	switch (fieldType)
	{
		case IN_BYTES:
			break;
		case IN_PKTS:
			break;
		case FLOWS:
			break;
		case PROTOCOL:
			break;
		case SRC_TOS:
			break;
		case TCP_FLAGS:
			break;
		case L4_SRC_PORT:
			break;
		case IPV4_SRC_ADDR:
			break;
		case SRC_MASK:
			break;
		case INPUT_SNMP:
			break;
		case L4_DST_PORT:
			break;
		case IPV4_DST_ADDR:
			break;
		case DST_MASK:
			break;
		case OUTPUT_SNMP:
			break;
		case IPV4_NEXT_HOP:
			break;
		case SRC_AS:
			break;
		case DST_AS:
			break;
		case BGP_IPV4_NEXT_HOP:
			break;
		case MUL_DST_PKTS:
			break;
		case MUL_DST_BYTES:
			break;
		case LAST_SWITCHED:
			break;
		case FIRST_SWITCHED:
			break;
		case OUT_BYTES:
			break;
		case OUT_PKTS:
			break;
		case MIN_PKT_LENGTH:
			break;
		case MAX_PKT_LENGTH:
			break;
		case IPV6_SRC_ADDR:
			break;
		case IPV6_DST_ADDR:
			break;
		case IPV6_SRC_MASK:
			break;
		case IPV6_DST_MASK:
			break;
		case IPV6_FLOW_LABEL:
			break;
		case ICMP_TYPE:
			break;
		case MUL_IGMP_TYPE:
			break;
		case SAMPLING_INTERVAL:
			break;
		case SAMPLING_ALGORITHM:
			break;
		case FLOW_ACTIVE_TIMEOUT:
			break;
		case FLOW_INACTIVE_TIMEOUT:
			break;
		case ENGINE_TYPE:
			break;
		case ENGINE_ID:
			break;
		case TOTAL_BYTES_EXP:
			break;
		case TOTAL_PKTS_EXP:
			break;
		case TOTAL_FLOWS_EXP:
			break;
		case VENDOR_PROPRIETARY_1:
			return false;
		case IPV4_SRC_PREFIX:
			break;
		case IPV4_DST_PREFIX:
			break;
		case MPLS_TOP_LABEL_TYPE:
			break;
		case MPLS_TOP_LABEL_IP_ADDR:
			break;
		case FLOW_SAMPLER_ID:
			break;
		case FLOW_SAMPLER_MODE:
			break;
		case FLOW_SAMPLER_RANDOM_INTERVAL:
			break;
		case VENDOR_PROPRIETARY_2:
			return false;
		case MIN_TTL:
			break;
		case MAX_TTL:
			break;
		case IPV4_IDENT:
			break;
		case DST_TOS:
			break;
		case IN_SRC_MAC:
			break;
		case OUT_DST_MAC:
			break;
		case SRC_VLAN:
			break;
		case DST_VLAN:
			break;
		case IP_PROTOCOL_VERSION:
			break;
		case DIRECTION:
			break;
		case IPV6_NEXT_HOP:
			break;
		case BPG_IPV6_NEXT_HOP:
			break;
		case IPV6_OPTION_HEADERS:
			break;
		case VENDOR_PROPRIETARY_3:
		case VENDOR_PROPRIETARY_4:
		case VENDOR_PROPRIETARY_5:
		case VENDOR_PROPRIETARY_6:
		case VENDOR_PROPRIETARY_7:
			return false;
		case MPLS_LABEL_1:
			break;
		case MPLS_LABEL_2:
			break;
		case MPLS_LABEL_3:
			break;
		case MPLS_LABEL_4:
			break;
		case MPLS_LABEL_5:
			break;
		case MPLS_LABEL_6:
			break;
		case MPLS_LABEL_7:
			break;
		case MPLS_LABEL_8:
			break;
		case MPLS_LABEL_9:
			break;
		case MPLS_LABEL_10:
			break;
		case IN_DST_MAC:
			break;
		case OUT_SRC_MAC:
			break;
		case IF_NAME:
			break;
		case IF_DESC:
			break;
		case SAMPLER_NAME:
			break;
		case IN_PERMANENT_BYTES:
			break;
		case IN_PERMANENT_PKTS:
			break;
		case VENDOR_PROPRIETARY_8:
		default:
			return false;
	}

	return true;
}

const bool ParseNetflow9Packet(const char* buffer, std::vector<unsigned int>& outSequences, std::vector<PNETFLOW9_DATA_FLOWSET_HEADER>& outRecords)
{
	if (!buffer)
	{
		return false;
	}

	// Retrieve flows from the packet.
	const PNETFLOW9_HEADER nfHeader = (PNETFLOW9_HEADER)buffer;

#ifdef _WIN32
	const int flowCount = SwapBytes(&nfHeader->FlowCount);
	outRecords.reserve(flowCount);
	unsigned int seq = SwapBytes(&nfHeader->PackageSequence);
	const char* packetIterator = buffer + sizeof(NETFLOW9_HEADER);
	for (int i = 0; i < flowCount; ++i)
	{
		const PNETFLOW9_FLOWSET_HEADER currentFlow = (PNETFLOW9_FLOWSET_HEADER)packetIterator;
		if (currentFlow->FlowsetID < 256)
		{
			if (currentFlow->FlowsetID == 0)
			{
				// The flowset is a template flowset that describes fields.
				const PNETFLOW9_TEMPLATE_FLOWSET_HEADER templateHeader = (PNETFLOW9_TEMPLATE_FLOWSET_HEADER)(packetIterator + sizeof(NETFLOW9_FLOWSET_HEADER));
			}
			else if (currentFlow->FlowsetID == 1)
			{
				// The flowset is a template flowset that describes options.
				const PNETFLOW9_OPTIONS_TEMPLATE_HEADER optionsHeader = (PNETFLOW9_OPTIONS_TEMPLATE_HEADER)(packetIterator + sizeof(NETFLOW9_FLOWSET_HEADER));
			}
		}
		else
		{
			// The flowset is a data flowset.
			const PNETFLOW9_DATA_FLOWSET_HEADER dataHeader = (PNETFLOW9_DATA_FLOWSET_HEADER)(packetIterator + sizeof(NETFLOW9_FLOWSET_HEADER));
			// FIND TEMPLATE IN CACHE AND SEE IF THE TEMPLATE IDS MATCH! IF SO, PARSE PACKET USING TEMPLATE!
		}

		// Add the variable length value of the processed flowset to the iterator.
		packetIterator += currentFlow->Length;
	}
#else

#endif
	return true;
}