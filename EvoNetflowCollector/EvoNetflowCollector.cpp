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
#include "EvoNetflow9TemplateCache.h"
#include <sstream>

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

extern const char* const GetProtocolStringFromNumber(const unsigned short number);

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

	// Set a timeout on the socket so that it does not block execution infinitely.
	unsigned long timeout = 25;
	setsockopt(this->ListenSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(unsigned long));

	// Start listening for Netflow input on a separate thread.
	this->mRunning = true;
	this->mSocketThread = std::thread(&EvoNetflowCollector::ListenerThread, this);

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
			QueuedPacketDescriptor desc(safeBuffer, bytesRead);
			desc.GeneratorIpAddress.IpAddress4 = clientinfo.sin_addr.S_un.S_addr;
			eventDispatcher.QueuePacket(&desc);
		}
	}
}

// --------------------------------------------------------------------------------------------------------

const int CheckNetflowPacketVersion(const char* buffer)
{
	if (buffer)
	{
#ifdef _WIN32
		return (int)SwapBytes((unsigned short*)buffer);
#else
		return (int)*(unsigned short*)buffer;
#endif
	}

	return 0;
}

const bool ParseNetflow5Packet(const QueuedPacketDescriptor* buffer, std::vector<unsigned int>& outSequences, std::vector<NETFLOW5_FLOW_RECORD>& outRecords)
{
	if (!buffer->PacketBuffer)
	{
		return false;
	}

	if (buffer->PacketLength < sizeof(NETFLOW5_HEADER))
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

const bool ParseNetflow9Packet(const QueuedPacketDescriptor* buffer, unsigned int* sequenceCounter, std::vector<EvoNetflow9FieldValueSet>& outRecords)
{
	if (!buffer->PacketBuffer)
	{
		return false;
	}

	if (buffer->PacketLength < sizeof(NETFLOW9_HEADER))
	{
		return false;
	}

	// Retrieve flows from the packet.
	const PNETFLOW9_HEADER nfHeader = (PNETFLOW9_HEADER)buffer->PacketBuffer;
	*sequenceCounter = nfHeader->PackageSequence;
	const char* packetIterator = buffer->PacketBuffer + sizeof(NETFLOW9_HEADER);
	const PNETFLOW9_FLOWSET_HEADER flowHeader = (PNETFLOW9_FLOWSET_HEADER)packetIterator;

#ifdef _WIN32
	const unsigned long sourceId = SwapBytes(&nfHeader->SourceID);
	const unsigned short flowCount = SwapBytes(&nfHeader->FlowCount);
	const unsigned short flowsetId = SwapBytes(&flowHeader->FlowsetID);
#else
	const unsigned long sourceId = nfHeader->SourceID;
	const unsigned short flowCount = nfHeader->FlowCount;
	const unsigned short flowsetId = flowHeader->FlowsetID;
#endif

	if (flowsetId < 256)
	{
		// Flowset ID of 1 is an options template. Otherwise it is a data template.
		if (flowsetId == 1)
		{

		}
		else
		{
			// The packet contains a data template.
			packetIterator += sizeof(NETFLOW9_FLOWSET_HEADER);
			const PNETFLOW9_TEMPLATE_FLOWSET_HEADER templateHeader = (PNETFLOW9_TEMPLATE_FLOWSET_HEADER)packetIterator;
#ifdef _WIN32
			const unsigned short templateId = SwapBytes(&templateHeader->TemplateID);
			const unsigned short fieldCount = SwapBytes(&templateHeader->FieldCount);
#else
			const unsigned short templateId = templateHeader->TemplateID;
			const unsigned short fieldCount = templateHeader->FieldCount;
#endif
			packetIterator += sizeof(NETFLOW9_TEMPLATE_FLOWSET_HEADER);
			std::vector<NETFLOW9_TEMPLATE_FIELD> fields;
			for (unsigned short i = 0; i < fieldCount; ++i)
			{
				const PNETFLOW9_TEMPLATE_FIELD curEntry = ((PNETFLOW9_TEMPLATE_FIELD)packetIterator) + i;
#ifdef _WIN32
				NETFLOW9_TEMPLATE_FIELD newOne;
				newOne.FieldType = SwapBytes(&curEntry->FieldType);
				newOne.FieldLength = SwapBytes(&curEntry->FieldLength);
				fields.push_back(newOne);
#else
				fields.push_back(*curEntry);
#endif
				packetIterator += sizeof(NETFLOW9_TEMPLATE_FIELD);
			}

			// Add the template to the cache. If the template already exists, it will not be added.
			v9TemplateCacheInstance->AddTemplate(&buffer->GeneratorIpAddress, sourceId, templateId, fields);
		}
	}
	else if (flowsetId >= 256)
	{
		// Attempt to retrieve the template that is associated with the data. If no template is found, discard the packet.
		const PNETFLOW9_TEMPLATE_CACHE_ENTRY foundTemplate = v9TemplateCacheInstance->FindTemplate(flowHeader->FlowsetID);
		if (!foundTemplate)
		{
			return false;
		}

		packetIterator += sizeof(NETFLOW9_FLOWSET_HEADER);

		// Walk the flows inside the flowset.
		for (unsigned short i = 0; i < flowCount; ++i)
		{
			packetIterator += foundTemplate->ParseFieldsUsingTemplate((PNETFLOW9_DATA_FLOWSET_HEADER)packetIterator, outRecords);
		}
	}
	else
	{
		return false;
	}

	return true;
}