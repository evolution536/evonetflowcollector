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
	// Running in Windows, we need to initiate WinSock.
	WSADATA wsaData;
	int wsaReturn = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsaReturn != 0)
	{
		this->ListenSocket = NULL;
	}
	else
	{
		// Create a datagram socket to listen for packets.
		this->ListenSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
#else
	// Create a datagram socket to listen for packets.
	this->ListenSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
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

// Binds the Netflow collector socket to the specified port. Currently only IPv4!
const bool EvoNetflowCollector::Bind(const int port)
{
	sockaddr_in info;
	info.sin_addr.s_addr = htonl(INADDR_ANY);
	info.sin_family = AF_INET;
	info.sin_port = htons(port);
	const int infolen = sizeof(sockaddr_in);

	// Bind the socket to listen on the configured port.
	return bind(this->ListenSocket, (sockaddr*)&info, infolen) != SOCKET_ERROR;
}

// Starts the listener thread to listen for Netflow packets.
const bool EvoNetflowCollector::BeginListen(const int port)
{
#ifdef _WIN32
	// If running on Windows, check whether WSA initialized succesfully.
	if (!this->ListenSocket)
	{
		return false;
	}
#endif

	// The socket has failed to initialize.
	if (this->ListenSocket == INVALID_SOCKET)
	{
		return false;
	}

	// Attempt to bind the socket to the specified port.
	if (!this->Bind(port))
	{
		return false;
	}

	// Start listening for Netflow input on a separate thread.
	this->mRunning = true;
	this->mSocketThread = std::thread(&EvoNetflowCollector::ListenerThread, this);

	return true;
}

// Stops the internal listener thread.
void EvoNetflowCollector::StopListening()
{
	this->mRunning = false;

	// Wait for the listener thread to finish before finalizing the application.
	this->mSocketThread.join();
}

// Internal listener function, runs asynchronously.
void EvoNetflowCollector::ListenerThread()
{
	sockaddr_storage clientinfo;
	char buffer[2048];

	// Set a timeout on the socket so that it does not block execution infinitely.
	unsigned long timeout = 25;
	setsockopt(this->ListenSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(unsigned long));

	// Increase the receive buffer to avoid packets being dropped.
	unsigned long buffersize = 65536;
	setsockopt(this->ListenSocket, SOL_SOCKET, SO_RCVBUF, (char*)&buffersize, sizeof(unsigned long));

	// Decrease the size of the send buffer. We don't need it.
	unsigned long sendbuffer = 1024;
	setsockopt(this->ListenSocket, SOL_SOCKET, SO_SNDBUF, (char*)&sendbuffer, sizeof(unsigned long));

	// Start receiving data from the listening socket.
	while (this->mRunning)
	{
		int clientinfolen = sizeof(clientinfo);

#ifdef _WIN32
		int bytesRead = recvfrom(this->ListenSocket, buffer, sizeof(buffer), 0, (sockaddr*)&clientinfo, &clientinfolen);
#else
		int bytesRead = recvfrom(this->ListenSocket, buffer, sizeof(buffer), 0, (sockaddr*)&clientinfo, (socklen_t*)&clientinfolen);
#endif
		if (bytesRead > 0)
		{
			// To avoid missing packets, dispatch the processing of each to another worker.
			char* safeBuffer = new char[bytesRead];
			memcpy(safeBuffer, buffer, bytesRead);
			QueuedPacketDescriptor desc(safeBuffer, bytesRead);

#ifdef _WIN32
			desc.GeneratorIpAddress.IpAddress4 = ((sockaddr_in*)&clientinfo)->sin_addr.S_un.S_addr;
#else
			desc.GeneratorIpAddress.IpAddress4 = ((sockaddr_in*)&clientinfo)->sin_addr.s_addr;
#endif
			// IPv6 connections, still need to implement it!
			eventDispatcher.QueuePacket(&desc);
		}
	}
}

// --------------------------------------------------------------------------------------------------------

// Retrieves the version of a Netflow packet. Used to spot invalid packets.
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

// Parses a Netflow v5 packet and returns the flows that are inside it.
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
	const PNETFLOW5_HEADER nfHeader = (PNETFLOW5_HEADER)buffer->PacketBuffer;

#ifdef _WIN32
	const unsigned short flowCount = SwapBytes(&nfHeader->FlowCount);
	if (flowCount > 30)
	{
		return false;
	}

	// Walk the flows in the packet and parse them using the Netflow v5 structures.
	outRecords.reserve(flowCount);
	PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(buffer->PacketBuffer + sizeof(NETFLOW5_HEADER));
	unsigned int seq = SwapBytes(&nfHeader->FlowSequence);
	for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
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
	if (nfHeader->FlowCount > 30)
	{
		return false;
	}

	// Walk the flows in the packet and parse them using the Netflow v5 structures.
	outSequences.push_back(nfHeader->FlowSequence);
	outRecords.reserve(nfHeader->FlowCount);
	PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(buffer->PacketBuffer + sizeof(NETFLOW5_HEADER));
	for (int i = 0; i < nfHeader->FlowCount; ++i, ++flowRecord)
	{
		outSequences.push_back(nfHeader->FlowSequence + i);
		outRecords.push_back(*flowRecord);
	}
#endif

	return true;
}

// Parses a Netflow v9 packet, handles templates and returns the flows inside of the packet.
const bool ParseNetflow9Packet(const QueuedPacketDescriptor* buffer, std::vector<unsigned int>& outSequences, std::vector<std::vector<EvoNetflow9FieldValueSet>>& outRecords)
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
	const int sequenceCounter = nfHeader->PackageSequence;

#ifdef _WIN32
	const unsigned long sourceId = SwapBytes(&nfHeader->SourceID);
	const unsigned short flowCount = SwapBytes(&nfHeader->FlowCount);
#else
	const unsigned long sourceId = nfHeader->SourceID;
	const unsigned short flowCount = nfHeader->FlowCount;
#endif

	// There cannot be more than 30 flows in the packet. If there are, it is invalid.
	if (flowCount > 30)
	{
		return false;
	}

	// Parse the packet until we run out of bytes. We must not run outside of the buffer.
	const char* packetIterator = buffer->PacketBuffer + sizeof(NETFLOW9_HEADER);
 	while (packetIterator < (buffer->PacketBuffer + buffer->PacketLength))
	{
		PNETFLOW9_FLOWSET_HEADER flowHeader = (PNETFLOW9_FLOWSET_HEADER)packetIterator;
#ifdef _WIN32
		const unsigned short flowsetId = SwapBytes(&flowHeader->FlowsetID);
		const unsigned short flowsetLength = SwapBytes(&flowHeader->Length);
#else
		const unsigned short flowsetId = flowHeader->FlowsetID;
		const unsigned short flowsetLength = flowHeader->Length;
#endif

		// Extra check for corrupt packets.
		if (!flowsetLength || flowsetLength > buffer->PacketLength)
		{
			return false;
		}

		packetIterator += sizeof(NETFLOW9_FLOWSET_HEADER);
		if (flowsetId < 256)
		{
			// Flowset ID of 1 is an options template. Flowset ID of 0 is a data template.
			if (flowsetId == 1)
			{
				 // Not supported yet. :)
			}
			else if (flowsetId == 0)
			{
				// The packet contains a data template.
				const PNETFLOW9_TEMPLATE_FLOWSET_HEADER templateHeader = (PNETFLOW9_TEMPLATE_FLOWSET_HEADER)packetIterator;
#ifdef _WIN32
				const unsigned short templateId = SwapBytes(&templateHeader->TemplateID);
				const unsigned short fieldCount = SwapBytes(&templateHeader->FieldCount);
#else
				const unsigned short templateId = templateHeader->TemplateID;
				const unsigned short fieldCount = templateHeader->FieldCount;
#endif

				// Walk the fields in the template and save it.
				packetIterator += sizeof(NETFLOW9_TEMPLATE_FLOWSET_HEADER);
				std::vector<NETFLOW9_TEMPLATE_FIELD> fields;
				for (unsigned short i = 0; i < fieldCount; ++i)
				{
					const PNETFLOW9_TEMPLATE_FIELD curEntry = (PNETFLOW9_TEMPLATE_FIELD)packetIterator;
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

				// Add the template to the cache. If the template already exists, the fields will be replaced.
				v9TemplateCacheInstance->AddTemplate(&buffer->GeneratorIpAddress, sourceId, templateId, fields);
			}
		}
		else if (flowsetId >= 256)
		{
			// Attempt to retrieve the template that is associated with the data. If no template is found, discard the packet.
			const PNETFLOW9_TEMPLATE_CACHE_ENTRY foundTemplate = v9TemplateCacheInstance->FindTemplate(flowsetId);
			if (foundTemplate)
			{
				// Walk the flows inside the flowset.
				unsigned short processedLength = 0;
				outRecords.reserve(flowCount);
				for (unsigned short i = 0; i < flowCount; ++i)
				{
					outSequences.push_back(sequenceCounter + i);
					std::vector<EvoNetflow9FieldValueSet> thisrecord;
					thisrecord.reserve(foundTemplate->FieldList.size());

					// Parse the data using the fields in the associated data template.
					const int currentLength = foundTemplate->ParseFieldsUsingTemplate((PNETFLOW9_DATA_FLOWSET_HEADER)packetIterator, thisrecord);
					processedLength += currentLength;
					packetIterator += currentLength;
					outRecords.push_back(thisrecord);
				}

				// If there is a padding at the end of the flowset, we can handle it by adding the leftover bytes to the iterator.
				packetIterator += flowsetLength - processedLength;
			}
			else
			{
				// If the data flowset could not be parsed using a template, skip it.
				packetIterator += flowsetLength;
			}
		}
	}

	return true;
}
