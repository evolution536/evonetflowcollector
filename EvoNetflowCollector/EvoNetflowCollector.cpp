#include "EvoNetflowCollector.h"
#include "UtilityFunctions.h"
#include "EvoProcessingDispatcher.h"

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
		int bytesRead = recvfrom(this->ListenSocket, buffer, sizeof(buffer), 0, (sockaddr*)&clientinfo, &clientinfolen);
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

const bool ParseNetflow5Packet(const char* buffer, std::vector<unsigned int>& outSequences, std::vector<NETFLOW5_FLOW_RECORD>& outRecords)
{
	if (!buffer)
	{
		return false;
	}

	// Check if the packet is a valid Netflow packet.
	const PNETFLOW5_HEADER nfHeader = (PNETFLOW5_HEADER)buffer;
#ifdef _WIN32
	if (SwapBytes(&nfHeader->Version) != 5)
#else
	if (nfHeader->Version != 5)
#endif
	{
		return false;
	}

	// Retrieve flows from the packet.
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
