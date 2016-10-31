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

#include "NetflowCollector.h"
#include "UtilityFunctions.h"
#include "GlobalDefinitions.h"

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

// Specifies the size of the socket listening queue.
#define LISTEN_QUEUE 128

// NetflowCollector default constructor.
NetflowCollector::NetflowCollector()
{
	this->mRunning = false;
	this->mSocket = SOCKET_ERROR;
}

// NetflowCollector default destructor.
NetflowCollector::~NetflowCollector()
{
#ifdef _WIN32
	closesocket(this->mSocket);
	WSACleanup();
#else
	close(this->mSocket);
#endif
}

// Binds the socket to the correct port. Currently only IPv4!
const bool NetflowCollector::Bind(const unsigned short port)
{
#ifdef _WIN32
	// Running in Windows, we need to initiate WinSock.
	WSADATA wsaData;
	const int wsaReturn = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsaReturn != 0)
	{
		return false;
	}
#endif

	// From nfcapd.c (NfDump).
	struct addrinfo hints, *res, *ressave;
	memset(&hints, 0, sizeof(struct addrinfo));

	// AI_PASSIVE flag: we use the resulting address to bind to a socket for accepting incoming connections.
	// So, when the hostname == NULL, getaddrinfo function will return one entry per allowed protocol family containing
	// the unspecified address for that family.
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    // Get address information for our socket.
    if (getaddrinfo(NULL, IntStr(port), &hints, &res) != 0)
    {
        return false;
    }

	// Try open socket with each address getaddrinfo returned, until we get a valid listening socket.
    ressave = res;
    while (res)
    {
        // We only want to listen on IPv4 or IPv6.
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
		{
			continue;
		}

		// Try to create a socket on the currently iterated address.
		this->mSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

		// Check whether the socket was succesfully created.
		if (this->mSocket != SOCKET_ERROR)
		{
			// Try to bind the socket.
			if (bind(this->mSocket, res->ai_addr, res->ai_addrlen) == 0)
			{
				// Succesfully bound, quit the loop.
				break;
			}
			else
			{
				// Bind was unsuccesful.
#ifdef _WIN32
				closesocket(this->mSocket);
#else
				close(this->mSocket);
#endif
			}
		}

		// Try the next address.
		res = res->ai_next;
    }

	// Free the address information structure used to bind the socket.
	freeaddrinfo(ressave);

	// Created socket and bound succesfully?
	if (this->mSocket == SOCKET_ERROR)
	{
		return false;
	}

	// Place the socket in listening mode. It doesn't matter whether this call succeeds or not.
	listen(this->mSocket, LISTEN_QUEUE);

	// Did we succeed?
	return this->mSocket != SOCKET_ERROR;
}

// ---------------------------------------------------------------------------------------------

// Sets socket options for the receive socket.
void NetflowCollector::SetSocketOptions()
{
	// Set a timeout on the socket so that it does not block execution infinitely.
	unsigned long timeout = 25;
	setsockopt(this->mSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(unsigned long));

	// Increase the receive buffer to avoid packets being dropped.
	int p;
	socklen_t optlen = sizeof(socklen_t);
	getsockopt(this->mSocket, SOL_SOCKET, SO_RCVBUF, (char*)&p, &optlen);

	// If the current buffer size is too small, we need to increase it.
	if (p != SOCKET_ERROR && p < SOCKET_MINIMUM_BUFFER_SIZE)
	{
		const unsigned long buffersize = SOCKET_MINIMUM_BUFFER_SIZE;
		setsockopt(this->mSocket, SOL_SOCKET, SO_RCVBUF, (char*)&buffersize, sizeof(unsigned long));
	}

	// Decrease the size of the send buffer. We don't need it.
	unsigned long sendbuffer = 1024;
	setsockopt(this->mSocket, SOL_SOCKET, SO_SNDBUF, (char*)&sendbuffer, sizeof(unsigned long));
}

// Retrieves the version of a Netflow packet. Used to spot invalid packets.
const int NetflowCollector::CheckNetflowPacketVersion(const char* buffer) const
{
	if (buffer)
	{
		return (int)ntohs(*(unsigned short*)buffer);
	}

	return 0;
}

// The message loop for the collector.
void NetflowCollector::ListenerThread()
{
	// Storage for the source IP address.
	sockaddr_storage clientinfo;

	// Buffer for receiving packets. The maximum UDP packet size is 64kb.
	char recvBuffer[4096];

	// Adjust socket options.
	this->SetSocketOptions();

	// Start the message loop.
	while (this->mRunning)
	{
		int clientinfolen = sizeof(clientinfo);

		// Receive data from the UDP socket.
#ifdef _WIN32
		int bytesRead = recvfrom(this->mSocket, recvBuffer, sizeof(recvBuffer), 0, (sockaddr*)&clientinfo, &clientinfolen);
#else
		int bytesRead = recvfrom(this->mSocket, recvBuffer, sizeof(recvBuffer), 0, (sockaddr*)&clientinfo, (socklen_t*)&clientinfolen);
#endif
		// Did we receive a packet?
		if (bytesRead > 0)
		{
			// Retrieve the IPv4 address of the exporter.
#ifdef _WIN32
			const IPV4ADDRESS ipaddr = ((sockaddr_in*)&clientinfo)->sin_addr.S_un.S_addr;
#else
			const IPV4ADDRESS ipaddr = ((sockaddr_in*)&clientinfo)->sin_addr.s_addr;
#endif

			// Queue the packet for processing.
			GlobalNetflowParser->QueueTask(this->CheckNetflowPacketVersion(recvBuffer), recvBuffer, bytesRead, (UNIVERSAL_IPADDRESS*)&ipaddr);
		}
	}
}

// ---------------------------------------------------------------------------------------------

// Starts the listener thread to listen for Netflow packets.
const bool NetflowCollector::BeginListen(const int port)
{
	// Attempt to bind the socket to the specified port.
	if (!this->Bind(port))
	{
		return false;
	}

	// Start listening for Netflow input on a separate thread.
	this->mRunning = true;
	this->mSocketListeningThread.Run(THISBACK(ListenerThread));

	return true;
}

// Stops the internal listener thread.
void NetflowCollector::StopListening()
{
	this->mRunning = false;

	// Wait for the listener thread to finish before finalizing the application.
	this->mSocketListeningThread.Wait();
}
