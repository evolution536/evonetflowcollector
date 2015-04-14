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

#ifndef EVO_NETFLOW_COLLECTOR_H
#define EVO_NETFLOW_COLLECTOR_H

#ifdef _WIN32
	#include <winsock2.h>
#else
	#include <sys/socket.h>
#endif

#include "EvoNetflow.h"
#include "EvoProcessingDispatcher.h"
#include <vector>
#include <thread>

class EvoNetflowCollector
{
private:
#ifdef _WIN32
	SOCKET ListenSocket;
#else
	int ListenSocket;
#endif
	bool mRunning;
	std::thread mSocketThread;

	void ListenerThread();
public:
	EvoNetflowCollector();
	~EvoNetflowCollector();

	const bool Bind(const int port);
	const bool BeginListen();
	void StopListening();
};

const int CheckNetflowPacketVersion(const char* buffer);
const bool ParseNetflow5Packet(const QueuedPacketDescriptor* buffer, std::vector<unsigned int>& outSequences, std::vector<NETFLOW5_FLOW_RECORD>& outRecords);
const bool ProcessNetflow9FieldValue(const unsigned int fieldType, const unsigned int fieldLength, const char* fieldVal, std::stringstream& outVal);
const bool ParseNetflow9Packet(const QueuedPacketDescriptor* buffer, std::vector<unsigned int>& outSequences, std::vector<std::vector<EvoNetflow9FieldValueSet>>& outRecords);

#endif