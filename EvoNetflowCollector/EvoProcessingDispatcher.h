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

#ifndef EVO_PROCESSING_DISPATCHER_H
#define EVO_PROCESSING_DISPATCHER_H

#include "EvoNetflow.h"
#include <deque>
#include <functional>
#include <mutex>
#include <vector>
#include <thread>

union UNIVERSAL_IPADDRESS
{
	IPV4ADDRESS IpAddress4;
	IPV6ADDRESS IpAddress6;
};

// Represents a field/value set from a Netflow v9 input.
struct EvoNetflow9FieldValueSet
{
	unsigned short Field;
	std::string Value;
};

struct QueuedPacketDescriptor
{
	const char* PacketBuffer;
	unsigned int PacketLength;
	UNIVERSAL_IPADDRESS GeneratorIpAddress;

	QueuedPacketDescriptor(const char* buffer, const unsigned int length)
	{
		this->PacketBuffer = buffer;
		this->PacketLength = length;
		this->GeneratorIpAddress = { 0 };
	};
};

class EvoProcessingDispatcher
{
private:
	std::deque<QueuedPacketDescriptor> mQueuedPackets;
	bool _running;
	std::mutex mQueueCs;
	std::thread mRunningthread;

	void ProcessPacket(QueuedPacketDescriptor* const pPacket);
	void ProcessingLoop();
public:
	EvoProcessingDispatcher();
	~EvoProcessingDispatcher();

	void QueuePacket(QueuedPacketDescriptor* const pPacket);
	void StartDispatcher();
	void StopDispatcher();

	std::function<void(const unsigned int, const PNETFLOW5_FLOW_RECORD)> FlowReceived5;
	std::function<void(const unsigned int, const std::vector<EvoNetflow9FieldValueSet>&)> FlowReceived9;
};

#endif
