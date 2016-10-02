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

#include "EvoProcessingDispatcher.h"
#include "EvoNetflowCollector.h"
#include <vector>

EvoProcessingDispatcher::EvoProcessingDispatcher()
{
	this->_running = false;
}

EvoProcessingDispatcher::~EvoProcessingDispatcher()
{
	while (this->mQueuedPackets.size() > 0)
	{
		delete[] this->mQueuedPackets.front().PacketBuffer;
		this->mQueuedPackets.pop_front();
	}
}

void EvoProcessingDispatcher::QueuePacket(QueuedPacketDescriptor* const pPacket)
{
	this->mQueueCs.lock();
	this->mQueuedPackets.push_back(*pPacket);
	this->mQueueCs.unlock();
}

void EvoProcessingDispatcher::ProcessPacket(QueuedPacketDescriptor* const pPacket)
{
	const int netflowVersion = CheckNetflowPacketVersion(pPacket->PacketBuffer);

	// Netflow v5 packet.
	if (netflowVersion == 5)
	{
		std::vector<NETFLOW5_FLOW_RECORD> flows;
		std::vector<unsigned int> sequenceNumbers;
		if (ParseNetflow5Packet(pPacket, sequenceNumbers, flows))
		{
			for (unsigned int i = 0; i < flows.size(); ++i)
			{
				this->FlowReceived5(sequenceNumbers[i], &flows[i]);
			}
		}
	}
	// Netflow v9 packet.
	else if (netflowVersion == 9)
	{
		std::vector<std::vector<EvoNetflow9FieldValueSet>> flows;
		std::vector<unsigned int> sequenceNumbers;
		if (ParseNetflow9Packet(pPacket, sequenceNumbers, flows))
		{
			for (unsigned int i = 0; i < flows.size(); ++i)
			{
				this->FlowReceived9(sequenceNumbers[i], flows[i]);
			}
		}
	}
	// IPFIX packet.
	else if (netflowVersion == 10)
	{

	}

	delete[] pPacket->PacketBuffer;
}

void EvoProcessingDispatcher::StartDispatcher()
{
	this->_running = true;
	this->mRunningthread = std::thread(&EvoProcessingDispatcher::ProcessingLoop, this);
}

void EvoProcessingDispatcher::StopDispatcher()
{
	this->_running = false;
	this->mRunningthread.join();
}

void EvoProcessingDispatcher::ProcessingLoop()
{
	while (this->_running)
	{
		this->mQueueCs.lock();
		while (this->mQueuedPackets.size() > 0)
		{
			this->ProcessPacket(&this->mQueuedPackets.front());
			this->mQueuedPackets.pop_front();
		}

		this->mQueueCs.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}
