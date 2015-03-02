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
		delete[] this->mQueuedPackets.front();
		this->mQueuedPackets.pop_front();
	}
}

void EvoProcessingDispatcher::QueuePacket(char* const pPacket)
{
	this->mQueueCs.lock();
	this->mQueuedPackets.push_back(pPacket);
	this->mQueueCs.unlock();
}

void EvoProcessingDispatcher::ProcessPacket(char* const pPacket)
{
	std::vector<unsigned int> sequenceNumbers;
	std::vector<NETFLOW5_FLOW_RECORD> flows;
	ParseNetflow5Packet((char*)pPacket, sequenceNumbers, flows);

	for (unsigned int i = 0; i < flows.size(); ++i)
	{
		this->FlowReceived(sequenceNumbers[i], &flows[i]);
	}

	delete[] pPacket;
}

void EvoProcessingDispatcher::StartDispatcher()
{
	this->_running = true;
	std::thread dispatchThread(&EvoProcessingDispatcher::ProcessingLoop, this);
	dispatchThread.detach();
}

void EvoProcessingDispatcher::StopDispatcher()
{
	this->_running = false;
}

void EvoProcessingDispatcher::ProcessingLoop()
{
	while (this->_running)
	{
		while (this->mQueuedPackets.size() > 0)
		{
			this->ProcessPacket(this->mQueuedPackets.front());
			this->mQueuedPackets.pop_front();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
}
