#ifndef EVO_PROCESSING_DISPATCHER_H
#define EVO_PROCESSING_DISPATCHER_H

#include "EvoNetflow.h"
#include <deque>
#include <functional>
#include <mutex>

class EvoProcessingDispatcher
{
private:
	std::deque<char*> mQueuedPackets;
	bool _running;
	std::mutex mQueueCs;

	void ProcessPacket(char* const pPacket);
	void ProcessingLoop();
public:
	EvoProcessingDispatcher();
	~EvoProcessingDispatcher();

	void QueuePacket(char* const pPacket);
	void StartDispatcher();
	void StopDispatcher();

	std::function<void(const unsigned int, const PNETFLOW5_FLOW_RECORD)> FlowReceived;
};

#endif
