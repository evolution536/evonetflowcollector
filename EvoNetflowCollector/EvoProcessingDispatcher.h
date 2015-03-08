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

	std::function<void(const unsigned int, const PNETFLOW5_FLOW_RECORD)> FlowReceived5;
	std::function<void(const char*)> FlowReceived9;
};

#endif
