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

#ifndef _EvoNetflowCollector_NetflowParser_h_
#define _EvoNetflowCollector_NetflowParser_h_

#include <Core/Core.h>

using namespace Upp;

#include "EvoNetflow.h"

// Represents a processing task for the parser.
struct ProcessingTask : public Moveable<ProcessingTask>
{
	// Represents the Netflow version that this task is about.
	unsigned int Version;
	
	// The buffer for the packet.
	char PacketBuffer[4096];
	
	// The length of the packet buffer.
	unsigned int PacketLength;
	
	// The IP address of the exporter of this packet.
	UNIVERSAL_IPADDRESS ExporterIpAddress;
	
	// Default constructor.
	ProcessingTask()
	{
		this->Version = 0;
		this->PacketLength = 0;
		this->ExporterIpAddress = {};
	};
	
	// Initializing constructor.
	ProcessingTask(const unsigned int version, const char* buffer, const unsigned int length, const UNIVERSAL_IPADDRESS* const expip)
	{
		this->Version = version;
		memcpy(this->PacketBuffer, buffer, length);
		this->PacketLength = length;
		this->ExporterIpAddress = *expip;
	};
};

// A parser class for Netflow v5, v9 and IPFIX.
class NetflowParser
{
private:
	Thread mProcessingThread;
	bool mRunning;
	CoWork mThreadPool;
	BiVector<ProcessingTask> mQueuedTasks;
	CriticalSection mLock;
	unsigned int mFailedTasks;
	
	void ProcessTask(const ProcessingTask& task);
	void ProcessingLoop();
	
	typedef NetflowParser CLASSNAME;
	
	void ParseNetflow5Packet(const char* packet, const unsigned int length);
	void ParseNetflow9Packet(const char* packet, const unsigned int length);
	void ParseIPFIXPacket(const char* packet, const unsigned int length);
public:
	NetflowParser();
	~NetflowParser();
	
	const bool IsRunning() const;
	const unsigned int GetFailedTasks() const;
	
	void StartParser();
	void StopParser();
	
	void QueueTask(const unsigned int version, const char* packet, const unsigned int length, const UNIVERSAL_IPADDRESS* const expip);
	
	static const char* const GetProtocolStringFromNumber(const unsigned int number);
};

#endif