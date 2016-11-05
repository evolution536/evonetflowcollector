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

#ifndef _EvoNetflowCollector_NetflowResultContainer_h_
#define _EvoNetflowCollector_NetflowResultContainer_h_

#include <Core/Core.h>

using namespace Upp;

#include "Netflow1.h"
#include "Netflow5.h"
#include "Netflow7.h"
#include "Netflow9.h"
#include "IPFIX.h"

// Represents a Netflow v1 storage structure that includes the sequence number.
struct Netflow1Storage : Moveable<Netflow1Storage>
{
	// The timestamp of the flow.
	unsigned long TimeStamp;
	
	// The flow record.
	NETFLOW1_FLOW_RECORD FlowStorage;
};

// Represents a Netflow v5 storage structure that includes the sequence number.
struct Netflow5Storage : Moveable<Netflow5Storage>
{
	// The timestamp of the flow.
	unsigned long TimeStamp;
	
	// The flow sequence number.
	unsigned long FlowSequence;
	
	// The flow record.
	NETFLOW5_FLOW_RECORD FlowStorage;
};

// Represents a Netflow v7 storage structure that includes the sequence number.
struct Netflow7Storage : Moveable<Netflow7Storage>
{
	// The timestamp of the flow.
	unsigned long TimeStamp;
	
	// The flow sequence number.
	unsigned long FlowSequence;
	
	// The flow record.
	NETFLOW7_FLOW_RECORD FlowStorage;
};

// Represents a combination of a field type with a parsed string representation of its value.
struct FieldStorageStruct
{
	// The field value in parsed state.
	char FieldValue[64];
	
	// Let's put a copy operator here, to simplify the assignment code.
	FieldStorageStruct& operator=(const FieldStorageStruct& other)
	{
		memcpy(this->FieldValue, other.FieldValue, sizeof(this->FieldValue));
		return *this;
	};
};

// Represents a Netflow v9 storage structure that includes the sequence number.
struct Netflow9Storage : Moveable<Netflow9Storage>
{
	// The timestamp of the flow.
	unsigned long TimeStamp;
	
	// The flow sequence number.
	unsigned long FlowSequence;
	
	// Collection of fields including their values.
	FieldStorageStruct FlowStorage[128];
	
	// Assignment operator here as well.
	Netflow9Storage& operator=(const Netflow9Storage& other)
	{
		this->FlowSequence = other.FlowSequence;
		for (int i = 0; i < sizeof(this->FlowStorage) / sizeof(this->FlowStorage[0]); ++i)
		{
			this->FlowStorage[i] = other.FlowStorage[i];
		}
		
		return *this;
	};
};

// Represents an IPFIX storage structure that includes the sequence number.
struct IPFIXStorage : Moveable<IPFIXStorage>
{
	
};

// Keeps track of processed Netflow packets, ready for output.
class NetflowResultContainer
{
private:
	// Back buffer size variables.
	unsigned long mv1BufferSize;
	unsigned long mv5BufferSize;
	unsigned long mv7BufferSize;
	unsigned long mv9BufferSize;
	
	// Back buffer definitions.
	Netflow1Storage* mv1BackBuffer;
	Netflow5Storage* mv5BackBuffer;
	Netflow7Storage* mv7BackBuffer;
	Netflow9Storage* mv9BackBuffer;
	
	// Critical sections matching the back buffers.
	CriticalSection mv1CS;
	CriticalSection mv5CS;
	CriticalSection mv7CS;
	CriticalSection mv9CS;
	
	unsigned long mDroppedFlows;
	
	NetflowResultContainer();
	~NetflowResultContainer();
	
	NetflowResultContainer(NetflowResultContainer const&);
	void operator=(NetflowResultContainer const&);
public:
	static NetflowResultContainer* GetInstance()
	{
		static NetflowResultContainer instance;
		return &instance;
	}
	
	const unsigned long GetDroppedFlowCount() const;
	
	// Retrieval functions.
	const unsigned long GetNetflow1BackBufferSize() const;
	const unsigned long GetNetflow5BackBufferSize() const;
	const unsigned long GetNetflow7BackBufferSize() const;
	const unsigned long GetNetflow9BackBufferSize() const;
	
	const unsigned long GetNetflow1BackBuffer(Vector<Netflow1Storage>& frontBuffer);
	const unsigned long GetNetflow5BackBuffer(Vector<Netflow5Storage>& frontBuffer);
	const unsigned long GetNetflow7BackBuffer(Vector<Netflow7Storage>& frontBuffer);
	const unsigned long GetNetflow9BackBuffer(Vector<Netflow9Storage>& frontBuffer);
	
	// Push functions.
	const unsigned long PushNetflow1Flows(const Vector<Netflow1Storage>& flows);
	const unsigned long PushNetflow5Flows(const Vector<Netflow5Storage>& flows);
	const unsigned long PushNetflow7Flows(const Vector<Netflow7Storage>& flows);
	const unsigned long PushNetflow9Flows(const Vector<Netflow9Storage>& flows);
};

#endif
