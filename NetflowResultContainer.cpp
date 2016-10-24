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

#include "NetflowResultContainer.h"
#include "GlobalDefinitions.h"

// NetflowResultContainer default constructor.
NetflowResultContainer::NetflowResultContainer()
{
	this->mDroppedFlows = 0;
	
	// Initialize the Netflow v1 back buffer.
	this->mv1BufferSize = 0;
	this->mv1BackBuffer = new Netflow1Storage[BACK_BUFFER_SIZE_PER_VERSION];
	
	// Initialize the Netflow v5 back buffer.
	this->mv5BufferSize = 0;
	this->mv5BackBuffer = new Netflow5Storage[BACK_BUFFER_SIZE_PER_VERSION];

	// Initialize the Netflow v7 back buffer.
	this->mv7BufferSize = 0;
	this->mv7BackBuffer = new Netflow7Storage[BACK_BUFFER_SIZE_PER_VERSION];
}

// NetflowResultContainer default destructor.
NetflowResultContainer::~NetflowResultContainer()
{
	// Release the back buffers.
	delete[] this->mv1BackBuffer;
	delete[] this->mv5BackBuffer;
	delete[] this->mv7BackBuffer;
}

// ---------------------------------------------------------------------------------------------

// Retrieves the number of flows that were dropped as a result of a full back buffer.
const unsigned int NetflowResultContainer::GetDroppedFlowCount() const
{
	return this->mDroppedFlows;
}

// ---------------------------------------------------------------------------------------------

// Retrieves the size of the Netflow v1 back buffer, without copying anything.
const unsigned int NetflowResultContainer::GetNetflow1BackBufferSize() const
{
	return this->mv1BufferSize;
}

// Retrieves the size of the Netflow v5 back buffer, without copying anything.
const unsigned int NetflowResultContainer::GetNetflow5BackBufferSize() const
{
	return this->mv5BufferSize;
}

// Retrieves the size of the Netflow v7 back buffer, without copying anything.
const unsigned int NetflowResultContainer::GetNetflow7BackBufferSize() const
{
	return this->mv7BufferSize;
}

// ---------------------------------------------------------------------------------------------

// Retrieves all processed Netflow v1 flows that are inside the back buffer.
const unsigned int NetflowResultContainer::GetNetflow1BackBuffer(Vector<Netflow1Storage>& frontBuffer)
{
	// Lock the back buffer.
	this->mv1CS.Enter();
	
	// Move all entries in the back buffer to the front buffer.
	frontBuffer.Reserve(this->mv1BufferSize);
	for (unsigned int i = 0; i < this->mv1BufferSize; ++i)
	{
		frontBuffer << this->mv1BackBuffer[i];
	}
	
	// Clear the back buffer.
	this->mv1BufferSize = 0;
	
	// Release the lock.
	this->mv1CS.Leave();
	
	// Return the amount of flows copied.
	return frontBuffer.GetCount();
}

// Retrieves all processed Netflow v5 flows that are inside the back buffer.
const unsigned int NetflowResultContainer::GetNetflow5BackBuffer(Vector<Netflow5Storage>& frontBuffer)
{
	// Lock the back buffer.
	this->mv5CS.Enter();
	
	// Move all entries in the back buffer to the front buffer.
	frontBuffer.Reserve(this->mv5BufferSize);
	for (unsigned int i = 0; i < this->mv5BufferSize; ++i)
	{
		frontBuffer << this->mv5BackBuffer[i];
	}
	
	// Clear the back buffer.
	this->mv5BufferSize = 0;
	
	// Release the lock.
	this->mv5CS.Leave();
	
	// Return the amount of flows copied.
	return frontBuffer.GetCount();
}

// Retrieves all processed Netflow v7 flows that are inside the back buffer.
const unsigned int NetflowResultContainer::GetNetflow7BackBuffer(Vector<Netflow7Storage>& frontBuffer)
{
	// Lock the back buffer.
	this->mv7CS.Enter();
	
	// Move all entries in the back buffer to the front buffer.
	frontBuffer.Reserve(this->mv7BufferSize);
	for (unsigned int i = 0; i < this->mv7BufferSize; ++i)
	{
		frontBuffer << this->mv7BackBuffer[i];
	}
	
	// Clear the back buffer.
	this->mv7BufferSize = 0;
	
	// Release the lock.
	this->mv7CS.Leave();
	
	// Return the amount of flows copied.
	return frontBuffer.GetCount();
}

// ---------------------------------------------------------------------------------------------

// Pushes processed Netflow v1 flows to the back buffer.
const unsigned int NetflowResultContainer::PushNetflow1Flows(const Vector<Netflow1Storage>& flows)
{
	const int flowCount = flows.GetCount();
	const int possible = BACK_BUFFER_SIZE_PER_VERSION - this->mv1BufferSize;
	int number = 0;
	
	// Check whether there are still flows allowed in the Netflow v5 back buffer.
	if (possible > 0)
	{
		// Lock the back buffer.
		this->mv1CS.Enter();
		
		// Copy flows to the back buffer.
		number = min(possible, flowCount);
		for (int i = 0; i < number; ++i)
		{
			this->mv1BackBuffer[this->mv1BufferSize + i] = flows[i];
		}
		
		// Change the buffer size.
		this->mv1BufferSize += number;
		
		// Release the lock.
		this->mv1CS.Leave();
	}
	
	// Count the number of dropped flows.
	this->mDroppedFlows += flowCount - number;
	
	// Return the number of flows that were actually added to the back buffer.
	// The flows that were not added were dropped because the buffer was full.
	return number;
}

// Pushes processed Netflow v5 flows to the back buffer.
const unsigned int NetflowResultContainer::PushNetflow5Flows(const Vector<Netflow5Storage>& flows)
{
	const int flowCount = flows.GetCount();
	const int possible = BACK_BUFFER_SIZE_PER_VERSION - this->mv5BufferSize;
	int number = 0;
	
	// Check whether there are still flows allowed in the Netflow v5 back buffer.
	if (possible > 0)
	{
		// Lock the back buffer.
		this->mv5CS.Enter();
		
		// Copy flows to the back buffer.
		number = min(possible, flowCount);
		for (int i = 0; i < number; ++i)
		{
			this->mv5BackBuffer[this->mv5BufferSize + i] = flows[i];
		}
		
		// Change the buffer size.
		this->mv5BufferSize += number;
		
		// Release the lock.
		this->mv5CS.Leave();
	}
	
	// Count the number of dropped flows.
	this->mDroppedFlows += flowCount - number;
	
	// Return the number of flows that were actually added to the back buffer.
	// The flows that were not added were dropped because the buffer was full.
	return number;
}

// Pushes processed Netflow v7 flows to the back buffer.
const unsigned int NetflowResultContainer::PushNetflow7Flows(const Vector<Netflow7Storage>& flows)
{
	const int flowCount = flows.GetCount();
	const int possible = BACK_BUFFER_SIZE_PER_VERSION - this->mv7BufferSize;
	int number = 0;
	
	// Check whether there are still flows allowed in the Netflow v5 back buffer.
	if (possible > 0)
	{
		// Lock the back buffer.
		this->mv7CS.Enter();
		
		// Copy flows to the back buffer.
		number = min(possible, flowCount);
		for (int i = 0; i < number; ++i)
		{
			this->mv7BackBuffer[this->mv7BufferSize + i] = flows[i];
		}
		
		// Change the buffer size.
		this->mv7BufferSize += number;
		
		// Release the lock.
		this->mv7CS.Leave();
	}
	
	// Count the number of dropped flows.
	this->mDroppedFlows += flowCount - number;
	
	// Return the number of flows that were actually added to the back buffer.
	// The flows that were not added were dropped because the buffer was full.
	return number;
}