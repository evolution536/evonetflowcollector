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
	
	// Initialize the Netflow v5 back buffer.
	this->mv5BufferSize = 0;
	this->mv5BackBuffer = new Netflow5Storage[BACK_BUFFER_SIZE_PER_VERSION];
}

// NetflowResultContainer default destructor.
NetflowResultContainer::~NetflowResultContainer()
{
	// Release the back buffers.
	delete[] this->mv5BackBuffer;
}

// ---------------------------------------------------------------------------------------------

// Retrieves the number of flows that were dropped as a result of a full back buffer.
const unsigned int NetflowResultContainer::GetDroppedFlowCount() const
{
	return this->mDroppedFlows;
}

// ---------------------------------------------------------------------------------------------

// Retrieves the size of the Netflow v5 back buffer, without copying anything.
const unsigned int NetflowResultContainer::GetNetflow5BackBufferSize() const
{
	return this->mv5BufferSize;
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

// ---------------------------------------------------------------------------------------------

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