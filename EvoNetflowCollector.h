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

#ifndef _EvoNetflowCollector_EvoNetflowCollector_h_
#define _EvoNetflowCollector_EvoNetflowCollector_h_

#include <Core/Core.h>

using namespace Upp;

// Represents the information variables structure for the collector application.
struct EvoNetflowCollector
{
	// The time at which the collection was started.
	Time StartTime;
	
	// The total number of flows that were collected.
	int64 TotalFlows;
	
	// The total number of bytes that were collected.
	int64 TotalBytes;
};

#endif
