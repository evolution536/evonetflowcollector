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

#include "NetflowNullLogger.h"

// NetflowNullLogger default constructor.
NetflowNullLogger::NetflowNullLogger()
{
	
}

// NetflowNullLogger default destructor.
NetflowNullLogger::~NetflowNullLogger()
{
	
}
// Null function for a Netflow v1 flow record.
const bool NetflowNullLogger::WriteNetflow1Record(const Netflow1Storage* const record)
{
	return true;
}

// Null function for a Netflow v5 flow record.
const bool NetflowNullLogger::WriteNetflow5Record(const Netflow5Storage* const record)
{
	return true;
}

// Null function for a Netflow v7 flow record.
const bool NetflowNullLogger::WriteNetflow7Record(const Netflow7Storage* const record)
{
	return true;
}

// Null function for a Netflow v9 flow record.
const bool NetflowNullLogger::WriteNetflow9Record(const Netflow9Storage* const record)
{
	return true;
}

// Null function for an IPFIX flow record.
const bool NetflowNullLogger::WriteIPFIXRecord(const IPFIXStorage* const record)
{
	return true;
}

// The null logger is always reader.
const bool NetflowNullLogger::IsReady() const
{
	return true;
}