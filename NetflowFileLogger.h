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

#ifndef _EvoNetflowCollector_NetflowFileLogger_h_
#define _EvoNetflowCollector_NetflowFileLogger_h_

#include "NetflowLogger.h"

// Represents the Netflow file dumper. It writes rows of text to a file.
class NetflowFileLogger : public NetflowLogger
{
private:
	FileOut logFile;
public:
	NetflowFileLogger(const char* const fileName);
	~NetflowFileLogger();

	virtual const bool WriteNetflow1Record(const Netflow1Storage* const record);
	virtual const bool WriteNetflow5Record(const Netflow5Storage* const record);
	virtual const bool WriteNetflow7Record(const Netflow7Storage* const record);
	virtual const bool WriteNetflow9Record(const Netflow9Storage* const record);
	virtual const bool WriteIPFIXRecord(const IPFIXStorage* const record);
	virtual const bool IsReady() const;
};

#endif