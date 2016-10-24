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

#include "NetflowFileLogger.h"
#include "UtilityFunctions.h"

// NetflowFileLogger default constructor.
NetflowFileLogger::NetflowFileLogger(const char* const fileName)
{
	this->methodId = LOGGING_METHOD_FILE;
	this->logFile.Open(fileName);
}

// NetflowFileLogger default destructor.
NetflowFileLogger::~NetflowFileLogger()
{
	// Flush the log file and close it.
	this->logFile.Flush();
	this->logFile.Close();
}

// Writes a row of Netflow v1 data to the opened log file.
const bool NetflowFileLogger::WriteNetflow1Record(const Netflow1Storage* const record)
{
	// If the file is not open, return false.
	if (!this->logFile.IsOpen())
	{
		return false;
	}
	
	// Create a string representation of the v1 flow information.
	StringBuffer buf;
	buf.Reserve(128);
	buf << TimeFromUTC(record->TimeStamp) << " FLOW v1 #" << record->FlowSequence << ": " << Ipv4ToString(record->FlowStorage.SourceIpAddress)
		<< ":" << record->FlowStorage.SourcePort << " <> " << Ipv4ToString(record->FlowStorage.DestinationIpAddress) << ":" << record->FlowStorage.DestinationPort
		<< " Protocol: " << NetflowParser::GetProtocolStringFromNumber(record->FlowStorage.Protocol) << " Bytes: " << record->FlowStorage.BytesCount
		<< " Packets: " << record->FlowStorage.PacketCount;
	
	// Write processed Netflow information as a string to the file.
	String str = buf;
	this->logFile.PutLine(str);

	return true;
}

// Writes a row of Netflow v5 data to the opened log file.
const bool NetflowFileLogger::WriteNetflow5Record(const Netflow5Storage* const record)
{
	// If the file is not open, return false.
	if (!this->logFile.IsOpen())
	{
		return false;
	}
	
	// Create a string representation of the v5 flow information.
	StringBuffer buf;
	buf.Reserve(128);
	buf << TimeFromUTC(record->TimeStamp) << " FLOW v5 #" << record->FlowSequence << ": " << Ipv4ToString(record->FlowStorage.SourceIpAddress)
		<< ":" << record->FlowStorage.SourcePort << " <> " << Ipv4ToString(record->FlowStorage.DestinationIpAddress) << ":" << record->FlowStorage.DestinationPort
		<< " Protocol: " << NetflowParser::GetProtocolStringFromNumber(record->FlowStorage.Protocol) << " Bytes: " << record->FlowStorage.BytesCount
		<< " Packets: " << record->FlowStorage.PacketCount;
	
	// Write processed Netflow information as a string to the file.
	String s = buf;
	this->logFile.PutLine(s);

	return true;
}

// Writes a row of Netflow v7 data to the opened log file.
const bool NetflowFileLogger::WriteNetflow7Record(const Netflow7Storage* const record)
{
	return true;
}

// Writes a row of Netflow v9 data to the opened log file.
const bool NetflowFileLogger::WriteNetflow9Record(const Netflow9Storage* const record)
{
	return true;
}

// Writes a row of IPFIX data to the opened log file.
const bool NetflowFileLogger::WriteIPFIXRecord(const IPFIXStorage* const record)
{
	return true;
}

// Indicates whether the logfile is ready to be written to. This means: is the file open.
const bool NetflowFileLogger::IsReady() const
{
	return this->logFile.IsOpen();
}