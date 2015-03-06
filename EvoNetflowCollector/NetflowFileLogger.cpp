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

#include "NetflowLogger.h"

NetflowFileLogger::NetflowFileLogger(const char* fileName)
{
	this->logFile.open(fileName, std::ofstream::out | std::ofstream::app);
}

NetflowFileLogger::~NetflowFileLogger()
{
	this->logFile.close();
}

// Writes a row of Netflow data to the opened log file.
const bool NetflowFileLogger::WriteNetflow(const std::string& netflowString)
{
	if (!this->logFile.is_open())
	{
		return false;
	}

	this->logFile << netflowString.c_str() << std::endl;
	this->logFile.flush();

	return true;
}

// Indicates whether the logfile is ready to be written to. This means: is the file open.
const bool NetflowFileLogger::IsReady() const
{
	return this->logFile.is_open();
}