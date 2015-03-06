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

#include <iostream>
#include <fstream>

// Represents the base class of a Netflow log dumper. Netflow is collected and dumped, for example to a file.
class NetflowLogger
{
private:

public:
	NetflowLogger() { }
	virtual ~NetflowLogger() { }

	virtual const bool WriteNetflow(const std::string& netflowString) = 0;
	virtual const bool IsReady() const = 0;
};

// Represents the Netflow file dumper. It writes rows of text to a file.
class NetflowFileLogger : public NetflowLogger
{
private:
	std::ofstream logFile;
public:
	NetflowFileLogger(const char* fileName);
	~NetflowFileLogger();

	virtual const bool WriteNetflow(const std::string& netflowString);
	virtual const bool IsReady() const;
};