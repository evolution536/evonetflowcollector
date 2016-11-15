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

#ifndef _EvoNetflowCollector_CommandLineArgumentParser_h_
#define _EvoNetflowCollector_CommandLineArgumentParser_h_

#include <Core/Core.h>

using namespace Upp;

#include "GlobalDefinitions.h"

// Class responsible for parsing command line arguments.
class CommandLineArgumentParser
{
private:
	bool helpArg;
	unsigned short portArg;
	LoggingMethod methodArg;
	String logfileArg;
	bool debugModeArg;
	unsigned int argumentCount;
	bool testModeArg;
	
	void Parse(const Vector<String>& args);
	const LoggingMethod ParseLoggingMethod(const String& str);
public:
	CommandLineArgumentParser(const Vector<String>& args);
	~CommandLineArgumentParser();
	
	static const String GetHelpOutput();
	
	const int GetParameterCount() const;
	const bool GetWasHelpRequested() const;
	const bool GetWasDebuggingMode() const;
	const LoggingMethod GetLoggingMethod() const;
	const String& GetLogFileArgument() const;
	const unsigned short GetPortArgument() const;
	const bool GetWasTestMode() const;
};

#endif
