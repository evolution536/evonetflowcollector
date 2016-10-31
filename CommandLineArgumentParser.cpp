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

#include "CommandLineArgumentParser.h"
#include "GlobalDefinitions.h"

// Outputs help information to the user.
const String CommandLineArgumentParser::GetHelpOutput()
{
	return "Example: EvoNetflowCollector -p 9995 -D\n\nUsage:\n\n?, -h, --help\t\t\tDisplays this help information.\n"\
	"-p, --port <port>\t\tSets the UDP port to listen on. Must be greater than 0.\n-l, --logging <method>\t\t"\
	"Method of logging. One of: file null\n-o, --outfile <file>\t\tSets the output file that Netflow will be written to.\n"\
	"-D, --debug\t\t\tOutputs flows to stdout (Debugging purposes, logging method is optional).\n";
}

// ---------------------------------------------------------------------------------------------

// CommandLineArgumentParser default constructor.
CommandLineArgumentParser::CommandLineArgumentParser(const Vector<String>& args)
{
	// Initialize variables.
	this->helpArg = false;
	this->portArg = 0;
	this->debugModeArg = false;
	this->argumentCount = args.GetCount();
	this->methodArg = LOGGING_METHOD_UNDEFINED;
	
	// Parse command line arguments.
	this->Parse(args);
}

// CommandLineArgumentParser default destructor.
CommandLineArgumentParser::~CommandLineArgumentParser()
{
	
}

// ---------------------------------------------------------------------------------------------

// Parses the logging method entered as string.
const LoggingMethod CommandLineArgumentParser::ParseLoggingMethod(const String& str)
{
	if (str == "file")
	{
		return LOGGING_METHOD_FILE;
	}
	else if (str == "null")
	{
		return LOGGING_METHOD_NULL;
	}
	else
	{
		return LOGGING_METHOD_UNDEFINED;
	}
}

// Parses the command line.
void CommandLineArgumentParser::Parse(const Vector<String>& args)
{
	// Walk the arguments.
	const int argCount = args.GetCount();
	for (int i = 0; i < argCount; ++i)
	{
		// Check for the help argument.
		if (args[i] == "-h" || args[i] == "?" || args[i] == "--help")
		{
			this->helpArg = true;
		}
		else if ((args[i] == "-p" || args[i] == "--port") && i + 1 < argCount)
		{
			this->portArg = StrInt(args[++i]);
		}
		else if ((args[i] == "-l" || args[i] == "--logging") && i + 1 < argCount)
		{
			this->methodArg = this->ParseLoggingMethod(args[++i]);
		}
		else if ((args[i] == "-o" || args[i] == "--outfile") && i + 1 < argCount)
		{
			this->logfileArg = args[++i];
		}
		else if (args[i] == "-D" || args[i] == "--debug")
		{
			this->debugModeArg = true;
		}
	}
}

// ---------------------------------------------------------------------------------------------

// Gets the amount of parameters that were entered in the command line.
const int CommandLineArgumentParser::GetParameterCount() const
{
	return this->argumentCount;
}

// Gets whether command help was requested or not.
const bool CommandLineArgumentParser::GetWasHelpRequested() const
{
	return this->helpArg;
}

// Gets whether debug mode was requested or not.
const bool CommandLineArgumentParser::GetWasDebuggingMode() const
{
	return this->debugModeArg;
}

// Gets the logging method requested.
const LoggingMethod CommandLineArgumentParser::GetLoggingMethod() const
{
	return this->methodArg;
}

// Gets the path to the logfile.
const String& CommandLineArgumentParser::GetLogFileArgument() const
{
	return this->logfileArg;
}

// Gets the port argument.
const unsigned short CommandLineArgumentParser::GetPortArgument() const
{
	return this->portArg;
}