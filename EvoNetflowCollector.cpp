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

#include <signal.h>

#include "EvoNetflowCollector.h"
#include "CommandLineArgumentParser.h"
#include "GlobalDefinitions.h"
#include "NetflowFileLogger.h"
#include "NetflowCollector.h"
#include "NetflowParser.h"
#include "UtilityFunctions.h"

// This keeps the application running.
bool appRunning = false;

// Global variables for application-wide access.
NetflowResultContainer* GlobalResultContainer = NULL;
NetflowLogger* GlobalNetflowLogger = NULL;
NetflowParser* GlobalNetflowParser = NULL;
NetflowCollector* GlobalNetflowCollector = NULL;

// Collector information structure.
EvoNetflowCollector GlobalCollector;

// Gets a string representation of the elapsed time since the application started.
String GetElapsedTimeStatistics(const unsigned int elapsed)
{
	unsigned short days = 0;
	unsigned short hours = 0;
	unsigned short minutes = 0;
	unsigned short seconds = 0;
	unsigned int leftover = elapsed;

	// Loop the elapsed time until there is nothing left.
	while (leftover > 0)
	{
		if (leftover > 86400)
		{
			++days;
			leftover -= 86400;
		}
		else if (leftover > 3600)
		{
			++hours;
			leftover -= 3600;
		}
		else if (leftover > 60)
		{
			++minutes;
			leftover -= 60;
		}
		else
		{
			seconds = leftover;
			break;
		}
	}

	// Construct a string to represent the elapsed time.
	StringBuffer output;
	output << days << " days, " << hours << " hours, " << minutes << " minutes, " << seconds << " seconds";
	return output;
}

// Format the number of received bytes into MB, GB or TB.
const String FormatReceivedBytes(const int64 bytes)
{
	StringBuffer buf;

	// Calculate and format the total number of bytes received; more than a GB?
	if (bytes >= 1073741824)
	{
		// Even more than a TB?
		if (bytes >= 1099511627776)
		{
			buf << "(" << DblStr((float)GlobalCollector.TotalBytes / 1024.0f / 1024.0f / 1024.0f / 1024.0f) << " TB).";
		}
		else
		{
			// Format in GB.
			buf << "(" << DblStr((float)GlobalCollector.TotalBytes / 1024.0f / 1024.0f / 1024.0f) << " GB).";
		}
	}
	else
	{
		// Just format as MB.
		buf << "(" << DblStr((float)GlobalCollector.TotalBytes / 1024.0f / 1024.0f) << " MB).";
	}

	return buf;
}

// Finalize the collector, by reporting to the user and cleaning up used resources.
void FinalizeProgram()
{
	// Record time of application shutdown and calculate average packet processing count.
	Time endtime = GetSysTime();
	const unsigned int elapsed = (unsigned int)(endtime - GlobalCollector.StartTime);
	
	// Output application statistics.
	Cout() << "\nNetflow collector statistics:\n\n"
		<< GlobalCollector.TotalFlows << " flows were collected, totalling " << GlobalCollector.TotalBytes << " bytes " << FormatReceivedBytes(GlobalCollector.TotalBytes)
		<< "\nCollected for " << GetElapsedTimeStatistics(elapsed) << " , collecting an average of " << GlobalCollector.TotalFlows / elapsed << " flows/second.\n"
		<< GlobalNetflowParser->GetFailedTasks() << " packets failed to process, and " << GlobalResultContainer->GetDroppedFlowCount() << " flows were dropped.\n"
		<< "Shutting down collector.\n";
	
	// Stop the listener and wait for all queued packets to be processed.
	GlobalNetflowCollector->StopListening();

	// Stop the parser and wait for the processing loop to terminate. If we make the parser a singleton class too,
	// it will cause crashes on program finalization.
	GlobalNetflowParser->StopParser();
	delete GlobalNetflowParser;
	
	// Flush and stop the logger.
	if (GlobalNetflowLogger)
	{
		delete GlobalNetflowLogger;
		GlobalNetflowLogger = NULL;
	}
}

// ---------------------------------------------------------------------------------------------

// Writes Netflow v1 debug output for a specified flow.
void DebugOutputNetflow1(const Netflow1Storage* const flow)
{
	// Output flow to the console.
	Cout() << TimeFromUTC(flow->TimeStamp) << " FLOW v1 #" << flow->FlowSequence << ": " << Ipv4ToString(flow->FlowStorage.SourceIpAddress)
		<< ":" << flow->FlowStorage.SourcePort << " <> " << Ipv4ToString(flow->FlowStorage.DestinationIpAddress) << ":" << flow->FlowStorage.DestinationPort
		<< " Protocol: " << NetflowParser::GetProtocolStringFromNumber(flow->FlowStorage.Protocol) << " Bytes: " << flow->FlowStorage.BytesCount
		<< " Packets: " << flow->FlowStorage.PacketCount << "\n";
}

// Writes Netflow v5 debug output for a specified flow.
void DebugOutputNetflow5(const Netflow5Storage* const flow)
{
	// Output flow to the console.
	Cout() << TimeFromUTC(flow->TimeStamp) << " FLOW v5 #" << flow->FlowSequence << ": " << Ipv4ToString(flow->FlowStorage.SourceIpAddress)
		<< ":" << flow->FlowStorage.SourcePort << " <> " << Ipv4ToString(flow->FlowStorage.DestinationIpAddress) << ":" << flow->FlowStorage.DestinationPort
		<< " Protocol: " << NetflowParser::GetProtocolStringFromNumber(flow->FlowStorage.Protocol) << " Bytes: " << flow->FlowStorage.BytesCount
		<< " Packets: " << flow->FlowStorage.PacketCount << "\n";
}

// Writes Netflow v9 debug output for a specified flow.
void DebugOutputNetflow9(const Netflow9Storage* const flow)
{
	
}

// Writes IPFIX debug output for a specified flow.
void DebugOutputIPFIX()
{
	
}

// ---------------------------------------------------------------------------------------------

// Called when the program receives a SIGINT signal.
void SignalHandler(int signal)
{
	// SIGINT (Ctrl+C) received
	Cout() << "CTRL+C received, shutting down...\n";
	appRunning = false;
}

// Gets version information for the application.
void GetEvoNetflowCollectorVersion(int* const pMajor, int* const pMinor)
{
	*pMajor = 1;
	*pMinor = 0;
}

// ---------------------------------------------------------------------------------------------

// Application entry point.
CONSOLE_APP_MAIN
{
	// Output a little version information.
	int major;
	int minor;
	GetEvoNetflowCollectorVersion(&major, &minor);
	Cout() << "Evo Netflow Collector - version " << major << "." << minor << ", by evolution536.\n\n";
	
	// Retrieve command line options.
	CommandLineArgumentParser cmdParser(CommandLine());
	
	// Display help and exit the program. If the port is 0, meaning no port was entered, display the help as well.
	if (cmdParser.GetWasHelpRequested() || !cmdParser.GetPortArgument() || (!cmdParser.GetWasDebuggingMode()
		&& (cmdParser.GetLoggingMethod() == LOGGING_METHOD_UNDEFINED || cmdParser.GetLogFileArgument().IsEmpty())))
	{
		Cout() << CommandLineArgumentParser::GetHelpOutput();
		return;
	}
	
	// If any logging method was specified, initialize it.
	if (cmdParser.GetLoggingMethod() == LOGGING_METHOD_FILE)
	{
		// Initialize file logger.
		GlobalNetflowLogger = new NetflowFileLogger(cmdParser.GetLogFileArgument());
	}
	
	// Check if the logger was succesfully initialized.
	if (GlobalNetflowLogger && !GlobalNetflowLogger->IsReady())
	{
		Cout() << "Failed to initialize the specified logger!\n";
	}
	
	// Set interrupt handler to catch Ctrl+C. We need to clean up stuff first if the user signals the program.
	signal(SIGINT, SignalHandler);
	
	// Get the current time as start time.
	GlobalCollector.StartTime = GetSysTime();

	// Initialize the collector.
	GlobalNetflowCollector = NetflowCollector::GetInstance();

	// Try to bind the socket and start listening for packets.
	const unsigned short portArg = cmdParser.GetPortArgument();
	if (!GlobalNetflowCollector->BeginListen(portArg))
	{
		Cout() << "Failed to bind a socket to port " << portArg << "!\n";
		
		// If a logger was activated, destruct it.
		if (GlobalNetflowLogger)
		{
			delete GlobalNetflowLogger;
		}
		
		return;
	}
	
	// Initialize the result container.
	GlobalResultContainer = NetflowResultContainer::GetInstance();
	
	// Initialize the Netflow parser, and start the processing loop.
	GlobalNetflowParser = new NetflowParser();
	GlobalNetflowParser->StartParser();

	// Report that we have started collecting.
	Cout() << "Listening for input on port " << portArg << "...\n";
	
	// Set the application to started state.
	appRunning = true;
	
	// Keep a loop running to process asynchronous event callbacks.
	while (appRunning)
	{
		// Poll the back buffers for processed Netflow v5 flows.
		if (GlobalResultContainer->GetNetflow5BackBufferSize() > 0)
		{
			// There are flows in the back buffer. Retrieve them and submit them to output.
			Vector<Netflow5Storage> localFlows;
			const unsigned int flowCount = GlobalResultContainer->GetNetflow5BackBuffer(localFlows);
			
			// Output flows to the logger.
			for (unsigned int i = 0; i < flowCount; ++i)
			{
				// If debug mode was activated, write output to the console.
				if (cmdParser.GetWasDebuggingMode())
				{
					DebugOutputNetflow5(&localFlows[i]);
				}
				
				// If a logger was instantiated, push Netflow to the logger.
				if (GlobalNetflowLogger)
				{
					GlobalNetflowLogger->WriteNetflow5Record(&localFlows[i]);
				}
				
				// Increment the bytes counter.
				GlobalCollector.TotalBytes += localFlows[i].FlowStorage.BytesCount;
			}
			
			// Increment the processed flow counter.
			GlobalCollector.TotalFlows += flowCount;
		}
		
		// Give the CPU a break.
		Thread::Sleep(1);
	}

	// Clean up used resources.
	FinalizeProgram();
}