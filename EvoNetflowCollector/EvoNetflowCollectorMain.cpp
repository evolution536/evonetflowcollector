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

#ifndef _WIN32
	#include <string.h>
	#include <stdio.h>
#endif

#include <string>
#include <sstream>
#include <iostream>
#include <signal.h>
#include "EvoNetflowCollector.h"
#include "EvoProcessingDispatcher.h"
#include "NetflowLogger.h"
#include "EvoNetflow9TemplateCache.h"

extern EvoProcessingDispatcher eventDispatcher;
NetflowLogger* netflowLoggerInstance = NULL;
extern EvoNetflow9TemplateCache* v9TemplateCacheInstance;

#define EVO_NETFLOW_COLLECTOR_VERSION 1.0

unsigned int totalFlows = 0;
unsigned long long totalBytes = 0;
bool helpArg = false;
unsigned short portArg = 0;
std::string loggingMethod;
std::string logFileArg;

std::deque<std::string> mProcessedEventsQueue;

// Holds string representations for numeric protocol type identifiers.
const char* const ProtocolStringArray[] =
{
	"HOPOPT",
	"ICMP",
	"IGMP",
	"GGP",
	"IPv4",
	"ST",
	"TCP",
	"CBT",
	"EGP",
	"IGP",
	"BBN-RCC-MON",
	"NVP-II",
	"PUP",
	"ARGUS",
	"EMCON",
	"XNET",
	"CHAOS",
	"UDP",
	"MUX",
	"DCN-MEAS",
	"HMP",
	"PRM",
	"XNS-IDP",
	"TRUNK-1",
	"TRUNK-2",
	"LEAF-1",
	"LEAF-2",
	"RDP",
	"IRTP",
	"ISO-TP4",
	"NETBLT",
	"MFE-NSP",
	"MERIT-INP",
	"DCCP",
	"3PC",
	"IDPR",
	"XTP",
	"DDP",
	"IDPR-CMTP",
	"TP++",
	"IL",
	"IPv6",
	"SDRP",
	"IPv6-Route",
	"IPv6-Frag",
	"IDRP",
	"RSVP",
	"GRE",
	"DSR",
	"BNA",
	"ESP",
	"AH",
	"I-NLSP",
	"SWIPE",
	"NARP",
	"MOBILE",
	"TLSP",
	"SKIP",
	"IPv6-ICMP",
	"IPv6-NoNxt",
	"IPv6-Opts",
	"CFTP",
	"Local Network",
	"SAT-EXPAK",
	"KRYPTOLAN",
	"RVD",
	"IPPC",
	"Distributed Filesystem",
	"SAT-MON",
	"VISA",
	"IPCV",
	"CPNX",
	"CPHB",
	"WSN",
	"PVP",
	"BR-SAT-MON",
	"SUN-ND",
	"WB-MON",
	"WB-EXPAK",
	"ISO-IP",
	"VMTP",
	"SECURE-VMTP",
	"VINES",
	"TTP",
	"IPTM",
	"NSFNET-IGP",
	"DGP",
	"TCF",
	"EIGRP",
	"OSPFIGP",
	"Sprite-RPC",
	"LARP",
	"MTP",
	"AX.25",
	"IPIP",
	"MICP",
	"SCC-SP",
	"ETHERIP",
	"ENCAP",
	"Private Encryption Scheme",
	"GMTP",
	"IFMP",
	"PNNI",
	"PIM",
	"ARIS",
	"SCPS",
	"QNX",
	"A/N",
	"IPComp",
	"SNP",
	"Compaq-Peer",
	"IPX-in-IP",
	"VRRP",
	"PGM",
	"0-Hop Procol",
	"L2TP",
	"DDX",
	"IATP",
	"STP",
	"SRP",
	"UTI",
	"SMP",
	"SM",
	"PTP",
	"ISIS over IPv4",
	"FIRE",
	"CRTP",
	"CRUDP",
	"SSCOPMCE",
	"IPLT",
	"SPS",
	"PIPE",
	"SCTP",
	"FC",
	"RSVP-E2E-IGNORE",
	"Mobility Header",
	"UDPLite",
	"MPLS-in-IP",
	"MANET",
	"HIP",
	"Shim6",
	"WESP",
	"ROHC"
};

// ----------------------------------------------------------------------------------------

// Converts a long IPv4 address to its string representation.
std::string Ipv4ToString(const IPV4ADDRESS ipv4)
{
	unsigned char bytes[4];
	bytes[3] = ipv4 & 0xFF;
	bytes[2] = (ipv4 >> 8) & 0xFF;
	bytes[1] = (ipv4 >> 16) & 0xFF;
	bytes[0] = (ipv4 >> 24) & 0xFF;
	std::stringstream outstream;
	outstream << (int)bytes[0] << "." << (int)bytes[1] << "." << (int)bytes[2] << "." << (int)bytes[3];
	return outstream.str();
}

// Finalizes the program before shutting it down.
void FinalizeProgram()
{
	std::stringstream unitOutput;
	if (totalBytes > 1073741824)
	{
		// Display in gigabytes.
		unitOutput << "(" << std::to_string((float)totalBytes / 1024.0f / 1024.0f / 1024.0f) << " GB).";
	}
	else
	{
		// Display in megabytes.
		unitOutput << "(" << std::to_string((float)totalBytes / 1024.0f / 1024.0f) << " MB).";
	}
	std::cout << totalFlows << " flows were collected, totalling " << totalBytes << " bytes " << unitOutput.str() << std::endl;
	std::cout << "Shutting down collector." << std::endl;

	delete netflowLoggerInstance;
	eventDispatcher.StopDispatcher();
}

// Called when the program is signaled with Ctrl+C (SIGINT)
void SignalHandler(int signal)
{
	// Since the program was signaled, clean it up and exit it with failure status.
	FinalizeProgram();
	exit(signal);
}

void FlowReceivedCallback(const unsigned int SequenceCounter, PNETFLOW5_FLOW_RECORD const record)
{
	// Create output string for the processed packet.
	std::stringstream next;
	next << "FLOW " << SequenceCounter << ": " << Ipv4ToString(record->SourceIpAddress) << ":" << record->SourcePort << " <> "
		<< Ipv4ToString(record->DestinationIpAddress) << ":" << record->DestinationPort << " Bytes: " << record->BytesCount
		<< " Packets: " << record->PacketCount << " Protocol: "	<< ProtocolStringArray[record->Protocol];

	// Push the event to the queue for processing in UI thread.
	totalBytes += record->BytesCount;
	mProcessedEventsQueue.push_back(next.str());
}

int main(int argc, char* argv[])
{
	// Parse the command line arguments.
	std::cout << "Evo Netflow Collector " << EVO_NETFLOW_COLLECTOR_VERSION << " by evolution536" << std::endl;
	for (int i = 1; i < argc; ++i)
	{
		// Check whether the user wants the help menu displayed.
		if (strcmp(argv[i], "?") == 0 || strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
		{
			helpArg = true;
		}

		// Check for a port argument.
		if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0)
		{
			if (i + 1 < argc)
			{
				portArg = (unsigned short)strtol(argv[i + 1], NULL, 10);
			}
		}

		// Check whether the user selected a logging method.
		if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--logging") == 0)
		{
			if (i + 1 < argc)
			{
				loggingMethod = argv[i + 1];
			}
		}

		// Check for an output file argument.
		if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--outfile") == 0)
		{
			if (i + 1 < argc)
			{
				logFileArg = argv[i + 1];
			}
		}
	}

	// Display help and exit the program. If the port is 0, meaning no port was entered, display the help as well.
	const bool isFile = loggingMethod.compare("file") == 0;
	if (helpArg || !portArg || (isFile && logFileArg.empty()))
	{
		std::cout << "Example: EvoNetflowCollector -p 9995" << std::endl;
		std::cout << std::endl << "Usage:" << std::endl << std::endl;
		std::cout << "?, -h, --help\t\t\tDisplays this help information." << std::endl;
		std::cout << "-p, --port <port>\t\tSets the UDP port to listen on. Must be greater than 0." << std::endl;
		std::cout << "-l, --logging <method>\t\tSets the method of Netflow logging. Example: file" << std::endl;
		std::cout << "-o, --outfile <file>\t\tSets the output file that Netflow will be written to." << std::endl;
		return 0;
	}

	// Start up the logging method. If no logging method was found, output is dumped only to standard output.
	if (isFile)
	{
		netflowLoggerInstance = new NetflowFileLogger(logFileArg.c_str());
		if (!netflowLoggerInstance->IsReady())
		{
			delete netflowLoggerInstance;
			std::cout << "The logfile could not be written to, exiting!" << std::endl;
			return 1;
		}
	}

	// Set interrupt handler to catch Ctrl+C. We need to clean up stuff first if the user signals the program.
	signal(SIGINT, SignalHandler);

	// Create UDP socket and start listening for Netflow input. The input is processed by the backend automatically.
	EvoNetflowCollector main;
	if (!main.Bind(portArg))
	{
		std::cout << "Failed to bind a socket to port " << portArg << " for Netflow packet listening!" << std::endl;
	}

	// Initialize the template cache class for Netflow v9 input.
	v9TemplateCacheInstance = EvoNetflow9TemplateCache::GetInstance();

	// Start the dispatcher as well to asynchronously process Netflow input.
	std::cout << "Listening for Netflow input on port " << portArg << "..." << std::endl;
	eventDispatcher.FlowReceived5 = FlowReceivedCallback;
	eventDispatcher.StartDispatcher();
	main.BeginListen();

	// Keep a loop running to process asynchronous event callbacks.
	while (1)
	{
		while (mProcessedEventsQueue.size() > 0)
		{
			// Process the next event in the queue.
			const std::string& str = mProcessedEventsQueue.front();
			std::cout << str << std::endl;

			// Write the row of netflow to the logger.
			if (netflowLoggerInstance)
			{
				netflowLoggerInstance->WriteNetflow(str);
			}
			
			mProcessedEventsQueue.pop_front();

			// Increment the amount of flows that are collected.
			++totalFlows;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}

	// Clean up resources and let the user know about the statistics.
	FinalizeProgram();

	return 0;
}
