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
#include <ctime>
#include "EvoNetflowCollector.h"
#include "EvoProcessingDispatcher.h"
#include "NetflowLogger.h"
#include "EvoNetflow9TemplateCache.h"
#include "UtilityFunctions.h"

#ifndef _WIN32
	#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif

extern EvoProcessingDispatcher eventDispatcher;
NetflowLogger* netflowLoggerInstance = NULL;
extern EvoNetflow9TemplateCache* v9TemplateCacheInstance;

bool debuggingMode = false;
unsigned int totalFlows = 0;
unsigned long long totalBytes = 0;
std::time_t startTime;
bool helpArg = false;
unsigned short portArg = 0;
std::string loggingMethod;
std::string logFileArg;

std::deque<std::string> mProcessedEventsQueue;
volatile bool mIsReading = false;
volatile bool mIsWriting = false;

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

// ----------------------------------------------------------------------------------------------------

// Custom itoa function, solely for converting IP-address numbers. Copy-pasted from StackOverflow.
const int itoa_custom(const int value, char* sp, const int radix)
{
	char tmp[16];// be careful with the length of the buffer
	char *tp = tmp;
	int i;
	unsigned v;

	int sign = (radix == 10 && value < 0);
	if (sign)
		v = -value;
	else
		v = (unsigned)value;

	while (v || tp == tmp)
	{
		i = v % radix;
		v /= radix; // v/=radix uses less CPU clocks than v=v/radix does
		if (i < 10)
			*tp++ = i + '0';
		else
			*tp++ = i + 'a' - 10;
	}

	int len = tp - tmp;

	if (sign)
	{
		*sp++ = '-';
		len++;
	}

	while (tp > tmp)
		*sp++ = *--tp;

	return len;
}

// Converts a long IPv4 address to its string representation.
std::string Ipv4ToString(const IPV4ADDRESS ipv4)
{
	char ipbuffer[16];
	int strlength = itoa_custom((ipv4 >> 24) & 0xFF, ipbuffer, 10);
	ipbuffer[strlength++] = 0x2E;
	strlength += itoa_custom((ipv4 >> 16) & 0xFF, ipbuffer + strlength, 10);
	ipbuffer[strlength++] = 0x2E;
	strlength += itoa_custom((ipv4 >> 8) & 0xFF, ipbuffer + strlength, 10);
	ipbuffer[strlength++] = 0x2E;
	strlength += itoa_custom(ipv4 & 0xFF, ipbuffer + strlength, 10);
	ipbuffer[strlength] = 0;
	return std::string(ipbuffer);
}

std::string MacAddressToString(const unsigned char addr[6])
{
	std::stringstream stream;
	stream << addr[0] << ":" << addr[1] << ":" << addr[2] << ":" << addr[3] << ":" << addr[4] << ":" << addr[5];
	return stream.str();
}

const bool ProcessNetflow9FieldValue(const unsigned int fieldType, const unsigned int fieldLength, const char* fieldVal, std::stringstream& outVal)
{
	switch (fieldType)
	{
		case IN_BYTES:
		case IN_PKTS:
		case FLOWS:
		case LAST_SWITCHED:
		case FIRST_SWITCHED:
		case SAMPLING_INTERVAL:
		case MPLS_TOP_LABEL_IP_ADDR:
		case FLOW_SAMPLER_RANDOM_INTERVAL:
		case IPV6_OPTION_HEADERS:
		case MUL_DST_PKTS:
		case MUL_DST_BYTES:
		case OUT_BYTES:
		case OUT_PKTS:
		case TOTAL_BYTES_EXP:
		case TOTAL_PKTS_EXP:
		case TOTAL_FLOWS_EXP:
		case IN_PERMANENT_BYTES:
		case IN_PERMANENT_PKTS:
		case SRC_TRAFFIC_INDEX:
		case DST_TRAFFIC_INDEX:
		case replication_factor:
#ifdef _WIN32
			outVal << SwapBytes((unsigned long*)fieldVal);
#else
			outVal << *(unsigned long*)fieldVal;
#endif
			return true;
		case IP_PROTOCOL_VERSION:
			outVal << (((int)*fieldVal == 6) ? "IPv6" : "IPv4");
			return true;
		case PROTOCOL:
			if ((int)*fieldVal > 0 && (int)*fieldVal < (int)_countof(ProtocolStringArray))
			{
				outVal << ProtocolStringArray[(int)*fieldVal];
				return true;
			}
			return false;
		case SAMPLING_ALGORITHM:
			outVal << (((int)*fieldVal == 0x1) ? "Deterministic" : "Random");
			return true;
		case ENGINE_TYPE:
			outVal << (((int)*fieldVal == 0x1) ? "VIP/Linecard" : "RP");
			return true;
		case DIRECTION:
			outVal << (((int)*fieldVal == 0x1) ? "egress" : "ingress");
			return true;
		case MUL_IGMP_TYPE:
		case SRC_TOS:
		case TCP_FLAGS:
		case SRC_MASK:
		case DST_MASK:
		case IPV6_SRC_MASK:
		case IPV6_DST_MASK:
		case ENGINE_ID:
		case MPLS_TOP_LABEL_TYPE:
		case FLOW_SAMPLER_ID:
		case FLOW_SAMPLER_MODE:
		case MIN_TTL:
		case MAX_TTL:
		case DST_TOS:
		case FORWARDING_STATUS:
		case MPLS_PREFIX_LEN:
		case postipDiffServCodePoint:
			outVal << (int)*fieldVal;
			return true;
		case L4_SRC_PORT:
		case L4_DST_PORT:
		case MIN_PKT_LENGTH:
		case MAX_PKT_LENGTH:
		case ICMP_TYPE:
		case FLOW_ACTIVE_TIMEOUT:
		case FLOW_INACTIVE_TIMEOUT:
		case IPV4_IDENT:
		case SRC_VLAN:
		case DST_VLAN:
		case SRC_AS:
		case DST_AS:
		case FRAGMENT_OFFSET:
#ifdef _WIN32
			outVal << SwapBytes((unsigned short*)fieldVal);
#else
			outVal << *(unsigned short*)fieldVal;
#endif
			return true;
		case INPUT_SNMP:
		case OUTPUT_SNMP:
#ifdef _WIN32
			outVal << ((fieldLength == sizeof(int)) ? SwapBytes((unsigned long*)fieldVal) : SwapBytes((unsigned short*)fieldVal));
#else
			outVal << ((fieldLength == sizeof(int)) ? *(unsigned long*)fieldVal : *(unsigned short*)fieldVal);
#endif
			return true;
		case IPV4_SRC_ADDR:
		case IPV4_DST_ADDR:
		case IPV4_NEXT_HOP:
		case BGP_IPV4_NEXT_HOP:
		case IPV4_SRC_PREFIX:
		case IPV4_DST_PREFIX:
#ifdef _WIN32
			outVal << Ipv4ToString(SwapBytes((IPV4ADDRESS*)fieldVal));
#else
			outVal << Ipv4ToString(*(IPV4ADDRESS*)fieldVal);
#endif
			return true;
		case IPV6_SRC_ADDR:
		case IPV6_DST_ADDR:
		case IPV6_FLOW_LABEL: // 3 bytes long!
		case IPV6_NEXT_HOP:
		case BPG_IPV6_NEXT_HOP:
			return false; // do eet
		case IN_SRC_MAC:
		case OUT_DST_MAC:
		case IN_DST_MAC:
		case OUT_SRC_MAC:
			outVal << MacAddressToString((unsigned char*)fieldVal);
			return true;
		case IF_NAME:
		case IF_DESC:
		case SAMPLER_NAME:
		case APPLICATION_DESCRIPTION:
		case APPLICATION_NAME:
			outVal << std::string(fieldVal, fieldLength);
			return true;
		case VENDOR_PROPRIETARY_1:
		case VENDOR_PROPRIETARY_2:
		case VENDOR_PROPRIETARY_3:
		case VENDOR_PROPRIETARY_4:
		case VENDOR_PROPRIETARY_5:
		case VENDOR_PROPRIETARY_6:
		case VENDOR_PROPRIETARY_7:
		case VENDOR_PROPRIETARY_8:
		case MPLS_LABEL_1:
		case MPLS_LABEL_2:
		case MPLS_LABEL_3:
		case MPLS_LABEL_4:
		case MPLS_LABEL_5:
		case MPLS_LABEL_6:
		case MPLS_LABEL_7:
		case MPLS_LABEL_8:
		case MPLS_LABEL_9:
		case MPLS_LABEL_10:
		case MPLS_PAL_RD:
		case APPLICATION_TAG:
		case DEPRECATED:
		case layer2packetSectionOffset:
		case layer2packetSectionSize:
		case layer2packetSectionData:
		default:
			return false;
	}
}

// Gets a string representation of the elapsed time since the application started.
std::string GetElapsedTimeStatistics(const unsigned int elapsed)
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
	std::stringstream output;
	output << days << " days, " << hours << " hours, " << minutes << " minutes, " << seconds << " seconds";
	return output.str();
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

	// Record time of application shutdown and calculate average packet processing count.
	std::time_t endtime = std::time(NULL);
	const unsigned int elapsed = (unsigned int)(endtime - startTime);

	// Output application statistics.
	std::cout << std::endl << "Netflow collector statistics:" << std::endl << std::endl;
	std::cout << totalFlows << " flows were collected, totalling " << totalBytes << " bytes " << unitOutput.str() << std::endl;
	std::cout << "Collected for " << GetElapsedTimeStatistics(elapsed) << " , collecting an average of " << totalFlows / elapsed << " flows/second." << std::endl;
	std::cout << "Shutting down collector." << std::endl;

	// Clean up used resources.
	if (netflowLoggerInstance)
	{
		delete netflowLoggerInstance;
		netflowLoggerInstance = NULL;
	}

	eventDispatcher.StopDispatcher();
}

// Called when the program is signaled with Ctrl+C (SIGINT)
void SignalHandler(int signal)
{
	// Since the program was signaled, clean it up and exit it with failure status.
	FinalizeProgram();
	exit(signal);
}

void FlowReceivedCallback5(const unsigned int SequenceCounter, PNETFLOW5_FLOW_RECORD const record)
{
	// Create output string for the processed packet.
	char buffer[512];
	int strLength = 5;
	memcpy(buffer, "FLOW ", 5);
	strLength += itoa_custom(SequenceCounter, buffer + strLength, 10);
	*(unsigned short*)(buffer + strLength) = 0x203A;
	strLength += sizeof(unsigned short);
	std::string nextIpRet = Ipv4ToString(record->SourceIpAddress);
	memcpy(buffer + strLength, nextIpRet.c_str(), nextIpRet.length());
	strLength += nextIpRet.length();
	buffer[strLength++] = 0x3A;
	strLength += itoa_custom(record->SourcePort, buffer + strLength, 10);
	*(unsigned long*)(buffer + strLength) = 0x203E3C20;
	strLength += sizeof(unsigned long);
	nextIpRet = Ipv4ToString(record->DestinationIpAddress);
	memcpy(buffer + strLength, nextIpRet.c_str(), nextIpRet.length());
	strLength += nextIpRet.length();
	buffer[strLength++] = 0x3A;
	strLength += itoa_custom(record->DestinationPort, buffer + strLength, 10);
	memcpy(buffer + strLength, " Bytes: ", 8);
	strLength += 8;
	strLength += itoa_custom(record->BytesCount, buffer + strLength, 10);
	memcpy(buffer + strLength, " Packets: ", 10);
	strLength += 10;
	strLength += itoa_custom(record->PacketCount, buffer + strLength, 10);
	memcpy(buffer + strLength, " Protocol: ", 11);
	strLength += 11;
	const char* protocolStr = ProtocolStringArray[record->Protocol];
	memcpy(buffer + strLength, protocolStr, strlen(protocolStr));
	strLength += 3;
	buffer[strLength] = 0;

	// Push the event to the queue for processing in UI thread.
	totalBytes += record->BytesCount;

	// Add the Netflow line to the queue for log processing.
	while (mIsReading)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	mIsWriting = true;
	mProcessedEventsQueue.push_back(std::string(buffer));
	mIsWriting = false;
}

const char* GetNetflow9FieldResult(const std::vector<EvoNetflow9FieldValueSet>& outRecords, const unsigned short fieldnum)
{
	for (auto& fieldset : outRecords)
	{
		if (fieldset.Field == fieldnum)
		{
			return fieldset.Value.c_str();
		}
	}

	return "";
}

void FlowReceivedCallback9(const unsigned int SequenceCounter, const std::vector<EvoNetflow9FieldValueSet>& outRecords)
{
	std::string next;
	next.reserve(512);
	next = "FLOW " + std::to_string(SequenceCounter) + ": " + GetNetflow9FieldResult(outRecords, IPV4_SRC_ADDR) + ":" + GetNetflow9FieldResult(outRecords, L4_SRC_PORT)
		+ " <> " + GetNetflow9FieldResult(outRecords, IPV4_DST_ADDR) + ":" + GetNetflow9FieldResult(outRecords, L4_DST_PORT) + " Bytes: " + GetNetflow9FieldResult(outRecords, IN_BYTES)
		+ " Packets: " + GetNetflow9FieldResult(outRecords, IN_PKTS) + " Protocol: " + GetNetflow9FieldResult(outRecords, PROTOCOL);

	// Push the event to the queue for processing in UI thread.
	std::istringstream converter(GetNetflow9FieldResult(outRecords, IN_BYTES));
	unsigned long tempValue;
	converter >> tempValue;
	totalBytes += tempValue;

	// Add the Netflow line to the queue for log processing.
	while (mIsReading)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	mIsWriting = true;
	mProcessedEventsQueue.push_back(next);
	mIsWriting = false;
}

int main(int argc, char* argv[])
{
	// Parse the command line arguments.
	std::cout << "Evo Netflow Collector by evolution536" << std::endl;
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

		// Check for the debug mode option.
		if (strcmp(argv[i], "-D") == 0)
		{
			debuggingMode = true;
		}
	}

	// Display help and exit the program. If the port is 0, meaning no port was entered, display the help as well.
	if (helpArg || !portArg || (!debuggingMode && loggingMethod.empty()))
	{
		std::cout << "Example: EvoNetflowCollector -p 9995" << std::endl;
		std::cout << std::endl << "Usage:" << std::endl << std::endl;
		std::cout << "?, -h, --help\t\t\tDisplays this help information." << std::endl;
		std::cout << "-p, --port <port>\t\tSets the UDP port to listen on. Must be greater than 0." << std::endl;
		std::cout << "-l, --logging <method>\t\tSets the method of Netflow logging. Example: file" << std::endl;
		std::cout << "-o, --outfile <file>\t\tSets the output file that Netflow will be written to." << std::endl;
		std::cout << "-D\t\t\t\tOutputs flows to stdout (Debugging purposes)." << std::endl;
		return 0;
	}

	// Start up the logging method. If no logging method was found, output is dumped only to standard output.
	if (loggingMethod.compare("file") == 0)
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

	// Initialize the template cache class for Netflow v9 input.
	v9TemplateCacheInstance = EvoNetflow9TemplateCache::GetInstance();

	// Record the time of application startup.
	startTime = std::time(NULL);

	// Create UDP socket and start listening for Netflow input. The input is processed by the backend automatically.
	EvoNetflowCollector main;
	if (!main.BeginListen(portArg))
	{
		std::cout << "Failed to bind a socket to port " << portArg << " for Netflow packet listening!" << std::endl;
		if (netflowLoggerInstance)
		{
			delete netflowLoggerInstance;
		}

		return 1;
	}

	// Start the dispatcher as well to asynchronously process Netflow input.
	eventDispatcher.FlowReceived5 = FlowReceivedCallback5;
	eventDispatcher.FlowReceived9 = FlowReceivedCallback9;
	eventDispatcher.StartDispatcher();
	std::cout << "Listening for Netflow input on port " << portArg << "..." << std::endl;

	// Keep a loop running to process asynchronous event callbacks.
	while (1)
	{
		while (mIsWriting)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		mIsReading = true;

		while (mProcessedEventsQueue.size() > 0)
		{
			// Increment the amount of flows that are collected.
			++totalFlows;

			// Process the next event in the queue.
			const std::string& str = mProcessedEventsQueue.front();

			// If the debug mode argument was specified, write flows to stdout. Has a huge impact on the performance.
			if (debuggingMode)
			{
				std::cout << str << std::endl;
			}

			// Write the row of netflow to the logger.
			if (netflowLoggerInstance)
			{
				netflowLoggerInstance->WriteNetflow(str);
			}

			mProcessedEventsQueue.pop_front();
		}

		mIsReading = false;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// Clean up resources and let the user know about the statistics.
	FinalizeProgram();

	return 0;
}
