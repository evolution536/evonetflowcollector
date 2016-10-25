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

#include "NetflowParser.h"
#include "UtilityFunctions.h"
#include "GlobalDefinitions.h"

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

// ---------------------------------------------------------------------------------------------

// NetflowParser default constructor.
NetflowParser::NetflowParser()
{
	this->mRunning = false;
	this->mFailedTasks = 0;
}

// NetflowParser default destructor.
NetflowParser::~NetflowParser()
{

}

// ---------------------------------------------------------------------------------------------

// Retrieves the string representation of a protocol by its number.
const char* const NetflowParser::GetProtocolStringFromNumber(const unsigned int number)
{
	// If the number is out of the array bounds, return NULL.
	return number < sizeof(ProtocolStringArray) ? ProtocolStringArray[number] : NULL;
}

// ---------------------------------------------------------------------------------------------

// Processes a task from the processing loop.
void NetflowParser::ProcessTask(const ProcessingTask& task)
{
	// Parse Netflow v1.
	if (task.Version == 1)
	{
		this->mThreadPool & THISBACK2(ParseNetflow1Packet, task.PacketBuffer, task.PacketLength);
	}
	// Parse Netflow v5.
	else if (task.Version == 5)
	{
		this->mThreadPool & THISBACK2(ParseNetflow5Packet, task.PacketBuffer, task.PacketLength);
	}
	// Parse Netflow v7.
	else if (task.Version == 7)
	{
		this->mThreadPool & THISBACK2(ParseNetflow7Packet, task.PacketBuffer, task.PacketLength);
	}
	// Parse Netflow v9.
	else if (task.Version == 9)
	{
		this->mThreadPool & THISBACK2(ParseNetflow9Packet, task.PacketBuffer, task.PacketLength);
	}
	// Parse IPFIX.
	else if (task.Version == 10)
	{
		this->mThreadPool & THISBACK2(ParseIPFIXPacket, task.PacketBuffer, task.PacketLength);
	}
	// In this case, the task was not recognized and it failed processing.
	else
	{
		++this->mFailedTasks;
	}
}

// The internal processing loop.
void NetflowParser::ProcessingLoop()
{
	while (this->mRunning)
	{
		// Make sure nobody is writing to the queue.
		this->mLock.Enter();
		
		// Check for tasks in the queue.
		while (this->mQueuedTasks.GetCount() > 0)
		{
			this->ProcessTask(this->mQueuedTasks.Head());
			this->mQueuedTasks.DropHead();
		}
		
		// Let go of the lock.
		this->mLock.Leave();
		
		// Give the CPU a break.
		Thread::Sleep(5);
	}
}

// Parses a Netflow v1 packet.
void NetflowParser::ParseNetflow1Packet(const char* packet, const unsigned int length)
{
	// Check whether the packet size and buffer are valid.
	if (packet && (length > 0 && length >= sizeof(NETFLOW1_HEADER)))
	{
		// Output vector for the processed flows.
		Vector<Netflow1Storage> outRecords;
		
		// Retrieve flows from the packet.
		const PNETFLOW1_HEADER nfHeader = (PNETFLOW1_HEADER)packet;
			
#ifdef _WIN32
		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = _byteswap_ushort(nfHeader->FlowCount);
		if (flowCount <= 24)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
			PNETFLOW1_FLOW_RECORD flowRecord = (PNETFLOW1_FLOW_RECORD)(packet + sizeof(NETFLOW1_HEADER));
			
			for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
			{
				Netflow1Storage& newRecord = outRecords.Add();
				newRecord.TimeStamp = _byteswap_ulong(nfHeader->UnixSeconds);
				newRecord.FlowStorage.SourceIpAddress = flowRecord->SourceIpAddress;
				newRecord.FlowStorage.DestinationIpAddress = flowRecord->DestinationIpAddress;
				newRecord.FlowStorage.NextHop = flowRecord->NextHop;
				newRecord.FlowStorage.InputSnmp = _byteswap_ushort(flowRecord->InputSnmp);
				newRecord.FlowStorage.OutputSnmp = _byteswap_ushort(flowRecord->OutputSnmp);
				newRecord.FlowStorage.PacketCount = _byteswap_ulong(flowRecord->PacketCount);
				newRecord.FlowStorage.BytesCount = _byteswap_ulong(flowRecord->BytesCount);
				newRecord.FlowStorage.SysUptimeFirst = _byteswap_ulong(flowRecord->SysUptimeFirst);
				newRecord.FlowStorage.SysUptimeLast = _byteswap_ulong(flowRecord->SysUptimeLast);
				newRecord.FlowStorage.SourcePort = _byteswap_ushort(flowRecord->SourcePort);
				newRecord.FlowStorage.DestinationPort = _byteswap_ushort(flowRecord->DestinationPort);
				newRecord.FlowStorage.TcpFlags = flowRecord->TcpFlags;
				newRecord.FlowStorage.Protocol = flowRecord->Protocol;
				newRecord.FlowStorage.IpTypeOfService = flowRecord->IpTypeOfService;
			}
		}		
#else
		if (nfHeader->FlowCount <= 24)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(nfHeader->FlowCount);
			PNETFLOW1_FLOW_RECORD flowRecord = (PNETFLOW1_FLOW_RECORD)(packet + sizeof(NETFLOW1_HEADER));
			for (int i = 0; i < nfHeader->FlowCount; ++i, ++flowRecord)
			{
				Netflow1Storage& newRecord = outRecords.Add();
				newRecord.FlowStorage = *flowRecord;
			}	
		}
#endif

		// Push the processed flows to the result container.
		GlobalResultContainer->PushNetflow1Flows(outRecords);
	}
}

// Parses a Netflow v5 packet.
void NetflowParser::ParseNetflow5Packet(const char* packet, const unsigned int length)
{
	// Check whether the packet size and buffer are valid.
	if (packet && (length > 0 && length >= sizeof(NETFLOW5_HEADER)))
	{
		// Output vector for the processed flows.
		Vector<Netflow5Storage> outRecords;
		
		// Retrieve flows from the packet.
		const PNETFLOW5_HEADER nfHeader = (PNETFLOW5_HEADER)packet;
		
#ifdef _WIN32
		// Save the sequence number of this packet.
		const unsigned int seqnum = _byteswap_ulong(nfHeader->FlowSequence);
		
		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = _byteswap_ushort(nfHeader->FlowCount);
		if (flowCount <= 30)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
			PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(packet + sizeof(NETFLOW5_HEADER));
			//unsigned int seq = SwapBytes(&nfHeader->FlowSequence);
			
			for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
			{
				Netflow5Storage& newRecord = outRecords.Add();
				newRecord.TimeStamp = _byteswap_ulong(nfHeader->UnixSeconds);
				newRecord.FlowSequence = seqnum + i;
				newRecord.FlowStorage.SourceIpAddress = flowRecord->SourceIpAddress;
				newRecord.FlowStorage.DestinationIpAddress = flowRecord->DestinationIpAddress;
				newRecord.FlowStorage.NextHop = flowRecord->NextHop;
				newRecord.FlowStorage.InputSnmp = _byteswap_ushort(flowRecord->InputSnmp);
				newRecord.FlowStorage.OutputSnmp = _byteswap_ushort(flowRecord->OutputSnmp);
				newRecord.FlowStorage.PacketCount = _byteswap_ulong(flowRecord->PacketCount);
				newRecord.FlowStorage.BytesCount = _byteswap_ulong(flowRecord->BytesCount);
				newRecord.FlowStorage.SysUptimeFirst = _byteswap_ulong(flowRecord->SysUptimeFirst);
				newRecord.FlowStorage.SysUptimeLast = _byteswap_ulong(flowRecord->SysUptimeLast);
				newRecord.FlowStorage.SourcePort = _byteswap_ushort(flowRecord->SourcePort);
				newRecord.FlowStorage.DestinationPort = _byteswap_ushort(flowRecord->DestinationPort);
				newRecord.FlowStorage.TcpFlags = flowRecord->TcpFlags;
				newRecord.FlowStorage.Protocol = flowRecord->Protocol;
				newRecord.FlowStorage.IpTypeOfService = flowRecord->IpTypeOfService;
				newRecord.FlowStorage.SourceAutonomousSystemNumber = _byteswap_ushort(flowRecord->SourceAutonomousSystemNumber);
				newRecord.FlowStorage.DestinationAutonomousSystemNumber = _byteswap_ushort(flowRecord->DestinationAutonomousSystemNumber);
				newRecord.FlowStorage.SourceMask = flowRecord->SourceMask;
				newRecord.FlowStorage.DestinationMask = flowRecord->DestinationMask;
			}
		}		
#else
		if (nfHeader->FlowCount <= 30)
		{
			// Save the sequence number of this packet.
			const unsigned int seqnum = nfHeader->FlowSequence;
			
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(nfHeader->FlowCount);
			PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(packet + sizeof(NETFLOW5_HEADER));
			for (int i = 0; i < nfHeader->FlowCount; ++i, ++flowRecord)
			{
				Netflow5Storage& newRecord = outRecords.Add();
				newRecord.FlowSequence = seqnum + i;
				newRecord.FlowStorage = *flowRecord;
			}	
		}
#endif

		// Push the processed flows to the result container.
		GlobalResultContainer->PushNetflow5Flows(outRecords);
	}
}

// Parses a Netflow v7 packet.
void NetflowParser::ParseNetflow7Packet(const char* packet, const unsigned int length)
{
	// Check whether the packet size and buffer are valid.
	if (packet && (length > 0 && length >= sizeof(NETFLOW7_HEADER)))
	{
		// Output vector for the processed flows.
		Vector<Netflow7Storage> outRecords;
		
		// Retrieve flows from the packet.
		const PNETFLOW7_HEADER nfHeader = (PNETFLOW7_HEADER)packet;
		
#ifdef _WIN32
		// Save the sequence number of this packet.
		const unsigned int seqnum = _byteswap_ulong(nfHeader->FlowSequence);

		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = _byteswap_ushort(nfHeader->FlowCount);
		if (flowCount <= 30)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
			PNETFLOW7_FLOW_RECORD flowRecord = (PNETFLOW7_FLOW_RECORD)(packet + sizeof(NETFLOW7_HEADER));
			//unsigned int seq = SwapBytes(&nfHeader->FlowSequence);
			
			for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
			{
				Netflow7Storage& newRecord = outRecords.Add();
				newRecord.TimeStamp = _byteswap_ulong(nfHeader->UnixSeconds);
				newRecord.FlowSequence = seqnum + i;
				newRecord.FlowStorage.SourceIpAddress = flowRecord->SourceIpAddress;
				newRecord.FlowStorage.DestinationIpAddress = flowRecord->DestinationIpAddress;
				newRecord.FlowStorage.NextHop = flowRecord->NextHop;
				newRecord.FlowStorage.InputSnmp = _byteswap_ushort(flowRecord->InputSnmp);
				newRecord.FlowStorage.OutputSnmp = _byteswap_ushort(flowRecord->OutputSnmp);
				newRecord.FlowStorage.PacketCount = _byteswap_ulong(flowRecord->PacketCount);
				newRecord.FlowStorage.BytesCount = _byteswap_ulong(flowRecord->BytesCount);
				newRecord.FlowStorage.SysUptimeFirst = _byteswap_ulong(flowRecord->SysUptimeFirst);
				newRecord.FlowStorage.SysUptimeLast = _byteswap_ulong(flowRecord->SysUptimeLast);
				newRecord.FlowStorage.SourcePort = _byteswap_ushort(flowRecord->SourcePort);
				newRecord.FlowStorage.DestinationPort = _byteswap_ushort(flowRecord->DestinationPort);
				newRecord.FlowStorage.TcpFlags = flowRecord->TcpFlags;
				newRecord.FlowStorage.Protocol = flowRecord->Protocol;
				newRecord.FlowStorage.IpTypeOfService = flowRecord->IpTypeOfService;
				newRecord.FlowStorage.SourceAutonomousSystemNumber = _byteswap_ushort(flowRecord->SourceAutonomousSystemNumber);
				newRecord.FlowStorage.DestinationAutonomousSystemNumber = _byteswap_ushort(flowRecord->DestinationAutonomousSystemNumber);
				newRecord.FlowStorage.SourceMask = flowRecord->SourceMask;
				newRecord.FlowStorage.DestinationMask = flowRecord->DestinationMask;
				newRecord.FlowStorage.Flags = _byteswap_ushort(flowRecord->Flags);
			}
		}		
#else
		if (nfHeader->FlowCount <= 30)
		{
			// Save the sequence number of this packet.
			const unsigned int seqnum = nfHeader->FlowSequence;
			
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(nfHeader->FlowCount);
			PNETFLOW7_FLOW_RECORD flowRecord = (PNETFLOW7_FLOW_RECORD)(packet + sizeof(NETFLOW7_HEADER));
			for (int i = 0; i < nfHeader->FlowCount; ++i, ++flowRecord)
			{
				Netflow7Storage& newRecord = outRecords.Add();
				newRecord.FlowSequence = seqnum + i;
				newRecord.FlowStorage = *flowRecord;
			}	
		}
#endif

		// Push the processed flows to the result container.
		GlobalResultContainer->PushNetflow7Flows(outRecords);
	}
}

// Parses a Netflow v9 packet.
void NetflowParser::ParseNetflow9Packet(const char* packet, const unsigned int length)
{
	// Check whether the packet size and buffer are valid.
	if (packet && (length > 0 && length >= sizeof(NETFLOW9_HEADER)))
	{
		// Output vector for the processed flows.
		Vector<Netflow9Storage> outRecords;
		
		// Retrieve flows from the packet.
		const PNETFLOW9_HEADER nfHeader = (PNETFLOW9_HEADER)packet;
		
		// Save the sequence number of this packet.
		//const unsigned int seqnum = SwapBytes(&nfHeader->FlowSequence);
		
#ifdef _WIN32
		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = _byteswap_ushort(nfHeader->FlowCount);
		if (flowCount <= 30)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
		}		
#else
		if (nfHeader->FlowCount <= 30)
		{
			// Save the sequence number of this packet.
			//const unsigned int seqnum = nfHeader->FlowSequence;
			
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(nfHeader->FlowCount);	
		}
#endif

		// Push the processed flows to the result container.
		//GlobalResultContainer->PushNetflow9Flows(outRecords);
	}
}

// Parses an IPFIX packet.
void NetflowParser::ParseIPFIXPacket(const char* packet, const unsigned int length)
{
	
}

// ---------------------------------------------------------------------------------------------

// Gets whether the parser loop is running or not.
const bool NetflowParser::IsRunning() const
{
	return this->mRunning;
}

// Gets the number of failed tasks.
const unsigned int NetflowParser::GetFailedTasks() const
{
	return this->mFailedTasks;
}

// ---------------------------------------------------------------------------------------------

// Starts the parser loop.
void NetflowParser::StartParser()
{
	// Set the workers to have started.
	this->mRunning = true;
	
	// Fire off the processing loop.
	this->mProcessingThread.Run(THISBACK(ProcessingLoop));
}

// Stops the parser loop and waits until it can be interrupted.
void NetflowParser::StopParser()
{
	// Tell the workers to finish up their work.
	this->mRunning = false;
	
	// Wait for the workers to finish.
	this->mThreadPool.Finish();
	
	// Wait for the processing loop to finish.
	this->mProcessingThread.Wait();
}

// Queues a packet for processing.
void NetflowParser::QueueTask(const unsigned int version, const char* packet, const unsigned int length, const UNIVERSAL_IPADDRESS* const expip)
{
	this->mLock.Enter();
	this->mQueuedTasks.AddTail(ProcessingTask(version, packet, length, expip));
	this->mLock.Leave();
}