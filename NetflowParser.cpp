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
const char* NetflowParser::GetProtocolStringFromNumber(const unsigned int number)
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
		
		// Get the timestamp for the flows in this packet.
		const unsigned long timestamp = ntohl(nfHeader->UnixSeconds);
		
		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = ntohs(nfHeader->FlowCount);
		if (flowCount <= 24)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
			PNETFLOW1_FLOW_RECORD flowRecord = (PNETFLOW1_FLOW_RECORD)(packet + sizeof(NETFLOW1_HEADER));

			for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
			{
				Netflow1Storage& newRecord = outRecords.Add();
				newRecord.TimeStamp = timestamp;
				newRecord.FlowStorage.SourceIpAddress = flowRecord->SourceIpAddress;
				newRecord.FlowStorage.DestinationIpAddress = flowRecord->DestinationIpAddress;
				newRecord.FlowStorage.NextHop = flowRecord->NextHop;
				newRecord.FlowStorage.InputSnmp = ntohs(flowRecord->InputSnmp);
				newRecord.FlowStorage.OutputSnmp = ntohs(flowRecord->OutputSnmp);
				newRecord.FlowStorage.PacketCount = ntohl(flowRecord->PacketCount);
				newRecord.FlowStorage.BytesCount = ntohl(flowRecord->BytesCount);
				newRecord.FlowStorage.SysUptimeFirst = ntohl(flowRecord->SysUptimeFirst);
				newRecord.FlowStorage.SysUptimeLast = ntohl(flowRecord->SysUptimeLast);
				newRecord.FlowStorage.SourcePort = ntohs(flowRecord->SourcePort);
				newRecord.FlowStorage.DestinationPort = ntohs(flowRecord->DestinationPort);
				newRecord.FlowStorage.TcpFlags = flowRecord->TcpFlags;
				newRecord.FlowStorage.Protocol = flowRecord->Protocol;
				newRecord.FlowStorage.IpTypeOfService = flowRecord->IpTypeOfService;
			}
		}

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

		// Get the timestamp for the flows in this packet.
		const unsigned long timestamp = ntohl(nfHeader->UnixSeconds);

		// Save the sequence number of this packet.
		const unsigned long seqnum = ntohl(nfHeader->FlowSequence);

		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = ntohs(nfHeader->FlowCount);
		if (flowCount <= 30)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
			PNETFLOW5_FLOW_RECORD flowRecord = (PNETFLOW5_FLOW_RECORD)(packet + sizeof(NETFLOW5_HEADER));

			for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
			{
				Netflow5Storage& newRecord = outRecords.Add();
				newRecord.TimeStamp = timestamp;
				newRecord.FlowSequence = seqnum + i;
				newRecord.FlowStorage.SourceIpAddress = flowRecord->SourceIpAddress;
				newRecord.FlowStorage.DestinationIpAddress = flowRecord->DestinationIpAddress;
				newRecord.FlowStorage.NextHop = flowRecord->NextHop;
				newRecord.FlowStorage.InputSnmp = ntohs(flowRecord->InputSnmp);
				newRecord.FlowStorage.OutputSnmp = ntohs(flowRecord->OutputSnmp);
				newRecord.FlowStorage.PacketCount = ntohl(flowRecord->PacketCount);
				newRecord.FlowStorage.BytesCount = ntohl(flowRecord->BytesCount);
				newRecord.FlowStorage.SysUptimeFirst = ntohl(flowRecord->SysUptimeFirst);
				newRecord.FlowStorage.SysUptimeLast = ntohl(flowRecord->SysUptimeLast);
				newRecord.FlowStorage.SourcePort = ntohs(flowRecord->SourcePort);
				newRecord.FlowStorage.DestinationPort = ntohs(flowRecord->DestinationPort);
				newRecord.FlowStorage.TcpFlags = flowRecord->TcpFlags;
				newRecord.FlowStorage.Protocol = flowRecord->Protocol;
				newRecord.FlowStorage.IpTypeOfService = flowRecord->IpTypeOfService;
				newRecord.FlowStorage.SourceAutonomousSystemNumber = ntohs(flowRecord->SourceAutonomousSystemNumber);
				newRecord.FlowStorage.DestinationAutonomousSystemNumber = ntohs(flowRecord->DestinationAutonomousSystemNumber);
				newRecord.FlowStorage.SourceMask = flowRecord->SourceMask;
				newRecord.FlowStorage.DestinationMask = flowRecord->DestinationMask;
			}
		}

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

		// Get the timestamp for the flows in this packet.
		const unsigned long timestamp = ntohl(nfHeader->UnixSeconds);

		// Save the sequence number of this packet.
		const unsigned long seqnum = ntohl(nfHeader->FlowSequence);

		// Build in a safeguard for the flow count, in case we run into a corrupt packet.
		// The flow count makes sure we don't run out of our buffer.
		const unsigned short flowCount = ntohs(nfHeader->FlowCount);
		if (flowCount <= 30)
		{
			// Walk the flows in the packet and parse them using the Netflow v5 structures.
			outRecords.Reserve(flowCount);
			PNETFLOW7_FLOW_RECORD flowRecord = (PNETFLOW7_FLOW_RECORD)(packet + sizeof(NETFLOW7_HEADER));

			for (unsigned int i = 0; i < flowCount; ++i, ++flowRecord)
			{
				Netflow7Storage& newRecord = outRecords.Add();
				newRecord.TimeStamp = timestamp;
				newRecord.FlowSequence = seqnum + i;
				newRecord.FlowStorage.SourceIpAddress = flowRecord->SourceIpAddress;
				newRecord.FlowStorage.DestinationIpAddress = flowRecord->DestinationIpAddress;
				newRecord.FlowStorage.NextHop = flowRecord->NextHop;
				newRecord.FlowStorage.InputSnmp = ntohs(flowRecord->InputSnmp);
				newRecord.FlowStorage.OutputSnmp = ntohs(flowRecord->OutputSnmp);
				newRecord.FlowStorage.PacketCount = ntohl(flowRecord->PacketCount);
				newRecord.FlowStorage.BytesCount = ntohl(flowRecord->BytesCount);
				newRecord.FlowStorage.SysUptimeFirst = ntohl(flowRecord->SysUptimeFirst);
				newRecord.FlowStorage.SysUptimeLast = ntohl(flowRecord->SysUptimeLast);
				newRecord.FlowStorage.SourcePort = ntohs(flowRecord->SourcePort);
				newRecord.FlowStorage.DestinationPort = ntohs(flowRecord->DestinationPort);
				newRecord.FlowStorage.TcpFlags = flowRecord->TcpFlags;
				newRecord.FlowStorage.Protocol = flowRecord->Protocol;
				newRecord.FlowStorage.IpTypeOfService = flowRecord->IpTypeOfService;
				newRecord.FlowStorage.SourceAutonomousSystemNumber = ntohs(flowRecord->SourceAutonomousSystemNumber);
				newRecord.FlowStorage.DestinationAutonomousSystemNumber = ntohs(flowRecord->DestinationAutonomousSystemNumber);
				newRecord.FlowStorage.SourceMask = flowRecord->SourceMask;
				newRecord.FlowStorage.DestinationMask = flowRecord->DestinationMask;
				newRecord.FlowStorage.Flags = ntohs(flowRecord->Flags);
			}
		}

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
		// Retrieve flows from the packet.
		const PNETFLOW9_HEADER nfHeader = (PNETFLOW9_HEADER)packet;

		// Save the sequence number and timestamp of this packet.
		const unsigned long seqnum = ntohl(nfHeader->PackageSequence);
		const unsigned long timestamp = ntohl(nfHeader->UnixSeconds);
		
		// Keep track of how many flows are in this packet.
		unsigned int sequenceCounter = 0;

		// Walk the packet flowsets, making sure it does not leave the bounds of the packet buffer.
		unsigned int pktIt = sizeof(NETFLOW9_HEADER);
		while (pktIt < length)
		{
			// Let's process the next flowset.
			PNETFLOW9_FLOWSET_HEADER pFlowSet = (PNETFLOW9_FLOWSET_HEADER)(packet + pktIt);
			const unsigned short flowsetId = ntohs(pFlowSet->FlowsetID);
			const unsigned short flowSetLength = ntohs(pFlowSet->Length);
			unsigned int flowsetIt = 0;
			
			// Is this flowset an option template?
			if (flowsetId == 1)
			{
				// Parse options template flowset.
				while (flowsetIt + sizeof(NETFLOW9_FLOWSET_HEADER) < flowSetLength)
				{
					const PNETFLOW9_OPTIONS_TEMPLATE_HEADER optionsHeader = (PNETFLOW9_OPTIONS_TEMPLATE_HEADER)(packet + pktIt + sizeof(NETFLOW9_FLOWSET_HEADER) + flowsetIt);
					flowsetIt += sizeof(NETFLOW9_OPTIONS_TEMPLATE_HEADER);
					
					// Find out how many fields are in this template record.
					const unsigned short templateID = ntohs(optionsHeader->TemplateID);
					const unsigned short scopeLength = ntohs(optionsHeader->OptionsScopeLength);
					const unsigned short optionsLength = ntohs(optionsHeader->OptionsLength);
					
					if (!ParseNetflow9OptionsTemplate(optionsHeader, length - pktIt))
					{
						// parse succeeded...
					}
				}
			}
			// Is this flowset a data template?
			else if (flowsetId <= 255)
			{
				// Parse data template flowset.
				while (flowsetIt + sizeof(NETFLOW9_FLOWSET_HEADER) < flowSetLength)
				{
					const PNETFLOW9_TEMPLATE_FLOWSET_HEADER templateHeader = (PNETFLOW9_TEMPLATE_FLOWSET_HEADER)(packet + pktIt + sizeof(NETFLOW9_FLOWSET_HEADER) + flowsetIt);
					flowsetIt += sizeof(NETFLOW9_TEMPLATE_FLOWSET_HEADER);

					// Find out how many fields are in this template record.
					const unsigned short templateID = ntohs(templateHeader->TemplateID);
					const unsigned short fieldCount = ntohs(templateHeader->FieldCount);

					Vector<TemplateFieldEntry> dataFields;
					dataFields.Reserve(fieldCount);
					if (ParseNetflow9DataTemplate(templateHeader, length - pktIt, dataFields))
					{
						// Succeeded in parsing the template, now pass it to the template cache.
						GlobalTemplateCache->AddTemplate(9, templateID, TEMPLATE_DATA, dataFields);
					}

					// Increment the flowset iterator.
					flowsetIt += fieldCount * sizeof(NETFLOW9_TEMPLATE_RECORD);
				}
			}
			// Is this a flowset a collection of flow records?
			else if (flowsetId > 255)
			{
				const unsigned short flowCount = ntohs(nfHeader->FlowCount);
				
				// Are there flows in this packet?
				if (flowCount <= 30)
				{
					// Find out which template should be used to parse this flowset.
					const FlowTemplate* const flowTemplate = GlobalTemplateCache->FindTemplate(9, flowsetId);
					
					// Only continue parsing the flows in this packet if we actually have a template to do so.
					if (flowTemplate)
					{
						// Make a copy of the fields, to enable another worker to replace the template if required.
						FlowTemplate localTemplate;
						GlobalTemplateCache->CopyTemplateData(flowTemplate, localTemplate);

						// How many fields should there be in these flow records?
						const unsigned short fieldCount = localTemplate.FieldCache.GetCount();

						// Output vector for the processed flows.
						Vector<Netflow9Storage> outRecords;
						outRecords.Reserve(flowCount);
						
						// Walk through the flowset in bytes.
						while (flowsetIt + sizeof(NETFLOW9_FLOWSET_HEADER) < flowSetLength)
						{
							// Add a new entry in the flow storage.
							Netflow9Storage& flow = outRecords.Add();
							flow.TimeStamp = timestamp;
							flow.FlowSequence = seqnum + sequenceCounter++;
							
							// Parse flow data records.
							PNETFLOW9_DATA_FLOWSET_HEADER flowRecord = (PNETFLOW9_DATA_FLOWSET_HEADER)(packet + pktIt + sizeof(NETFLOW9_FLOWSET_HEADER) + flowsetIt);
							for (int i = 0; i < fieldCount; ++i)
							{
								// Try to parse the current field.
								String output;
								const TemplateFieldEntry& thisField = localTemplate.FieldCache[i];
								if (ParseNetflow9Field(thisField.FieldType, thisField.FieldLength, flowRecord->FieldValue, output))
								{
									// Succeeded in parsing, add the output to the flow storage.
									// Another sanity check just to be sure we stay in the compile-time-defined bounds.
									if (thisField.FieldType < sizeof(flow.FlowStorage))
									{
										flow.FlowStorage[thisField.FieldType].FieldValue = output;
									}
								}
								
								// Increment the pointer to point to the next field.
								flowsetIt += thisField.FieldLength;
								flowRecord = (PNETFLOW9_DATA_FLOWSET_HEADER)((char*)flowRecord + thisField.FieldLength);
							}

							// There could be a padding at the end of the flowset to align it to 32-bits.
							const unsigned int leftOver = flowSetLength - (flowsetIt + sizeof(NETFLOW9_FLOWSET_HEADER));
							if (leftOver < sizeof(int))
							{
								flowsetIt += leftOver;
							}
						}
						
						// Push the processed flows to the result container.
						GlobalResultContainer->PushNetflow9Flows(outRecords);
					}
				}
			}
			else
			{
				// not valid?
			}

			// Increment the packet iterator.
			pktIt += flowSetLength;
		}
	}
}

// Parses an IPFIX packet.
void NetflowParser::ParseIPFIXPacket(const char* packet, const unsigned int length)
{
	// Check whether the packet size and buffer are valid.
	if (packet && (length > 0 && length >= sizeof(IPFIX_HEADER)))
	{
		// Retrieve flows from the packet.
		const PIPFIX_HEADER nfHeader = (PIPFIX_HEADER)packet;
		
		const unsigned long seqnum = ntohl(nfHeader->SequenceNumber);
		const unsigned long timestamp = ntohl(nfHeader->ExportTimeStamp);

		// Keep track of how many flows are in this packet.
		unsigned int sequenceCounter = 0;

		// Walk the packet flowsets, making sure it does not leave the bounds of the packet buffer.
		unsigned int pktIt = sizeof(IPFIX_HEADER);
		while (pktIt < length)
		{
			const PIPFIX_SET_HEADER pFlowSet = (PIPFIX_SET_HEADER)(packet + pktIt);
			const unsigned short flowsetId = ntohs(pFlowSet->SetID);
			const unsigned short flowSetLength = ntohs(pFlowSet->Length);
			unsigned int flowsetIt = 0;
			
			// Is this a template flowset?
			if (flowsetId == 2)
			{
				while (flowsetIt + sizeof(IPFIX_SET_HEADER) < flowSetLength)
				{
					const PIPFIX_TEMPLATE_HEADER templateHeader = (PIPFIX_TEMPLATE_HEADER)(packet + pktIt + flowsetIt + sizeof(IPFIX_SET_HEADER));
					flowsetIt += sizeof(IPFIX_TEMPLATE_HEADER);
					
					// Find out how many fields are in this template record.
					const unsigned short templateID = ntohs(templateHeader->TemplateID);
					const unsigned short fieldCount = ntohs(templateHeader->FieldCount);
					
					// Walk the fields in this template record.
					for (int i = 0; i < fieldCount; ++i)
					{
						PIPFIX_INFORMATION_ELEMENT_HEADER elementHeader = (PIPFIX_INFORMATION_ELEMENT_HEADER)((char*)templateHeader + i * sizeof(IPFIX_INFORMATION_ELEMENT_HEADER));
						
						// Enterprise number of template?
					}
				}
			}
			// If this an option template flowset?
			else if (flowsetId == 3)
			{
				while (flowsetIt + sizeof(IPFIX_SET_HEADER) < flowSetLength)
				{
					const PIPFIX_OPTIONS_TEMPLATE_HEADER templateHeader = (PIPFIX_OPTIONS_TEMPLATE_HEADER)(packet + pktIt + flowsetIt + sizeof(IPFIX_SET_HEADER));
					flowsetIt += sizeof(PIPFIX_OPTIONS_TEMPLATE_HEADER);
					
					// Find out how many fields are in this template record.
					const unsigned short templateID = ntohs(templateHeader->TemplateID);
					const unsigned short scopeFieldCount = ntohs(templateHeader->ScopeFieldCount);
					const unsigned short fieldCount = ntohs(templateHeader->FieldCount);
				}
			}
			// Is this a data flowset?
			else if (flowsetId > 255)
			{
				
			}
			else
			{
				// not valid?
			}
		}
	}
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
