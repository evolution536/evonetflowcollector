#ifndef EVO_NETFLOW_COLLECTOR_H
#define EVO_NETFLOW_COLLECTOR_H

#ifdef _WIN32
	#include <winsock2.h>
#else
	#include <sys/socket.h>
#endif

#include "EvoNetflow.h"
#include <vector>
#include <thread>

class EvoNetflowCollector
{
private:
#ifdef _WIN32
	SOCKET ListenSocket;
#else
	int ListenSocket;
#endif
	bool mRunning;
	std::thread mSocketThread;

	void ListenerThread();
public:
	EvoNetflowCollector();
	~EvoNetflowCollector();

	const bool Bind(const int port);
	const bool BeginListen();
	void StopListening();
};

const bool ParseNetflow5Packet(const char* buffer, std::vector<unsigned int>& outSequences, std::vector<NETFLOW5_FLOW_RECORD>& outRecords);

#endif