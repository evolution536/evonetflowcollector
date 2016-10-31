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

#ifndef _EvoNetflowCollector_EvoNetflowCollector_h
#define _EvoNetflowCollector_EvoNetflowCollector_h

#include <Core/Core.h>

using namespace Upp;

// Collector class that receives connections and passes packets through.
class NetflowCollector
{
private:
	int mSocket;
	bool mRunning;
	Thread mSocketListeningThread;
	
	typedef NetflowCollector CLASSNAME;
	
	void ListenerThread();
	const bool Bind(const unsigned short port);
	void SetSocketOptions();
	
	NetflowCollector();
	~NetflowCollector();
	
	NetflowCollector(NetflowCollector const&);
	void operator=(NetflowCollector const&);
public:
	static NetflowCollector* GetInstance()
	{
		static NetflowCollector instance;
		return &instance;
	}
	
	const int CheckNetflowPacketVersion(const char* buffer) const;
	const bool BeginListen(const int port);
	void StopListening();
};

#endif
