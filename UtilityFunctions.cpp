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

#ifdef _WIN32
	#include <Ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif

#include "UtilityFunctions.h"

// Swaps bytes of primitive data types to read big endian data.
template <typename T>
const T SwapBytes(const T* a)
{
	int reversed = 0;
	T retval;
	for (int i = sizeof(T) - 1; i >= 0; i--)
	{
		((unsigned char*)&retval)[reversed++] = ((unsigned char*)a)[i];
	}
	return retval;
}

// ---------------------------------------------------------------------------------------------

// Template definitions for SwapBytes function instances.
template const unsigned short SwapBytes<unsigned short>(const unsigned short* a);
template const unsigned long SwapBytes<unsigned long>(const unsigned long* a);
template const unsigned char SwapBytes<unsigned char>(const unsigned char* a);
template const unsigned int SwapBytes<unsigned int>(const unsigned int* a);

// ---------------------------------------------------------------------------------------------

// Converts a MAC address to its string representation.
String MacAddressToString(const unsigned char addr[6])
{
	StringBuffer stream;
	stream << addr[0] << ":" << addr[1] << ":" << addr[2] << ":" << addr[3] << ":" << addr[4] << ":" << addr[5];
	stream.Strlen();
	return stream;
}

// Converts a long IPv4 address to its string representation.
String Ipv4ToString(const IPV4ADDRESS ipv4)
{
	// Copy the IPv4 address to an in_addr structure.
	in_addr addr;
	*(IPV4ADDRESS*)&addr = ipv4;

	// Format it as string.
	StringBuffer ipbuffer(16);
	inet_ntop(AF_INET, &addr, ipbuffer.Begin(), 16);

	// Return the formatted IPv4 address.
	ipbuffer.Strlen();
	return ipbuffer;
}

// Converts a long IPv6 address to its string representation.
String Ipv6ToString(const IPV6ADDRESS ipv6)
{
	// Copy the IPv4 address to an in_addr structure.
	in6_addr addr;
	*(IPV6ADDRESS*)&addr = ipv6;

	// Format it as string.
	StringBuffer ipbuffer(46);
	inet_ntop(AF_INET6, &addr, ipbuffer.Begin(), 46);

	// Return the formatted IPv4 address.
	ipbuffer.Strlen();
	return ipbuffer;
}