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

#ifndef _EvoNetflowCollector_UtilityFunctions_h_
#define _EvoNetflowCollector_UtilityFunctions_h_

#include <Core/Core.h>

using namespace Upp;

#include "EvoNetflow.h"

// Swaps bytes of primitive data types to read big endian data.
template <typename T>
const T SwapBytes(const T* a);

// Converts a MAC address to its string representation.
String MacAddressToString(const unsigned char addr[6]);

// Converts a long IPv4 address to its string representation.
String Ipv4ToString(const IPV4ADDRESS ipv4);

// Converts a long IPv6 address to its string representation.
String Ipv6ToString(const IPV6ADDRESS ipv6);

#endif
