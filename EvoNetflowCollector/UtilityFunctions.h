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

#ifndef UTILITY_FUNCTIONS_H
#define UTILITY_FUNCTIONS_H

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

#endif