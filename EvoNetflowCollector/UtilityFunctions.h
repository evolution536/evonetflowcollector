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