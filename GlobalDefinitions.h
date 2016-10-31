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

#ifndef _EvoNetflowCollector_GlobalDefinitions_h_
#define _EvoNetflowCollector_GlobalDefinitions_h_

#include "TemplateCache.h"
#include "NetflowResultContainer.h"
#include "NetflowParser.h"

// The minimum socket buffer size that needs to be used for listening.
// If the buffer size is any lower, we might drop packets faster.
#define SOCKET_MINIMUM_BUFFER_SIZE				65536

// Specifies how many entries we will keep inside the back buffer for processed flows. This
// value is the size per version.
#define BACK_BUFFER_SIZE_PER_VERSION			1024

// Specifies the maximum number of simultaniously active logging methods.
#define MAXIMUM_ACTIVE_LOGGING_METHODS			8

// Represents a logging method.
enum LoggingMethod
{
	LOGGING_METHOD_UNDEFINED,
	LOGGING_METHOD_FILE,
	LOGGING_METHOD_NULL
};

// Global instance of the result container.
extern NetflowResultContainer* GlobalResultContainer;

// Global instance of the Netflow parser.
extern NetflowParser* GlobalNetflowParser;

// Global instance of the template cache.
extern TemplateCache* GlobalTemplateCache;

#endif
