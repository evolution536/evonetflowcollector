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

#ifndef EVO_NETFLOW9_TEMPLATE_CACHE_H
#define EVO_NETFLOW9_TEMPLATE_CACHE_H

#include <vector>
#include "EvoNetflow.h"
#include "EvoNetflowCollector.h"

typedef struct _NETFLOW9_TEMPLATE_FIELD
{
	unsigned short FieldType;
	unsigned short FieldLength;
} NETFLOW9_TEMPLATE_FIELD, *PNETFLOW9_TEMPLATE_FIELD;

typedef struct _NETFLOW9_TEMPLATE_CACHE_ENTRY
{
	UNIVERSAL_IPADDRESS SourceIpAddress;
	unsigned long SourceID;
	unsigned short TemplateID;
	std::vector<NETFLOW9_TEMPLATE_FIELD> FieldList;

	friend const bool operator ==(const _NETFLOW9_TEMPLATE_CACHE_ENTRY& first, const _NETFLOW9_TEMPLATE_CACHE_ENTRY& other);

	_NETFLOW9_TEMPLATE_CACHE_ENTRY(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID)
	{
		this->SourceIpAddress = *srcIp;
		this->SourceID = sourceID;
		this->TemplateID = TemplateID;
	};

	const unsigned int ParseFieldsUsingTemplate(const PNETFLOW9_DATA_FLOWSET_HEADER pDataHeader, std::vector<EvoNetflow9FieldValueSet>& outRecords);
} NETFLOW9_TEMPLATE_CACHE_ENTRY, *PNETFLOW9_TEMPLATE_CACHE_ENTRY;

// Comparison function for template cache entries.
inline const bool operator ==(const _NETFLOW9_TEMPLATE_CACHE_ENTRY& first, const _NETFLOW9_TEMPLATE_CACHE_ENTRY& other)
{
	return memcmp(&first.SourceIpAddress, &other.SourceIpAddress, sizeof(UNIVERSAL_IPADDRESS)) == 0 &&
		first.SourceID == other.SourceID && first.TemplateID == other.TemplateID;
}

// Represents the template cache for Netflow v9 exports.
class EvoNetflow9TemplateCache
{
private:
	std::vector<NETFLOW9_TEMPLATE_CACHE_ENTRY> mTemplateCache;
	
	// Singleton code: private constructor, destructor and copy constructors.
	EvoNetflow9TemplateCache();
	~EvoNetflow9TemplateCache();

	EvoNetflow9TemplateCache(EvoNetflow9TemplateCache const&);
	void operator=(EvoNetflow9TemplateCache const&);
public:
	static EvoNetflow9TemplateCache* GetInstance()
	{
		static EvoNetflow9TemplateCache instance;
		return &instance;
	}

	PNETFLOW9_TEMPLATE_CACHE_ENTRY FindTemplate(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID) const;
	const PNETFLOW9_TEMPLATE_CACHE_ENTRY FindTemplate(const unsigned short TemplateID) const;

	void AddTemplate(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID, const std::vector<NETFLOW9_TEMPLATE_FIELD>& fields);
	const bool RemoveTemplate(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID);
};

#endif