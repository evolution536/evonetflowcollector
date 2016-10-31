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

#ifndef _EvoNetflowCollector_TemplateCache_h_
#define _EvoNetflowCollector_TemplateCache_h_

#include <Core/Core.h>

using namespace Upp;

// Represents the type of template.
enum TemplateType
{
	TEMPLATE_DATA,
	TEMPLATE_OPTIONS
};

// Represents a template for Netflow v9 or IPFIX.
struct FlowTemplate : Moveable<FlowTemplate>
{
	// The version of Netflow of the template: 9 for Netflow v9 and 10 for IPFIX.
	unsigned short Version;
	
	// The type of template, data or options.
	TemplateType Type;
	
	// The template ID of the template.
	unsigned short TemplateID;
	
	// The fields of this template.
	VectorMap<unsigned short, unsigned short> FieldCache;
	
	// Retrieves the field size of a field in this template.
	const unsigned short GetFieldSize(const unsigned short fieldType) const
	{
		return this->FieldCache.Get(fieldType);
	};
};

// Represents a key for the template cache container.
struct TemplateCacheKey : Moveable<TemplateCacheKey>
{
	// The version of Netflow of the template: 9 for Netflow v9 and 10 for IPFIX.
	unsigned short Version;
	
	// The template ID of the template.
	unsigned short TemplateID;
	
	// We use this struct as map key, so it needs to return a hash value of some kind.
	unsigned GetHashValue() const
	{
		return (this->Version * Random(256) + this->TemplateID * Random(256)) % 256;
	};
	
	// Keys need to be comparable.
	bool operator==(const TemplateCacheKey& other) const
	{
		return this->Version == other.Version && this->TemplateID == other.TemplateID;
	};
};

// Represents the template cache for Netflow v9 and IPFIX exports.
class TemplateCache
{
private:
	VectorMap<TemplateCacheKey, FlowTemplate> mFlowTemplates;
	
	TemplateCache();
	~TemplateCache();
	
	TemplateCache(TemplateCache const&);
	void operator=(TemplateCache const&);
public:
	static TemplateCache* GetInstance()
	{
		static TemplateCache instance;
		return &instance;
	};
	
	void AddTemplate(const unsigned short version, const unsigned short templateID, const TemplateType type, const VectorMap<unsigned short, unsigned short>& dataFields);
	const FlowTemplate* FindTemplate(const unsigned short version, const unsigned short templateID) const;
};

#endif