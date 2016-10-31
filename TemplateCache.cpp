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

#include "TemplateCache.h"

// TemplateCache default constructor.
TemplateCache::TemplateCache()
{
	
}

// TemplateCache default destructor.
TemplateCache::~TemplateCache()
{
	
}

// Attemps to add a template to the cache. If the template already exists, it is replaced.
void TemplateCache::AddTemplate(const unsigned short version, const unsigned short templateID, const TemplateType type, const VectorMap<unsigned short, unsigned short>& dataFields)
{
	// Construct the key.
	TemplateCacheKey key;
	key.Version = version;
	key.TemplateID = templateID;
	
	// No need to check for existence of the specified template, the map will do that for us.
	FlowTemplate& templ = this->mFlowTemplates.Get(key);
	templ.Type = type;
	
	// Clear the current field list and insert the new one.
	templ.FieldCache.Clear();
	templ.FieldCache <<= dataFields;
}

// Looks for the specified template in the cache, and returns a pointer if it is found, or NULL otherwise.
const FlowTemplate* TemplateCache::FindTemplate(const unsigned short version, const unsigned short templateID) const
{
	// Construct the key.
	TemplateCacheKey key;
	key.Version = version;
	key.TemplateID = templateID;
	
	// Look for the specified template.
	const int pos = this->mFlowTemplates.Find(key);
	if (pos >= 0)
	{
		return &this->mFlowTemplates.Get(key);
	}
	
	// Not found!
	return NULL;
}