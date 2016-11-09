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
void TemplateCache::AddTemplate(const unsigned short version, const unsigned short templateID, const TemplateType type, const Vector<TemplateFieldEntry>& dataFields)
{
	// Construct the key.
	TemplateCacheKey key;
	key.Version = version;
	key.TemplateID = templateID;
	
	// One thread should be looking at templates at a time.
	this->mTemplateCS.Enter();
	
	// Check whether the template already exists. If not, we should add it.
	const int index = this->mFlowTemplates.Find(key);
	if (index < 0)
	{
		this->mFlowTemplates.Add(key);
	}
	
	// Change the properties of the template.
	FlowTemplate& templ = this->mFlowTemplates.Get(key);
	templ.Type = type;
	
	// Clear the current field list and insert the new one.
	templ.FieldCache.Clear();
	templ.FieldCache <<= dataFields;
	
	// Release the lock.
	this->mTemplateCS.Leave();
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

// Copies a template to a template passed as parameter, to avoid race conditions.
void TemplateCache::CopyTemplateData(const FlowTemplate* const flowTemplate, FlowTemplate& outTemplate)
{
	// One thread should be looking at templates at a time.
	this->mTemplateCS.Enter();
	
	// Copy the template.
	outTemplate.Type = flowTemplate->Type;
	outTemplate.FieldCache.Append(flowTemplate->FieldCache);
	
	// Release the lock.
	this->mTemplateCS.Leave();
}