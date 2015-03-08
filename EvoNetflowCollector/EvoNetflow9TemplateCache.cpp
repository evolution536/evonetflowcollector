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

#include "EvoNetflow9TemplateCache.h"
#include <algorithm>

EvoNetflow9TemplateCache::EvoNetflow9TemplateCache()
{

}

EvoNetflow9TemplateCache::~EvoNetflow9TemplateCache()
{

}

// Checks for the existence of a template with specified parameters.
const PNETFLOW9_TEMPLATE_CACHE_ENTRY EvoNetflow9TemplateCache::FindTemplate(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID) const
{
	auto retval = std::find(this->mTemplateCache.begin(), this->mTemplateCache.end(), NETFLOW9_TEMPLATE_CACHE_ENTRY(srcIp, sourceID, TemplateID));
	return retval == this->mTemplateCache.end() ? NULL : retval._Ptr;
}

// Adds a new template entry to the cache if it does not already exist.
const bool EvoNetflow9TemplateCache::AddTemplate(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID, const std::vector<NETFLOW9_TEMPLATE_FIELD>& fields)
{
	if (!this->FindTemplate(srcIp, sourceID, TemplateID))
	{
		NETFLOW9_TEMPLATE_CACHE_ENTRY entry(srcIp, sourceID, TemplateID);
		entry.FieldList = fields;
		this->mTemplateCache.push_back(entry);
		return true;
	}

	return false;
}

// Removes a template from the cache if it exists.
const bool EvoNetflow9TemplateCache::RemoveTemplate(const UNIVERSAL_IPADDRESS* srcIp, const unsigned long sourceID, unsigned short TemplateID)
{
	auto found_template = this->FindTemplate(srcIp, sourceID, TemplateID);
	if (found_template)
	{
		this->mTemplateCache.erase(std::remove(this->mTemplateCache.begin(), this->mTemplateCache.end(), *found_template), this->mTemplateCache.end());
	}

	return false;
}