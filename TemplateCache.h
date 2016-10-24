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

// Represents the template cache for Netflow v9 and IPFIX exports.
class TemplateCache
{
private:
	TemplateCache();
	~TemplateCache();
	
	TemplateCache(TemplateCache const&);
	void operator=(TemplateCache const&);
public:
	static TemplateCache* GetInstance()
	{
		static TemplateCache instance;
		return &instance;
	}
};

#endif