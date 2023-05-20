#include "memaccess.h"
#include "Util.h"




volatile size_t Gadget::current = 0;

// ReadGadget

ReadGadget::ReadGadget(ADDRINT i, ADDRINT start, ADDRINT end) : Gadget(READ, i) {
	range.first = start;
	range.second = end;
}

VOID ReadGadget::update_range(ADDRINT start, ADDRINT end) 
{
	if (start < range.first) 
	{
		range.first = start;
	}
	if (end > range.second) 
	{
		range.second = end;
	}
}

VOID ReadGadget::print() const 
{
	size_t len = range.second - range.first;
	ADDRINT base = Util::base;
	Util::Log(FALSE, "#%.4lu] %s+%#lx: R [+%#lx -  %#lx) - %#lx bytes\n", firstSeen, Util::imageName.c_str(), ip - base, range.first - base, range.second - base, range.second - range.first);
	Util::Log(FALSE, "----------------------------------------\n");
	return;
}

// WriteGadget

WriteGadget::WriteGadget(ADDRINT i, ADDRINT o, UINT64 val, size_t l) : Gadget(WRITE, i) {
	len = l;
	offset_values[o].push_back(val);
}

VOID WriteGadget::update_offset_values(ADDRINT address, UINT64 value) {
	offset_values[address].push_back(value);
}

VOID WriteGadget::print() const {
	ADDRINT base = Util::base;
	for (const auto& p : offset_values) {
		Util::Log(FALSE, "#%.4lu] %s+%#lx: W [+%#lx] = ", firstSeen, Util::imageName.c_str(), ADDRINT(ip) - base, p.first - base);
		for (const auto& value : p.second) {
			Util::Log(FALSE, "0x%.*lx ", len << 1, value);
		}
		Util::Log(FALSE, " (%lu values)\n", p.second.size());
	}
	Util::Log(FALSE, "----------------------------------------\n");
	return;
}