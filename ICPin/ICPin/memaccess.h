#pragma once
#include "common.h"


using namespace std;


class WriteGadget;

class Gadget 
{
public:
	// Vars
	ADDRINT ip;
	INT type;
	volatile static size_t current;
	size_t firstSeen;
	// Funcs
	Gadget(INT ty, ADDRINT i) : ip(i), type(ty), firstSeen(current) {}
	virtual VOID print() const = 0;
};

class ReadGadget : public Gadget
{
public:
	// [start, end)
	pair<ADDRINT, ADDRINT> range;
	ReadGadget(ADDRINT, ADDRINT, ADDRINT);
	VOID update_range(ADDRINT, ADDRINT);
	VOID print() const;
};

class WriteGadget : public Gadget
{
public:
	size_t len;
	tr1::unordered_map<ADDRINT, std::vector<UINT64>> offset_values;
	WriteGadget(ADDRINT, ADDRINT, UINT64, size_t);
	VOID update_offset_values(ADDRINT, UINT64);
	VOID print() const;
};
