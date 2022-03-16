#include "heuristic_module.hpp"
#include <memory>

// THREAD_LOCAL SimpleStats asstats;

using namespace snort;

//-------------------------------------------------------------------------
// arp_spoof stuff
//-------------------------------------------------------------------------
static const Parameter heuristic_params[]
	= { { "sensitivity", Parameter::PT_INT, nullptr, nullptr, "detection threshold" },
		{ "entropy", Parameter::PT_REAL, nullptr, nullptr, "packet entropy threshold" },
		{ "packet_value", Parameter::PT_REAL, nullptr, nullptr, "start packet value" },
		{ "filename_malicious", Parameter::PT_STRING, nullptr, nullptr, "Path to .CSV with malicius IP address" },

		{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter s_params[]
	= { { "hosts", Parameter::PT_LIST, heuristic_params, nullptr, "configure ARP cache overwrite attacks" },
		{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const RuleMap s_rules[] = { { 678, "Jeszcze jak" }, { 0, nullptr } };

//-------------------------------------------------------------------------
// arp_spoof module
//-------------------------------------------------------------------------
HeuristicModule::HeuristicModule() : Module( s_name, s_help, s_params ), config( nullptr ) {}

HeuristicModule::~HeuristicModule() = default;

const RuleMap* HeuristicModule::get_rules() const
{
	return s_rules;
}

ProfileStats* HeuristicModule::get_profile() const
{
	return &heuristicPerfStats;
}

bool HeuristicModule::set( const char*, Value& v, SnortConfig* )
{
	return true;
}

bool HeuristicModule::begin( const char*, int, SnortConfig* )
{
	if( !config )
	{
		config = std::make_shared< HeuristicConfig >();
	}

	return true;
}

bool HeuristicModule::end( const char*, int idx, SnortConfig* )
{
	return true;
}

std::shared_ptr< HeuristicConfig > HeuristicModule::get_config()
{
	return config;
}

const PegInfo* HeuristicModule::get_pegs() const
{
	return simple_pegs;
}

PegCount* HeuristicModule::get_counts() const
{
	return ( PegCount* )&asstats;
}

unsigned HeuristicModule::get_gid() const
{
	return gid_heuristic;
}

HeuristicModule::Usage HeuristicModule::get_usage() const
{
	return INSPECT;
}