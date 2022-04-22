#include "heuristic_module.hpp"
#include "config.hpp"
#include "framework/parameter.h"
#include "heuristic_inspector.hpp"
#include "parameters_name.hpp"
#include "utils.hpp"

#include "detection/detection_engine.h"
#include <cstddef>

static THREAD_LOCAL SimpleStats heuristic_stats;
static THREAD_LOCAL snort::ProfileStats heuristicPerfStats;

using namespace snort;
using namespace Parameters::Name;

//-------------------------------------------------------------------------
// heurstic params
//-------------------------------------------------------------------------
static const Parameter dangerous_flag[] = { { "H", Parameter::PT_REAL, nullptr, nullptr, "Value for flag High" },
											{ "M", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Medium" },
											{ "L", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Low" },
											{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter attack_flag[] = { { "D", Parameter::PT_REAL, nullptr, nullptr, "Value for DDoS flag" },
										 { "P", Parameter::PT_REAL, nullptr, nullptr, "Value for Phishing flag" },
										 { "M", Parameter::PT_REAL, nullptr, nullptr, "Value for Malware flag" },
										 { "R", Parameter::PT_REAL, nullptr, nullptr, "Value for Ransomware flag" },
										 { "S", Parameter::PT_REAL, nullptr, nullptr, "Value for DoS flag" },
										 { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter range_flag[] = { { "S", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Single" },
										{ "P", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Partial" },
										{ "C", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Complete" },
										{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter access_flag[] = { { "N", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Single" },
										 { "U", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Partial" },
										 { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter availability_flag[] = { { "N", Parameter::PT_REAL, nullptr, nullptr, "Value for flag None" },
											   { "P", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Partial" },
											   { "C", Parameter::PT_REAL, nullptr, nullptr, "Value for flag Complete" },
											   { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter heuristic_params[] = {
	{ s_sensitivityName.data(), Parameter::PT_REAL, nullptr, nullptr, "detection threshold" },
	{ s_entropyName.data(), Parameter::PT_REAL, nullptr, nullptr, "packet entropy threshold" },
	{ s_packetValueName.data(), Parameter::PT_REAL, nullptr, nullptr, "start packet value" },
	{ s_filenameMaliciousName.data(), Parameter::PT_STRING, nullptr, nullptr, "Path to .CSV with malicius IP address" },
	{ s_dangerousName.data(), Parameter::PT_LIST, dangerous_flag, nullptr, "Value for dangerous flag" },
	{ s_attackName.data(), Parameter::PT_LIST, attack_flag, nullptr, "Value for attack type flag" },
	{ s_rangeName.data(), Parameter::PT_LIST, range_flag, nullptr, "Value for range flag" },
	{ s_accessName.data(), Parameter::PT_LIST, access_flag, nullptr, "Value for access flag" },
	{ s_availabilityName.data(), Parameter::PT_LIST, availability_flag, nullptr, "Value for availability flag" },
	{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static constexpr RuleMap s_rules[] = { { 1, "Jeszcze jak" }, { 0, nullptr } };

HeuristicModule::HeuristicModule()
	: Module( s_name.data(), s_help.data(), heuristic_params ), m_config( std::make_shared< HeuristicConfig >() )
{
}

HeuristicModule::~HeuristicModule() = default;

const RuleMap* HeuristicModule::get_rules() const
{
	return s_rules;
}

ProfileStats* HeuristicModule::get_profile() const
{
	return &heuristicPerfStats;
}

bool HeuristicModule::set( const char* rawString, Value& value, SnortConfig* config )
{
	return m_config->set( rawString, value );
}

bool HeuristicModule::begin( const char*, int, SnortConfig* )
{
	return true;
}

bool HeuristicModule::end( const char*, int, SnortConfig* )
{
	return true;
}

void HeuristicModule::incrementPacketCounter()
{
	++heuristic_stats.total_packets;
}

std::shared_ptr< HeuristicConfig > HeuristicModule::get_config() const
{
	return m_config;
}

const PegInfo* HeuristicModule::get_pegs() const
{
	return simple_pegs;
}

PegCount* HeuristicModule::get_counts() const
{
	return &heuristic_stats.total_packets;
}

unsigned HeuristicModule::get_gid() const
{
	return s_idHeuristic;
}

HeuristicModule::Usage HeuristicModule::get_usage() const
{
	return INSPECT;
}

void HeuristicModule::setInspector( Heuristic* heuristic )
{
	m_inspector = heuristic;
}

std::string_view HeuristicModule::getName()
{
	return s_name;
}

std::string_view HeuristicModule::getHelp()
{
	return s_help;
}