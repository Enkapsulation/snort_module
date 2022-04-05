#include "heuristic_module.hpp"
#include "config.hpp"
#include "framework/parameter.h"
#include "heuristic.hpp"
#include "heuristic_types.hpp"
#include "utils.hpp"

#include "detection/detection_engine.h"
#include <cstddef>

static THREAD_LOCAL SimpleStats asstats;
static THREAD_LOCAL snort::ProfileStats heuristicPerfStats;

using namespace snort;

//-------------------------------------------------------------------------
// heurstic params
//-------------------------------------------------------------------------
static const Parameter risk_flag[] = { { "H", Parameter::PT_INT, nullptr, nullptr, "Value for flag High" },
									   { "M", Parameter::PT_INT, nullptr, nullptr, "Value for flag Medium" },
									   { "L", Parameter::PT_INT, nullptr, nullptr, "Value for flag Low" },
									   { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter attack_flag[] = { { "D", Parameter::PT_INT, nullptr, nullptr, "Value for DDoS flag" },
										 { "P", Parameter::PT_INT, nullptr, nullptr, "Value for Phishing flag" },
										 { "M", Parameter::PT_INT, nullptr, nullptr, "Value for Malware flag" },
										 { "R", Parameter::PT_INT, nullptr, nullptr, "Value for Ransomware flag" },
										 { "S", Parameter::PT_INT, nullptr, nullptr, "Value for DoS flag" },
										 { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter range_flag[] = { { "S", Parameter::PT_INT, nullptr, nullptr, "Value for flag Single" },
										{ "P", Parameter::PT_INT, nullptr, nullptr, "Value for flag Partial" },
										{ "C", Parameter::PT_INT, nullptr, nullptr, "Value for flag Complete" },
										{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter access_flag[] = { { "S", Parameter::PT_INT, nullptr, nullptr, "Value for flag Single" },
										 { "P", Parameter::PT_INT, nullptr, nullptr, "Value for flag Partial" },
										 { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter availability_flag[] = { { "N", Parameter::PT_INT, nullptr, nullptr, "Value for flag None" },
											   { "P", Parameter::PT_INT, nullptr, nullptr, "Value for flag Partial" },
											   { "C", Parameter::PT_INT, nullptr, nullptr, "Value for flag Complete" },
											   { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter heuristic_params[]
	= { { "sensitivity", Parameter::PT_REAL, nullptr, nullptr, "detection threshold" },
		{ "entropy", Parameter::PT_REAL, nullptr, nullptr, "packet entropy threshold" },
		{ "packet_value", Parameter::PT_REAL, nullptr, nullptr, "start packet value" },
		{ "filename_malicious", Parameter::PT_STRING, nullptr, nullptr, "Path to .CSV with malicius IP address" },
		{ "risk", Parameter::PT_LIST, risk_flag, nullptr, "Value for risk flag" },
		{ "attack_type", Parameter::PT_LIST, attack_flag, nullptr, "Value for attack type flag" },
		{ "range", Parameter::PT_LIST, range_flag, nullptr, "Value for range flag" },
		{ "access", Parameter::PT_LIST, range_flag, nullptr, "Value for access flag" },
		{ "availability", Parameter::PT_LIST, range_flag, nullptr, "Value for availability flag" },
		{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

// static const Parameter s_params[]
// 	= { { "configuration", Parameter::PT_LIST, heuristic_params, nullptr, "heursitic configuration" },
// 		{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static constexpr RuleMap s_rules[] = { { 1, "Jeszcze jak" }, { 0, nullptr } };

//-------------------------------------------------------------------------
// heuristic module
//-------------------------------------------------------------------------
HeuristicModule::HeuristicModule()
	: Module( s_name.data(), s_help.data(), heuristic_params ),
	  m_config( std::make_shared< HeuristicConfig >( HeuristicConfig::getDefaultConfig() ) ),
	  m_inspector( std::make_unique< Heuristic >( m_config ) )
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

bool HeuristicModule::set( const char*, Value& value, SnortConfig* config )
{
	return m_config->set( value );
}

bool HeuristicModule::begin( const char*, int, SnortConfig* )
{
	return true;
}

bool HeuristicModule::end( const char*, int idx, SnortConfig* )
{
	return true;
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
	return &asstats.total_packets;
}

unsigned HeuristicModule::get_gid() const
{
	return s_idHeuristic;
}

HeuristicModule::Usage HeuristicModule::get_usage() const
{
	return INSPECT;
}

snort::Inspector* HeuristicModule::getInspector() const
{
	return static_cast< snort::Inspector* >( m_inspector.get() );
}

std::string_view HeuristicModule::getName()
{
	return s_name;
}

std::string_view HeuristicModule::getHelp()
{
	return s_help;
}

void HeuristicModule::testCsv()
{
	m_inspector->readCsv();
}