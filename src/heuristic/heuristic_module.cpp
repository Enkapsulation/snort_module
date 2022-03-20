#include "heuristic_module.hpp"
#include "heuristic.hpp"
#include "heuristic_types.hpp"
#include "utils.hpp"

#include "detection/detection_engine.h"

// THREAD_LOCAL SimpleStats asstats;

using namespace snort;

//-------------------------------------------------------------------------
// heurstic params
//-------------------------------------------------------------------------
static const Parameter heuristic_params[]
	= { { "sensitivity", Parameter::PT_REAL, nullptr, nullptr, "detection threshold" },
		{ "entropy", Parameter::PT_REAL, nullptr, nullptr, "packet entropy threshold" },
		{ "packet_value", Parameter::PT_REAL, nullptr, nullptr, "start packet value" },
		{ "filename_malicious", Parameter::PT_STRING, nullptr, nullptr, "Path to .CSV with malicius IP address" },

		{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const Parameter s_params[]
	= { { "configuration", Parameter::PT_LIST, heuristic_params, nullptr, "heursitic configuration" },
		{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };

static const RuleMap s_rules[] = { { 1, "Jeszcze jak" }, { 0, nullptr } };

//-------------------------------------------------------------------------
// heuristic module
//-------------------------------------------------------------------------
HeuristicModule::HeuristicModule()
	: Module( s_name.data(), s_help.data(), s_params ),
	  m_config( nullptr ),
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

bool HeuristicModule::set( const char*, Value& value, SnortConfig* )
{
	if( value.is( "sensitivity" ) )
	{
		m_config->sensitivity = value.get_real();
	}
	else if( value.is( "dangerous_entropy" ) )
	{
		m_config->dangerous_entropy = value.get_real();
	}
	else if( value.is( "packet_value" ) )
	{
		m_config->packet_value = value.get_real();
	}
	else if( value.is( "filename_malicious" ) )
	{
		m_config->filename_malicious = value.get_as_string();
	}
	else
	{
		return false;
	}

	return true;
}

bool HeuristicModule::begin( const char*, int, SnortConfig* )
{
	if( !m_config )
	{
		/* Set default vaule config*/
		double defaultSensitivity			 = 20.0;
		double defaultDangerousEntropy		 = 6.0;
		double defaultPacketValue			 = 15.0;
		std::string defaultFilenameMalicious = "";

		m_config = std::make_shared< HeuristicConfig >(
			defaultSensitivity, defaultDangerousEntropy, defaultPacketValue, defaultFilenameMalicious );

		/* Set default value for flags*/
	}

	return true;
}

bool HeuristicModule::end( const char*, int idx, SnortConfig* )
{
	// if ( !config )
	// {
	//     config = new HeuristicConfig();
	// }
	return true;
}

std::shared_ptr< HeuristicConfig > HeuristicModule::get_config()
{
	std::shared_ptr< HeuristicConfig > temp = m_config;
	m_config								= nullptr;
	return temp;
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