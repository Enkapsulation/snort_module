#include <array>
#include <fstream>
#include <iostream>

#include "flag.hpp"
#include "framework/value.h"
#include <arpa/inet.h>
#include <iterator>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <string_view>

#include "config.hpp"
#include "utils.hpp"
#include <functional>
#include <unordered_map>

HeuristicConfig::HeuristicConfig( float sensitivity, float entropy, float packetValue, std::string filenameMalicious )
	: m_sensitivity( sensitivity ),
	  m_entropy( entropy ),
	  m_packetValue( packetValue ),
	  m_filenameMalicious( filenameMalicious ),
	  m_filenameConfig( nullptr ),
	  m_dangerousIpAdresses()
{
}

HeuristicConfig::~HeuristicConfig()
{
	saveAllDangerousIps();
}

std::optional< DangerousIpAddr* > HeuristicConfig::find( std::string ip ) const
{
	const auto ipToCompare{ DangerousIpAddr::makeSockaddr( ip ) };

	auto suspiciousIpAddrIterator
		= std::find_if( m_dangerousIpAdresses.begin(),
						m_dangerousIpAdresses.end(),
						[ & ]( const DangerousIpAddr& dangerousIpAddr )
						{ return dangerousIpAddr.m_ipAddr.sin_addr.s_addr == ipToCompare.sin_addr.s_addr; } );

	if( suspiciousIpAddrIterator != m_dangerousIpAdresses.cend() )
	{
		return const_cast< DangerousIpAddr* >( &( *suspiciousIpAddrIterator ) );
	}

	return std::nullopt;
}

HeuristicConfig::operator std::string() const
{
	std::string msg{};

	msg += "{ sensitivity: " + std::to_string( getSensitivity() ) + "\n";
	msg += " entropy: " + std::to_string( getEntropy() ) + "\n";
	msg += " default packet value: " + std::to_string( getPacketValue() ) + "\n";
	msg += " Filename: " + getFilenameMalicious() + "}";

	return msg;
}

class ValueWrapper
{
public:
	using value_type = uint64_t;

	template< typename Obj, typename T >
	ValueWrapper( Obj& obj, T Obj::*member )
	{
		get = [ &, member ]() { return obj.*member; };
		set = [ &, member ]( value_type value ) mutable { obj.*member = value; };
	}

	ValueWrapper() = default;

	ValueWrapper& operator=( value_type value )
	{
		set( value );
		return *this;
	}

	operator value_type()
	{
		return get();
	}

	std::function< value_type() > get;
	std::function< void( value_type ) > set;
};

std::unordered_map< std::string, ValueWrapper > makeMap( HeuristicConfig& heuristicConfig )
{
	std::unordered_map< std::string, ValueWrapper > map;

	map[ HeuristicConfig::s_packetValueName.data() ] = ValueWrapper( heuristicConfig, &HeuristicConfig::m_packetValue );
	map[ HeuristicConfig::s_entropyName.data() ]	 = ValueWrapper( heuristicConfig, &HeuristicConfig::m_entropy );
	map[ HeuristicConfig::s_sensitivityName.data() ] = ValueWrapper( heuristicConfig, &HeuristicConfig::m_sensitivity );

	return map;
}

static constexpr size_t s_numberOfMembers{ 3 };

std::array< std::string, s_numberOfMembers > floatNamesToset{ HeuristicConfig::s_packetValueName.data(),
															  HeuristicConfig::s_entropyName.data(),
															  HeuristicConfig::s_sensitivityName.data() };

bool HeuristicConfig::set( const snort::Value& value )
{
	// HeuristicConfig test{ HeuristicConfig::getDefaultConfig() };

	// auto map = makeMap( test );

	// std::cout << test.m_packetValue << " " << test.m_entropy << " " << test.m_sensitivity << std::endl;

	// map[ "field2" ] = 123.F;

	// std::cout << map[ "field1" ] << " " << map[ "field2" ] << " " << map[ "field3" ] << std::endl;

	const auto& valueName{ static_cast< std::string >( value.get_name() ) };

	if( valueName.empty() )
	{
		return false;
	}

	auto founded = std::find( floatNamesToset.begin(), floatNamesToset.end(), valueName );

	// if( founded != floatNamesToset.end() )
	// {
	std::cout << " LOOOOOOL  " << ( *founded ).data() << std::endl;
	// }

	if( valueName == s_sensitivityName )
	{
		setSensitivity( value.get_real() );
	}
	else if( valueName == s_entropyName )
	{
		setEntropy( value.get_real() );
	}
	else if( valueName == s_packetValueName )
	{
		setPacketValue( value.get_real() );
	}
	else if( valueName == s_filenameMaliciousName )
	{
		setFilenameMalicious( value.get_as_string() );
		readCSV();
	}
	else
	{
		return false;
	}

	return true;
}

HeuristicConfig HeuristicConfig::getDefaultConfig()
{
	return { s_defaultSensitivity, s_defaultEntropy, s_defaultPacketValue, s_defaultFilenameMalicious.data() };
}

float HeuristicConfig::getSensitivity() const
{
	return m_sensitivity;
}

float HeuristicConfig::getEntropy() const
{
	return m_entropy;
}

float HeuristicConfig::getPacketValue() const
{
	return m_packetValue;
}

std::string HeuristicConfig::getFilenameMalicious() const
{
	return m_filenameMalicious;
}

std::shared_ptr< DangerousIpConfig > HeuristicConfig::getFilenameConfig() const
{
	return m_filenameConfig;
}

const std::vector< DangerousIpAddr >& HeuristicConfig::getDangerousIpAdresses() const
{
	return m_dangerousIpAdresses;
}

void HeuristicConfig::setSensitivity( float sensitivity )
{
	m_sensitivity = sensitivity;
};

void HeuristicConfig::setEntropy( float entropy )
{
	m_entropy = entropy;
}

void HeuristicConfig::setPacketValue( float packetValue )
{
	m_packetValue = packetValue;
}

void HeuristicConfig::setFilenameMalicious( const std::string& filenameMalicious )
{
	m_filenameMalicious = filenameMalicious;
}

void HeuristicConfig::setFilenameConfig( std::shared_ptr< DangerousIpConfig > filenameConfig )
{
	m_filenameConfig = filenameConfig;
}

void HeuristicConfig::saveAllDangerousIps()
{
	std::ofstream outputFile( "scan_result.csv", std::ios::app );

	if( !m_dangerousIpAdresses.empty() )
	{
		outputFile << std::endl << "----------- ENTER -----------" << std::endl;
	}

	for( const auto& ip : m_dangerousIpAdresses )
	{
		outputFile << ip;
	}
	outputFile.close();
}

void HeuristicConfig::readCSV()
{
	std::ifstream maliciousFile( getFilenameMalicious() );

	if( maliciousFile.bad() )
	{
		std::cout << "ERROR: Where malicious file" << std::endl;
		return;
	}

	loadDangerousIp( maliciousFile );
}

void HeuristicConfig::loadDangerousIp( std::ifstream& file )
{
	for( const auto& row : CSVRange( file ) )
	{
		sockaddr_in ip_addr{ DangerousIpAddr::makeSockaddr( row[ AdressIp ].c_str() ) };

		auto getChar = [ & ]( CsvEncoder whichFlag ) { return row[ whichFlag ].data()[ 0 ]; };

		Parameters::RiskFlag riskFlag( getChar( RiskFlag ) );
		Parameters::AttackType attackTypeFlag( getChar( AttackType ) );
		Parameters::RangeFlag rangeFlag( getChar( RangeFlag ) );
		Parameters::AccessFlag accessFlag( getChar( AccessFlag ) );
		Parameters::AvailabilityFlag avaiabilityFlag( getChar( AvaiabilityFlag ) );

		auto packet_counter	  = std::stoi( row[ Counter ] );
		float network_entropy = std::stod( row[ PacketEntropy ] );

		DangerousIpAddr dangerousIpAddr( ip_addr,
										 riskFlag,
										 attackTypeFlag,
										 rangeFlag,
										 accessFlag,
										 avaiabilityFlag,
										 packet_counter,
										 network_entropy );

		m_dangerousIpAdresses.push_back( dangerousIpAddr );
	}

	if( m_dangerousIpAdresses.empty() )
	{
		std::cout << "ERROR: Where malicious file" << std::endl;
	}
}
