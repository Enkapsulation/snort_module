#include <array>
#include <fstream>
#include <iostream>

#include "flag.hpp"
#include "flag_factory.hpp"
#include <arpa/inet.h>
#include <framework/value.h>
#include <iterator>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "utils.hpp"

using namespace Parameters;

HeuristicConfig::HeuristicConfig( float sensitivity, float entropy, float packetValue, std::string filenameMalicious )
	: m_parameters( makeParametersMap( sensitivity, entropy, packetValue ) ),
	  m_filenameMalicious( filenameMalicious ),
	  m_dangerousIpAdresses()
{
}

HeuristicConfig::HeuristicConfig()
	: m_parameters( makeParametersMap( s_defaultSensitivity, s_defaultEntropy, s_defaultPacketValue ) ),
	  m_filenameMalicious( s_defaultFilenameMalicious.data() )
{
}

HeuristicConfig::~HeuristicConfig()
{
	saveAllDangerousIps();
}

HeuristicConfig::FlagCSVHelper HeuristicConfig::m_flagCSVHelper{ { { FlagType::Dangerous, CsvEncoder::DangerousFlag },
																   { FlagType::Range, CsvEncoder::RangeFlag },
																   { FlagType::Attack, CsvEncoder::AttackType },
																   { FlagType::Access, CsvEncoder::AccessFlag },
																   { FlagType::Availability,
																	 CsvEncoder::AvailabilityFlag } } };

std::optional< DangerousIpAddr* > HeuristicConfig::find( std::string ip ) const
{
	const auto ipToCompare{ DangerousIpAddr::makeSockaddr( ip ) };

	auto suspiciousIpAddrIterator
		= std::find_if( m_dangerousIpAdresses.begin(),
						m_dangerousIpAdresses.end(),
						[ & ]( const DangerousIpAddr& dangerousIpAddr )
						{ return dangerousIpAddr.getSockAddr().sin_addr.s_addr == ipToCompare.sin_addr.s_addr; } );

	if( suspiciousIpAddrIterator != m_dangerousIpAdresses.cend() )
	{
		return const_cast< DangerousIpAddr* >( &( *suspiciousIpAddrIterator ) );
	}

	return std::nullopt;
}

HeuristicConfig::operator std::string() const
{
	std::string msg{};

	msg += "{\n sensitivity: " + std::to_string( getSensitivity() ) + "\n";
	msg += " entropy: " + std::to_string( getEntropy() ) + "\n";
	msg += " packet value: " + std::to_string( getPacketValue() ) + "\n";
	msg += " Filename: " + getFilenameMalicious() + "\n}";

	return msg;
}

bool HeuristicConfig::set( const char* rawString, const snort::Value& value )
{
	const auto& valueName{ static_cast< std::string >( value.get_name() ) };
	const auto& fullParam{ static_cast< std::string >( rawString ) };

	if( valueName.empty() )
	{
		return false;
	}

	auto flagType = []( std::string flagIdentifier ) -> std::string
	{
		std::string first  = flagIdentifier.substr( flagIdentifier.find( "." ) + 1 );
		std::string second = first.substr( 0, first.find( "." ) );

		return second;
	};

	if( Parameters::FlagFactory::setFlagsData( flagType( fullParam ), valueName, value.get_real() ) )
	{
		return true;
	}
	if( m_parameters.find( valueName ) != m_parameters.end() )
	{
		m_parameters[ valueName ] = value.get_real();
	}
	else if( valueName == s_filenameMaliciousName )
	{
		setFilenameMalicious( value.get_as_string() );
	}
	else
	{
		return false;
	}

	return true;
}

float HeuristicConfig::getValueFromParameters( HeuristicConfig::Key key ) const
{
	return m_parameters.find( key )->second;
}

float HeuristicConfig::getSensitivity() const
{
	return getValueFromParameters( s_sensitivityName.data() );
}

float HeuristicConfig::getEntropy() const
{
	return getValueFromParameters( s_entropyName.data() );
}

float HeuristicConfig::getPacketValue() const
{
	return getValueFromParameters( s_packetValueName.data() );
}

std::string HeuristicConfig::getFilenameMalicious() const
{
	return m_filenameMalicious;
}

void HeuristicConfig::setFilenameMalicious( const std::string& filenameMalicious )
{
	m_filenameMalicious = filenameMalicious;
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
		printNoFileError();
		return;
	}

	loadDangerousIp( maliciousFile );
}

void HeuristicConfig::printNoFileError() const
{
	std::cout << "ERROR: Where malicious file" << std::endl;
}

std::map< HeuristicConfig::Key, float > HeuristicConfig::makeParametersMap( float sensitivity,
																			float entropy,
																			float packetValue )
{
	return { { s_sensitivityName.data(), sensitivity },
			 { s_entropyName.data(), entropy },
			 { s_packetValueName.data(), packetValue } };
}

void HeuristicConfig::loadDangerousIp( std::ifstream& file )
{
	for( const auto& row : CSVRange( file ) )
	{
		sockaddr_in ip_addr{ DangerousIpAddr::makeSockaddr( row[ AdressIp ].c_str() ) };
		std::vector< Flag > flags;
		flags.reserve( s_flagCount );

		std::string attackId;
		std::string dangerousId;

		for( const auto& flagHelper : m_flagCSVHelper )
		{
			const std::string identifier{ row[ flagHelper.csvEncoder ] };
			const auto flagType{ flagHelper.flagType };

			flags.push_back( FlagFactory::createFlag( flagType, identifier ) );

			if( flagType == FlagType::Attack )
			{
				attackId = identifier;
			}
			else if( flagType == FlagType::Dangerous )
			{
				dangerousId = identifier;
			}
		}

		const auto packet_counter{ std::stoul( row[ Counter ] ) };
		const float network_entropy{ std::stof( row[ PacketEntropy ] ) };

		m_dangerousIpAdresses.push_back( { flags, ip_addr, attackId, dangerousId, packet_counter, network_entropy } );
	}

	if( m_dangerousIpAdresses.empty() )
	{
		printNoFileError();
	}
}
