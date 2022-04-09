#include "heuristic.hpp"
#include "config.hpp"
#include "dangerous_ip_addr.hpp"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <iterator>
#include <string>

#include "log/messages.h"

#include "utils.hpp"

using namespace snort;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------
void Heuristic::heuristic_show_config( const HeuristicConfig* config ) const
{
	ConfigLogger::log_option( "heuristic" );
	ConfigLogger::log_list( "", std::string( *config ).c_str() );
}

void Heuristic::set_default_value( HeuristicConfig* config )
{
	( *config ) = HeuristicConfig::getDefaultConfig();
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Heuristic::Heuristic( const std::shared_ptr< HeuristicConfig >& config ) : m_config( config ) {}

Heuristic::~Heuristic() = default;

void Heuristic::show( const SnortConfig* ) const
{
	if( m_config )
	{
		heuristic_show_config( m_config.get() );
	}
}

bool Heuristic::validate( const Packet* packet ) const
{
	if( !packet->flow )
	{
		// LogMessage( "[WARRNING] Packet hasn't flow\n" );
		return false;
	}

	return true;
}

std::string Heuristic::getClientIp( const Packet* packet ) const
{
	char clientIp[ INET6_ADDRSTRLEN ];
	packet->flow->client_ip.ntop( clientIp, sizeof( clientIp ) );

	// LogMessage( "Client IP: %s\n", clientIp );

	return clientIp;
}

std::string Heuristic::getServerIp( const Packet* packet ) const
{
	char serverIp[ INET6_ADDRSTRLEN ];
	packet->flow->server_ip.ntop( serverIp, sizeof( serverIp ) );

	// LogMessage( "Server IP: %s\n", serverIp );

	return serverIp;
}

float Heuristic::computeFlags( const DangerousIpAddr& dangerousIpAddr ) const
{
	auto packetValue{ m_config->getPacketValue() };

	packetValue -= dangerousIpAddr.m_riskFlag.getValue();
	packetValue -= dangerousIpAddr.m_attackType.getValue();
	packetValue -= dangerousIpAddr.m_rangeFlag.getValue();
	packetValue -= dangerousIpAddr.m_accessFlag.getValue();
	packetValue -= dangerousIpAddr.m_availabilityFlag.getValue();

	return packetValue;
}

void Heuristic::printAttackInfo( std::string clientIp,
								 std::string serverIp,
								 const float packetValue,
								 const DangerousIpAddr& dangerousIpAddr ) const
{
	LogMessage( "[FLOW]%s->%s, [ATTACK]:%c, [DANGEROUS]%c, [VALUE]%lf, [ENTROPY]:%lf\n",
				clientIp.c_str(),
				serverIp.c_str(),
				dangerousIpAddr.m_attackType.getIdentifier(),
				dangerousIpAddr.m_riskFlag.getIdentifier(),
				packetValue,
				dangerousIpAddr.m_networkEntropy );
}

void Heuristic::checkThreshold( std::string clientIp,
								std::string serverIp,
								const float packetValue,
								const DangerousIpAddr& dangerousIpAddr ) const
{
	if( packetValue < m_config->getSensitivity() )
	{
		printAttackInfo( clientIp, serverIp, packetValue, dangerousIpAddr );
	}
}

static long long s_allPacketsCount{ 0 };

float Heuristic::computeEntropy( double probability ) const
{
	return -1.0 * ( std::log( probability ) / log2 );
}

float Heuristic::computePacketValue( DangerousIpAddr& dangerousIpAddr ) const
{
	const auto packetValue{ computeFlags( dangerousIpAddr ) };

	const auto packet_probability{ static_cast< double >( dangerousIpAddr.m_packetCounter )
								   / static_cast< double >( s_allPacketsCount ) };

	dangerousIpAddr.m_networkEntropy = computeEntropy( packet_probability );

	return packetValue - 0.5 * dangerousIpAddr.m_networkEntropy;
}

void Heuristic::eval( Packet* packet )
{
	++s_allPacketsCount;

	if( !validate( packet ) )
	{
		return;
	}

	const auto& dangerousIpAdresses{ m_config->getDangerousIpAdresses() };
	const auto clientIp{ getClientIp( packet ) };
	auto searchResult{ m_config->find( clientIp ) };

	if( !searchResult )
	{
		return;
	}

	auto& suspiciousIpAddr{ *searchResult.value() };

	suspiciousIpAddr.incrementCounter();

	checkThreshold( clientIp, getServerIp( packet ), computePacketValue( suspiciousIpAddr ), suspiciousIpAddr );
}
