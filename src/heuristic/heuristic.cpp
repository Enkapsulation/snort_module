#include "heuristic.hpp"
#include "config.hpp"
#include "dangerous_ip_addr.hpp"
#include "heuristic_module.hpp"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <iterator>
#include <string>

#include "log/messages.h"

#include "flag_default_value.hpp"
#include "utils.hpp"

using namespace snort;

PegCount Heuristic::m_allPacketCount{ 0 };

void Heuristic::heuristic_show_config( const HeuristicConfig* config ) const
{
	ConfigLogger::log_option( "heuristic" );
	ConfigLogger::log_list( "", std::string( *config ).c_str() );
}

Heuristic::Heuristic( const std::shared_ptr< HeuristicConfig >& config, HeuristicModule* module )
	: m_config( config ), m_module( module )
{
}

Heuristic::~Heuristic() = default;

bool Heuristic::configure( snort::SnortConfig* )
{
	m_allPacketCount = m_config->getInitialCount();
	return true;
}

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

PegCount Heuristic::getPacketsCount() const
{
	return m_allPacketCount;
}

void Heuristic::incrementAllPacketsCounters()
{
	m_module->incrementPacketCounter();
	++m_allPacketCount;
}

float Heuristic::computeFlags( const DangerousIpAddr& dangerousIpAddr ) const
{
	return m_config->getPacketValue() - dangerousIpAddr.getValueAllFlags();
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
	const auto isSenitivityExceeded{ packetValue < m_config->getSensitivity() };
	const auto isEntropyExceeded{ m_config->getEntropy() < dangerousIpAddr.m_networkEntropy };

	if( isSenitivityExceeded || isEntropyExceeded )
	{
		printAttackInfo( clientIp, serverIp, packetValue, dangerousIpAddr );
	}
}

float Heuristic::computeEntropy( double probability ) const
{
	return -( std::log( probability ) / ln2value );
}

float Heuristic::computePacketValue( DangerousIpAddr& dangerousIpAddr ) const
{
	const auto& packetsCount{ getPacketsCount() };
	assert( packetsCount > 0 );

	const auto packetValue{ computeFlags( dangerousIpAddr ) };
	const auto packet_probability{ static_cast< double >( dangerousIpAddr.m_packetCounter )
								   / static_cast< double >( packetsCount ) };

	dangerousIpAddr.m_networkEntropy = computeEntropy( packet_probability );

	return packetValue - Parameters::Default::s_entropyFactor * dangerousIpAddr.m_networkEntropy;
}

void Heuristic::eval( Packet* packet )
{
	incrementAllPacketsCounters();

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
