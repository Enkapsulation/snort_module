#include "heuristic_inspector.hpp"
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

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------
void Heuristic::showConfig() const
{
	ConfigLogger::log_option( "heuristic" );
	if( m_config )
	{
		ConfigLogger::log_list( "", std::string( *m_config ).c_str() );
	}
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Heuristic::Heuristic( const std::shared_ptr< HeuristicConfig >& config, HeuristicModule* module )
	: m_config( config ), m_module( module )
{
}

Heuristic::~Heuristic() = default;

void Heuristic::show( const SnortConfig* ) const
{
	showConfig();
}

bool Heuristic::validate( const Packet* packet ) const
{
	if( !packet->flow )
	{
		return false;
	}

	return true;
}

std::string Heuristic::getClientIp( const Packet* packet ) const
{
	char clientIp[ INET6_ADDRSTRLEN ];
	packet->flow->client_ip.ntop( clientIp, sizeof( clientIp ) );

	return clientIp;
}

std::string Heuristic::getServerIp( const Packet* packet ) const
{
	char serverIp[ INET6_ADDRSTRLEN ];
	packet->flow->server_ip.ntop( serverIp, sizeof( serverIp ) );

	return serverIp;
}

PegCount Heuristic::getPacketsCount() const
{
	return *m_module->get_counts();
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
	LogMessage( "[FLOW]%s->%s, [ATTACK]:%s, [DANGEROUS]:%s, [VALUE]:%lf, [ENTROPY]:%lf\n",
				clientIp.c_str(),
				serverIp.c_str(),
				dangerousIpAddr.getAttackTypeId().c_str(),
				dangerousIpAddr.getDangerousTypeId().c_str(),
				packetValue,
				dangerousIpAddr.getNetworkEntropy() );
}

void Heuristic::checkThreshold( std::string clientIp,
								std::string serverIp,
								const float packetValue,
								const DangerousIpAddr& dangerousIpAddr ) const
{
	const auto isSenitivityExceeded{ packetValue < m_config->getSensitivity() };
	const auto isEntropyExceeded{ m_config->getEntropy() < dangerousIpAddr.getNetworkEntropy() };

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
	const auto packet_probability{ static_cast< double >( dangerousIpAddr.getPacketCounter() )
								   / static_cast< double >( packetsCount ) };
	const auto networkEntropy{ computeEntropy( packet_probability ) };

	dangerousIpAddr.setNetworkEntropy( networkEntropy );
	return packetValue - Parameters::Default::s_entropyFactor * networkEntropy;
}

void Heuristic::eval( Packet* packet )
{
	if( !Heuristic::initStaus )
	{
		m_config->readCSV();
		Heuristic::initStaus = true;
	}

	m_module->incrementPacketCounter();

	if( !validate( packet ) )
	{
		return;
	}

	const auto clientIp{ getClientIp( packet ) };
	const auto searchResult{ m_config->find( clientIp ) };

	if( !searchResult )
	{
		return;
	}

	auto& suspiciousIpAddr{ *searchResult.value() };

	suspiciousIpAddr.incrementCounter();

	checkThreshold( clientIp, getServerIp( packet ), computePacketValue( suspiciousIpAddr ), suspiciousIpAddr );
}
