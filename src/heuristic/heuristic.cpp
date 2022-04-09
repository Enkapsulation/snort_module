#include "heuristic.hpp"
#include "config.hpp"
#include "dangerous_ip_addr.hpp"

#include <algorithm>
#include <iostream>
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
		LogMessage( "[WARRNING] Packet hasn't flow\n" );
		return false;
	}

	return true;
}

std::string Heuristic::getClientIp( const Packet* packet ) const
{
	char clientIp[ INET6_ADDRSTRLEN ];
	packet->flow->client_ip.ntop( clientIp, sizeof( clientIp ) );

	LogMessage( "Client IP: %s\n", clientIp );

	return clientIp;
}

void Heuristic::eval( Packet* packet )
{
	if( !validate( packet ) )
	{
		return;
	}

	const auto& dangerousIpAdresses{ m_config->getDangerousIpAdresses() };
	const auto ipToCompare{ DangerousIpAddr::makeSockaddr( getClientIp( packet ) ) };

	const auto& found
		= std::find_if( dangerousIpAdresses.begin(),
						dangerousIpAdresses.end(),
						[ & ]( const DangerousIpAddr& dangerousIpAddr )
						{ return dangerousIpAddr.m_ipAddr.sin_addr.s_addr == ipToCompare.sin_addr.s_addr; } );

	if( found != dangerousIpAdresses.cend() )
	{
		LogMessage( "GOT IT\n" );
	}
}
