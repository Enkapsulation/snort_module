#include "heuristic.hpp"
#include "config.hpp"
#include "heuristic_types.hpp"

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

	const auto& found = std::find_if( dangerousIpAdresses.begin(),
									  dangerousIpAdresses.end(),
									  [ & ]( const DangerousIpAddr& dangerousIpAddr ) {
										  return dangerousIpAddr.ip_addr.sin_addr.s_addr == ipToCompare.sin_addr.s_addr;
									  } );

	if( found != dangerousIpAdresses.cend() )
	{
		LogMessage( "GOT IT\n" );
	}

	// char cli_ip_str[ INET6_ADDRSTRLEN ];
	// pkt->flow->client_ip.ntop( cli_ip_str, sizeof( cli_ip_str ) );

	// const auto packetClientAddr{ packet->flow->client_ip.get_ip4_value() };
	// LogMessage( " Packet client addr %c\n", cli_ip_str );
	// std::cout << "Packet addr " << cli_ip_str << std::endl;
	// }
	// else
	// {
	// 	if( pkt->is_ip4() )
	// 	{
	/* Get dst and src IP addr */
	// SnortSnprintf( src_addr, 500, inet_ntoa( GET_SRC_IP( pkt ) ) );
	// SnortSnprintf( dst_addr, 500, inet_ntoa( GET_DST_IP( pkt ) ) );

	// result = binarySearch( dangerous_ip_record, 0, config->record_number - 1, GET_SRC_IPv4( pkt ) );

	// if( -1 != result )
	// {
	// 	switch( dangerous_ip_record[ result ].attack_type )
	// 	{
	// 	case DDOS:
	// 		type_attack = "DDoS";
	// 		ranking += ( ATTACK_TYPE_FACTOR * ( config->filename_config->attack_score[ DDOS ] ) );
	// 		break;
	// 	case PHISING:
	// 		type_attack = "Phising";
	// 		ranking += ( ATTACK_TYPE_FACTOR * ( config->filename_config->attack_score[ PHISING ] ) );
	// 		break;
	// 	case MALWARE:
	// 		type_attack = "Malware";
	// 		ranking += ( ATTACK_TYPE_FACTOR * ( config->filename_config->attack_score[ MALWARE ] ) );
	// 		break;
	// 	case RANSOMEWARE:
	// 		type_attack = "Ransomware";
	// 		ranking += ( ATTACK_TYPE_FACTOR * ( config->filename_config->attack_score[ RANSOMEWARE ] ) );
	// 		break;
	// 	case DoS:
	// 		type_attack = "DoS";
	// 		ranking += ( ATTACK_TYPE_FACTOR * ( config->filename_config->attack_score[ DoS ] ) );
	// 		break;
	// 	case XSS:
	// 		type_attack = "XSS";
	// 		ranking += ( ATTACK_TYPE_FACTOR * ( config->filename_config->attack_score[ XSS ] ) );
	// 	case 'L':
	// 		ranking += ( FLAG_FACTOR * ( config->filename_config->flags_score[ L_FLAGS ] ) );
	// 		break;
	// 	default:
	// 		break;
	// 	}

	// 	switch( dangerous_ip_record[ result ].range )
	// 	{
	// 	case SINGLE:
	// 		ranking += config->filename_config->range_score[ SINGLE ];
	// 		break;
	// 	case PARTIAL:
	// 		ranking += config->filename_config->range_score[ PARTIAL ];
	// 		break;
	// 	case COMPLETE:
	// 		ranking += config->filename_config->range_score[ COMPLETE ];
	// 		break;
	// 	default:
	// 		break;
	// 	}

	// 	switch( dangerous_ip_record[ result ].access )
	// 	{
	// 	case NONE:
	// 		ranking += config->filename_config->access_score[ NONE ];
	// 		break;
	// 	case USER:
	// 		ranking += config->filename_config->access_score[ USER ];
	// 		break;
	// 	default:
	// 		break;
	// 	}

	// 	switch( dangerous_ip_record[ result ].availability )
	// 	{
	// 	case SINGLE:
	// 		ranking += config->filename_config->availability_score[ NONE ];
	// 		break;
	// 	case PARTIAL:
	// 		ranking += config->filename_config->availability_score[ PARTIAL ];
	// 		break;
	// 	case COMPLETE:
	// 		ranking += config->filename_config->availability_score[ COMPLETE ];
	// 		break;
	// 	default:
	// 		break;
	// 	}				switch( dangerous_ip_record[ result ].flag )
	// 	{
	// 	case 'H':
	// 		ranking += ( FLAG_FACTOR * ( config->filename_config->flags_score[ H_FLAGS ] ) );
	// 		break;
	// 	case 'M':
	// 		ranking += ( FLAG_FACTOR * ( config->filename_config->flags_score[ M_FLAGS ] ) );
	// 		break;
	// 	case 'L':
	// 		ranking += ( FLAG_FACTOR * ( config->filename_config->flags_score[ L_FLAGS ] ) );
	// 		break;
	// 	default:
	// 		break;
	// 	}

	// 	switch( dangerous_ip_record[ result ].range )
	// 	{
	// 	case SINGLE:
	// 		ranking += config->filename_config->range_score[ SINGLE ];
	// 		break;
	// 	case PARTIAL:
	// 		ranking += config->filename_config->range_score[ PARTIAL ];
	// 		break;
	// 	case COMPLETE:
	// 		ranking += config->filename_config->range_score[ COMPLETE ];
	// 		break;
	// 	default:
	// 		break;
	// 	}

	// 	switch( dangerous_ip_record[ result ].access )
	// 	{
	// 	case NONE:
	// 		ranking += config->filename_config->access_score[ NONE ];
	// 		break;
	// 	case USER:
	// 		ranking += config->filename_config->access_score[ USER ];
	// 		break;
	// 	default:
	// 		break;
	// 	}

	// 	switch( dangerous_ip_record[ result ].availability )
	// 	{
	// 	case SINGLE:
	// 		ranking += config->filename_config->availability_score[ NONE ];
	// 		break;
	// 	case PARTIAL:
	// 		ranking += config->filename_config->availability_score[ PARTIAL ];
	// 		break;
	// 	case COMPLETE:
	// 		ranking += config->filename_config->availability_score[ COMPLETE ];
	// 		break;
	// 	default:
	// 		break;
	// 	}

	/* Probability */
	// dangerous_ip_record[ result ].counter += 1;
	// packet_probability
	// 	= ( ( double )( dangerous_ip_record[ result ].counter ) / ( ( double )pc.total_from_daq ) );
	// dangerous_ip_record[ result ].network_entropy = ENTROPY( packet_probability );

	/* Entoropy */
	// ranking -= ( 0.5 * ( dangerous_ip_record[ result ].network_entropy ) );

	// if( ( config->sensitivity > ranking )
	// 	|| ( config->dangerous_entropy < dangerous_ip_record[ result ].network_entropy ) )
	// {
	// 	LogMessage( "[%d][%d][FLOW]%s->%s, [ATTACK]:%s, [DANGEROUS]%c, [VALUE]%lf, [ENTROPY]:%lf\n",
	// 				pc.total_from_daq,
	// 				pc.ip,
	// 				src_addr,
	// 				dst_addr,
	// 				GET_SRC_IPv4 type_attack,
	// 				dangerous_ip_record[ result ].flag,
	// 				ranking,
	// 				dangerous_ip_record[ result ].network_entropy );
	// }
	// 		}
	// 	}
	// }

	/* co 1000 pakietów aktualizuj raporty */
	// if( ( 0 == pc.total_from_daq % 1000 ) )
	// {
	// 	LogMessage( "[SAVE]\n" );
	// 	write_structure_csv( config, dangerous_ip_record );
	// }
}
