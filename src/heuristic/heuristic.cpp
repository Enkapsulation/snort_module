#include "heuristic.hpp"
#include "heuristic_types.hpp"

#include <iostream>

#include "log/messages.h"

using namespace snort;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------
void Heuristic::heuristic_show_config( HeuristicConfig* config ) const
{
	std::string msg;
	ConfigLogger::log_option( "heuristic" );

	msg += "{ sensitivity: " + std::to_string( config->sensitivity ) + "\n";
	msg += " entropy: " + std::to_string( config->dangerous_entropy ) + "\n";
	msg += " default packet value: " + std::to_string( config->packet_value ) + "\n";
	msg += " Filename: " + config->filename_malicious + "}";
	ConfigLogger::log_list( "", msg.c_str() );
}

void Heuristic::set_default_value( HeuristicConfig* config )
{
	/* Init default sensitivity */
	config->sensitivity = 15.0;

	/* Init default entropy */
	config->dangerous_entropy = 6.0;

	/* Init default packet value */
	config->packet_value = 20.0;

	// /* Init default score flags */
	// config->filename_config->flags_score[ H_FLAGS ] = -3;
	// config->filename_config->flags_score[ M_FLAGS ] = -2;
	// config->filename_config->flags_score[ L_FLAGS ] = -1;

	// /* Default attack score */
	// config->filename_config->attack_score[ DDOS ]		 = -5;
	// config->filename_config->attack_score[ PHISING ]	 = -5;
	// config->filename_config->attack_score[ MALWARE ]	 = -5;
	// config->filename_config->attack_score[ RANSOMEWARE ] = -5;
	// config->filename_config->attack_score[ DoS ]		 = -5;
	// config->filename_config->attack_score[ XSS ]		 = -5;

	// /* Default range score */
	// config->filename_config->range_score[ SINGLE ]	 = -1;
	// config->filename_config->range_score[ PARTIAL ]	 = -2;
	// config->filename_config->range_score[ COMPLETE ] = -3;

	// /* Default Access score */
	// config->filename_config->access_score[ NONE ] = -2;
	// config->filename_config->access_score[ USER ] = -1;

	// /* Default Availability score */
	// config->filename_config->availability_score[ NONE ]		= -1;
	// config->filename_config->availability_score[ PARTIAL ]	= -2;
	// config->filename_config->availability_score[ COMPLETE ] = -4;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Heuristic::Heuristic( const std::shared_ptr< HeuristicConfig >& config ) : m_config( config ) {}

Heuristic::~Heuristic() = default;

void Heuristic::show( const SnortConfig* config ) const
{
	if( config )
	{
		heuristic_show_config( ( HeuristicConfig* )config );
	}
}

void Heuristic::eval( Packet* pkt )
{
	std::cout << "Hello World from -> " << pkt->is_icmp() << std::endl;

	// char src_addr[ 500 ];
	// char dst_addr[ 500 ];
	// int result				  = -1;
	// double packet_probability = 0.0;

	/* Log */
	// std::string_view type_attack;

	/* transfer start packet value */
	// double ranking = config->packet_value;

	// if( ( nullptr == config ) )
	// {
	// 	LogMessage( "[ERROR] config is NULL" );
	// 	return;
	// }
	// else if( ( false == pkt->has_ip_hdr() ) )
	// {
	// 	return;
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
