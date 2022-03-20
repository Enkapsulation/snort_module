#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <array>
#include <memory>
#include <string>
#include <vector>
#include <map>

#define GENERATOR_SPP_HEURISTIC 256
#define HEURISTIC_BRUTEFORECE_DETECT 1

/* Shanon entropy */
#define LOG2 0.69314718056
#define ENTROPY( prob ) ( -1 * ( log( prob ) / LOG2 ) )

/* Default value for entropy */
#define NO_SCORE ( double )-1

/*  number of flag types */
#define NUM_OF_FLAGS 3
#define NUM_OF_ATTACK 6
#define NUM_OF_RANGE 3
#define NUM_OF_ACCESS 2
#define NUM_OF_AVAILABILITY 3

enum class RiskFLag : uint8_t
{
	H,
	M,
	L
};

RiskFLag GetRiskFlag( std::string riskFlag );

enum class AttackTypes : uint8_t
{
	ddos,
	phishing,
	malware,
	ransomware,
	dos,
};

AttackTypes getAttackFlag( std::string attackFlag );

enum class RangeFlags : uint8_t
{
	single,
	partial,
	complete
};

RangeFlags getRangeFlag( std::string rangeFlag );

enum class AccessFlag : uint8_t
{
	none,
	user
};

AccessFlag getAccessFlag( std::string accessFlag );

enum class AvailabilityFlags : uint8_t
{
	none,
	partial,
	complete
};

AvailabilityFlags getAvailabilityFlags( std::string availabilityFlags );

/*============================================================================*\
* Local variables
\*============================================================================*/

/*===========================[Heurstic structure]===========================*/

/* Structre define file config for subpreprocessor */
struct DangerousIPConfig
{
	std::array< int, NUM_OF_FLAGS > flags_score;
	std::array< int, NUM_OF_ATTACK > attack_score;
	std::array< int, NUM_OF_RANGE > range_score;
	std::array< int, NUM_OF_ACCESS > access_score;
	std::array< int, NUM_OF_AVAILABILITY > availability_score;
};

/*===========================[Dangerous ip]===========================*/
struct DangerousIpAddr
{
	std::string hash; /* change types if needed */
	sockaddr_in ip_addr;
	RiskFLag risk_flag;
	AttackTypes attack_type;
	RangeFlags range;
	AccessFlag access;
	AvailabilityFlags availability;
	uint64_t counter;
	double network_entropy;

	DangerousIpAddr( sockaddr_in _ip_addr,
					 AttackTypes _attack_type,
					 RangeFlags _range,
					 AccessFlag _access,
					 AvailabilityFlags _availability,
					 RiskFLag _risk_flag,
					 uint64_t _counter,
					 double _network_entropy )
		: ip_addr{ _ip_addr },
		  attack_type{ _attack_type },
		  range{ _range },
		  access{ _access },
		  availability{ _availability },
		  risk_flag{ _risk_flag },
		  counter{ _counter },
		  network_entropy{ _network_entropy }
	{
	}
};

/* Main policy configuration */
struct HeuristicConfig
{
	double sensitivity;
	double dangerous_entropy;
	double packet_value;
	std::string filename_malicious;
	std::shared_ptr< DangerousIPConfig > filename_config;
	std::vector< DangerousIpAddr > dangerousIpAdress;

	HeuristicConfig( double _sensitivity,
					 double _dangerous_entropy,
					 double _packet_value,
					 std::string _filename_malicious )
		: sensitivity{ _sensitivity },
		  dangerous_entropy{ _dangerous_entropy },
		  packet_value{ _packet_value },
		  filename_malicious{ _filename_malicious }
	{
	}
};

/*===========================[linked list]===========================*/

/* Double linked list structure */
struct LinkedList
{
	LinkedList* next; // Previus item on the linked list
	double entropy;
	in_addr ip_addr;
	uint64_t count;
};

/*===========================[Error enum]===========================*/
enum ParseStatus
{
	STATUS_OK	 = 0,
	STATUS_ERROR = 1
};
