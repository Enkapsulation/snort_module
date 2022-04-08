#pragma once

#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

/* Shanon entropy */
#define LOG2 0.69314718056
#define ENTROPY( prob ) ( -1 * ( log( prob ) / LOG2 ) )

/* Default value for entropy */
#define NO_SCORE ( double )-1

enum class eRiskFLag : uint8_t
{
	H,
	M,
	L
};

eRiskFLag getRiskFlag( std::string riskFlag );

enum class eAttackTypes : uint8_t
{
	ddos,
	phishing,
	malware,
	ransomware,
	dos,
};

eAttackTypes getAttackFlag( std::string attackFlag );

enum class eRangeFlags : uint8_t
{
	single,
	partial,
	complete
};

eRangeFlags getRangeFlag( std::string rangeFlag );

enum class eAccessFlag : uint8_t
{
	none,
	user
};

eAccessFlag getAccessFlag( std::string accessFlag );

enum class eAvailabilityFlags : uint8_t
{
	none,
	partial,
	complete
};

eAvailabilityFlags getAvailabilityFlags( std::string availabilityFlags );
class DangerousIpAddr
{
public:
	sockaddr_in ip_addr;
	eRiskFLag risk_flag;
	eAttackTypes attack_type;
	eRangeFlags range;
	eAccessFlag access;
	eAvailabilityFlags availability;
	uint64_t packet_counter;
	double network_entropy;

	DangerousIpAddr( sockaddr_in _ip_addr,
					 eAttackTypes _attack_type,
					 eRangeFlags _range,
					 eAccessFlag _access,
					 eAvailabilityFlags _availability,
					 eRiskFLag _risk_flag,
					 uint64_t _packet_counter,
					 double _network_entropy )
		: ip_addr{ _ip_addr },
		  attack_type{ _attack_type },
		  range{ _range },
		  access{ _access },
		  availability{ _availability },
		  risk_flag{ _risk_flag },
		  packet_counter{ _packet_counter },
		  network_entropy{ _network_entropy }
	{
	}

	static sockaddr_in makeSockaddr( std::string ip );
};
