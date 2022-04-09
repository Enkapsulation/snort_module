#pragma once

#include <memory>

#include "detection/detection_engine.h"

class DangerousIpAddr;
class HeuristicConfig;

class Heuristic : public snort::Inspector
{
public:
	Heuristic( const std::shared_ptr< HeuristicConfig >& );
	virtual ~Heuristic();

	void show( const snort::SnortConfig* ) const override;
	void eval( snort::Packet* ) override;

private:
	void heuristic_show_config( const HeuristicConfig* config ) const;
	void set_default_value( HeuristicConfig* config );

	float computeFlags( const DangerousIpAddr& dangerousIpAddr ) const;
	void checkThreshold( std::string clientIp,
						 std::string serverIp,
						 const float packetValue,
						 const DangerousIpAddr& dangerousIpAddr ) const;

	void printAttackInfo( std::string clientIp,
						  std::string serverIp,
						  const float packetValue,
						  const DangerousIpAddr& dangerousIpAddr ) const;

	std::string getClientIp( const snort::Packet* packet ) const;
	std::string getServerIp( const snort::Packet* packet ) const;
	bool validate( const snort::Packet* packet ) const;

	std::shared_ptr< HeuristicConfig > m_config;
};
