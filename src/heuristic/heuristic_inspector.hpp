#pragma once

#include <memory>

#include <detection/detection_engine.h>
#include <snort/framework/counts.h>

class DangerousIpAddr;
class HeuristicConfig;
class HeuristicModule;

class Heuristic : public snort::Inspector
{
public:
	Heuristic( const std::shared_ptr< HeuristicConfig >&, HeuristicModule* );
	virtual ~Heuristic();

	void show( const snort::SnortConfig* ) const override;
	void eval( snort::Packet* ) override;

private:
	void showConfig() const;
	float computeFlags( const DangerousIpAddr& dangerousIpAddr ) const;
	float computeEntropy( double probability ) const;
	float computePacketValue( DangerousIpAddr& dangerousIpAddr ) const;

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
	PegCount getPacketsCount() const;
	bool validate( const snort::Packet* packet ) const;

	std::shared_ptr< HeuristicConfig > m_config;
	HeuristicModule* m_module{ nullptr };
	bool m_initStaus{ false };

	static constexpr double ln2value{ 0.69314718056 };
};
