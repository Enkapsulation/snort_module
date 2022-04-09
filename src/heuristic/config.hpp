#pragma once
#include "dangerous_ip_addr.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace snort
{
class Value;
}

class DangerousIpConfig;

/* Main policy configuration */
class HeuristicConfig
{
	enum CsvEncoder
	{
		AdressIp,
		RiskFlag,
		AttackType,
		RangeFlag,
		AccessFlag,
		AvaiabilityFlag,
		Counter,
		PacketEntropy
	};

public:
	HeuristicConfig( float sensitivity, float dangerousEntropy, float packetValue, std::string filenameMalicious );

	operator std::string() const;

	bool set( const snort::Value& value );
	static HeuristicConfig getDefaultConfig();

	float getSensitivity() const;
	float getDangerousEntropy() const;
	float getPacketValue() const;
	std::string getFilenameMalicious() const;
	std::shared_ptr< DangerousIpConfig > getFilenameConfig() const;
	const std::vector< DangerousIpAddr >& getDangerousIpAdresses() const;

private:
	void setSensitivity( float );
	void setDangerousEntropy( float );
	void setPacketValue( float );
	void setFilenameMalicious( const std::string& );
	void setFilenameConfig( std::shared_ptr< DangerousIpConfig > );
	void readCSV();
	void loadDangerousIp( std::ifstream& );

	static constexpr std::string_view s_sensitivityName{ "sensitivity" };
	static constexpr std::string_view s_dangerousEntropyName{ "dangerous_entropy" };
	static constexpr std::string_view s_packetValueName{ "packet_value" };
	static constexpr std::string_view s_filenameMaliciousName{ "filename_malicious" };

	static constexpr float s_defaultSensitivity{ 20.0 };
	static constexpr float s_defaultDangerousEntropy{ 6.0 };
	static constexpr float s_defaultPacketValue{ 15.0 };
	static constexpr std::string_view s_defaultFilenameMalicious{ "" };

	float m_sensitivity;
	float m_dangerousEntropy;
	float m_packetValue;
	std::string m_filenameMalicious;
	std::shared_ptr< DangerousIpConfig > m_filenameConfig;
	std::vector< DangerousIpAddr > m_dangerousIpAdresses;
};
