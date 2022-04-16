#pragma once
#include "dangerous_ip_addr.hpp"
#include <map>
#include <memory>
#include <optional>
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
		DangerousFlag,
		AttackType,
		RangeFlag,
		AccessFlag,
		AvaiabilityFlag,
		Counter,
		PacketEntropy
	};

public:
	HeuristicConfig( float sensitivity, float entropy, float packetValue, std::string filenameMalicious );
	~HeuristicConfig();

	std::optional< DangerousIpAddr* > find( std::string ip ) const;

	operator std::string() const;

	bool set( const snort::Value& value );

	static HeuristicConfig getDefaultConfig();
	float getSensitivity() const;
	float getEntropy() const;
	float getPacketValue() const;
	std::string getFilenameMalicious() const;
	std::shared_ptr< DangerousIpConfig > getFilenameConfig() const;
	const std::vector< DangerousIpAddr >& getDangerousIpAdresses() const;

private:
	using Key	  = std::string;
	using KeyView = std::string_view;

	void setFilenameMalicious( const std::string& );
	void saveAllDangerousIps();
	void readCSV();
	void loadDangerousIp( std::ifstream& );

	float getValueFromParameters( Key key ) const;

	static constexpr KeyView s_sensitivityName{ "sensitivity" };
	static constexpr KeyView s_entropyName{ "entropy" };
	static constexpr KeyView s_packetValueName{ "packet_value" };
	static constexpr KeyView s_filenameMaliciousName{ "filename_malicious" };

	static constexpr float s_defaultSensitivity{ 20.F };
	static constexpr float s_defaultEntropy{ 6.F };
	static constexpr float s_defaultPacketValue{ 15.F };
	static constexpr std::string_view s_defaultFilenameMalicious{ "" };

	std::map< Key, float > m_parameters = { { s_sensitivityName.data(), s_defaultSensitivity },
											{ s_entropyName.data(), s_defaultEntropy },
											{ s_packetValueName.data(), s_defaultPacketValue } };
	std::string m_filenameMalicious;
	std::vector< DangerousIpAddr > m_dangerousIpAdresses;
};
