#pragma once
#include "dangerous_ip_addr.hpp"
#include "parameters_name.hpp"
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
		AvailabilityFlag,
		Counter,
		PacketEntropy
	};

	struct FlagCSV
	{
		Parameters::FlagType flagType;
		CsvEncoder csvEncoder;
	};

public:
	HeuristicConfig();
	HeuristicConfig( float sensitivity, float entropy, float packetValue, std::string filenameMalicious );
	~HeuristicConfig();

	std::optional< DangerousIpAddr* > find( std::string ip ) const;

	operator std::string() const;

	bool set( const char* rawString, const snort::Value& value );

	float getSensitivity() const;
	float getEntropy() const;
	float getPacketValue() const;
	std::string getFilenameMalicious() const;
	void readCSV();

private:
	using Key	  = std::string;
	using KeyView = std::string_view;
	static constexpr size_t s_flagCount{ 5U };
	using FlagCSVHelper = const std::array< FlagCSV, s_flagCount >;

	void printNoFileError() const;
	std::map< Key, float > makeParametersMap( float sensitivity, float entropy, float packetValue );

	void setFilenameMalicious( const std::string& );
	void saveAllDangerousIps();
	void loadDangerousIp( std::ifstream& );

	float getValueFromParameters( const Key& key ) const;

	static constexpr std::string_view s_resultFilename{ "scan_result.csv" };

	static constexpr float s_defaultSensitivity{ 20.F };
	static constexpr float s_defaultEntropy{ 6.F };
	static constexpr float s_defaultPacketValue{ 15.F };
	static constexpr std::string_view s_defaultFilenameMalicious{ "" };

	static FlagCSVHelper m_flagCSVHelper;

	std::map< Key, float > m_parameters;
	std::string m_filenameMalicious;
	std::vector< DangerousIpAddr > m_dangerousIpAdresses;
};
