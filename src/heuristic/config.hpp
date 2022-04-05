#pragma once
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace snort
{
class Value;
}

class DangerousIpConfig;
class DangerousIpAddr;

/* Main policy configuration */
class HeuristicConfig
{
public:
	HeuristicConfig( double sensitivity, double dangerousEntropy, double packetValue, std::string filenameMalicious );

	operator std::string() const;

	bool set( const snort::Value& value );
	static HeuristicConfig getDefaultConfig();

	double getSensitivity() const;
	double getDangerousEntropy() const;
	double getPacketValue() const;
	std::string getFilenameMalicious() const;
	std::shared_ptr< DangerousIpConfig > getFilenameConfig() const;
	const std::vector< DangerousIpAddr >& getDangerousIpAdress() const;

private:
	void setSensitivity( double );
	void setDangerousEntropy( double );
	void setPacketValue( double );
	void setFilenameMalicious( const std::string& );
	void setFilenameConfig( std::shared_ptr< DangerousIpConfig > );
	void setDangerousIpAdress( const std::vector< DangerousIpAddr >& );
	void readCSV();

	static constexpr std::string_view s_sensitivityName{ "sensitivity" };
	static constexpr std::string_view s_dangerousEntropyName{ "dangerous_entropy" };
	static constexpr std::string_view s_packetValueName{ "packet_value" };
	static constexpr std::string_view s_filenameMaliciousName{ "filename_malicious" };

	static constexpr double s_defaultSensitivity{ 20.0 };
	static constexpr double s_defaultDangerousEntropy{ 6.0 };
	static constexpr double s_defaultPacketValue{ 15.0 };
	static constexpr std::string_view s_defaultFilenameMalicious{ "" };

	double m_sensitivity;
	double m_dangerousEntropy;
	double m_packetValue;
	std::string m_filenameMalicious;
	std::shared_ptr< DangerousIpConfig > m_filenameConfig;
	std::vector< DangerousIpAddr > m_dangerousIpAdress;
};