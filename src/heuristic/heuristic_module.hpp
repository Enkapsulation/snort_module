#pragma once

#include "framework/module.h"
#include "profiler/profiler.h"
#include <memory>
#include <string_view>

class Heuristic;
class HeuristicConfig;

namespace snort
{
class Inspector;
}
class HeuristicModule : public snort::Module
{
public:
	HeuristicModule();
	~HeuristicModule() override;

	bool set( const char*, snort::Value&, snort::SnortConfig* ) override;
	bool begin( const char*, int, snort::SnortConfig* ) override;
	bool end( const char*, int, snort::SnortConfig* ) override;

	void incrementPacketCounter();

	std::shared_ptr< HeuristicConfig > get_config() const;

	const PegInfo* get_pegs() const override;
	PegCount* get_counts() const override;

	unsigned get_gid() const override;

	const snort::RuleMap* get_rules() const override;
	snort::ProfileStats* get_profile() const override;

	Usage get_usage() const override;

	void setInspector( Heuristic* );

	static std::string_view getName();
	static std::string_view getHelp();

private:
	std::shared_ptr< HeuristicConfig > m_config;
	Heuristic* m_inspector{ nullptr };

	static constexpr std::string_view s_name{ "heuristic" };
	static constexpr std::string_view s_help{ "detection based on heuristic rules" };

	static constexpr unsigned s_idHeuristic{ 456U };
};
