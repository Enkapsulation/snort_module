#pragma once

#include <memory>

#include "framework/module.h"
#include "heuristic_types.hpp"

extern THREAD_LOCAL SimpleStats asstats;
extern THREAD_LOCAL snort::ProfileStats heuristicPerfStats;

class HeuristicModule : public snort::Module
{
public:
	HeuristicModule( const char* name, const char* help );
	~HeuristicModule() override;

	bool set( const char*, snort::Value&, snort::SnortConfig* ) override;
	bool begin( const char*, int, snort::SnortConfig* ) override;
	bool end( const char*, int, snort::SnortConfig* ) override;

	std::shared_ptr< HeuristicConfig > get_config();

	const PegInfo* get_pegs() const override;
	PegCount* get_counts() const override;

	unsigned get_gid() const override;

	const snort::RuleMap* get_rules() const override;
	snort::ProfileStats* get_profile() const override;

	Usage get_usage() const override;

private:
	std::shared_ptr< HeuristicConfig > m_config;
	static constexpr unsigned s_idHeuristic{ 456U };
};
