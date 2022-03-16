#ifndef HEURISTIC_MODULE_H
#define HEURISTIC_MODULE_H

#include "framework/module.h"
#include "heuristic_types.hpp"
#include <memory>

static const char* s_name = "heuristic";
static const char* s_help = "detection based on heuristic rules";

const int gid_heuristic = 456;

extern THREAD_LOCAL SimpleStats asstats;
extern THREAD_LOCAL snort::ProfileStats heuristicPerfStats;

class HeuristicModule : public snort::Module
{
private:
	std::shared_ptr< HeuristicConfig > config;

public:
	HeuristicModule();
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
};

#endif /* HEURISTIC_MODULE_H */