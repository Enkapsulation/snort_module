#pragma once

#include <memory>

#include "detection/detection_engine.h"

// THREAD_LOCAL const Trace* heu_trace = nullptr;

struct HeuristicConfig;

class Heuristic : public snort::Inspector
{
public:
	Heuristic( const std::shared_ptr< HeuristicConfig >& );
	virtual ~Heuristic();

	void show( const snort::SnortConfig* ) const override;
	void eval( snort::Packet* ) override;

private:
	void heuristic_show_config( HeuristicConfig* config ) const;
	void set_default_value( HeuristicConfig* config );

	std::shared_ptr< HeuristicConfig > m_config;
};
