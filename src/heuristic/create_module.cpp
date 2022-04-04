#include "create_module.hpp"
#include <memory>

#include "detection/detection_engine.h"
#include "heuristic_module.hpp"

#include <iostream>

using namespace snort;
using namespace Create;

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

void justTest()
{
	auto testModule = HeuristicModule();
	testModule.begin( nullptr, 0, nullptr );
	testModule.testCsv();
}

static Module* mod_ctor()
{
	g_heuristicModule = std::make_unique< HeuristicModule >();
	justTest();
	return g_heuristicModule.get();
}

static void mod_dtor( Module* )
{
	g_heuristicModule.reset();
}

static Inspector* heu_ctor( Module* module )
{
	return g_heuristicModule->getInspector();
}

static void heu_dtor( Inspector* ) {}

static const InspectApi as_api = {
	{ PT_INSPECTOR,
	  sizeof( InspectApi ),
	  INSAPI_VERSION,
	  0,
	  API_RESERVED,
	  API_OPTIONS,
	  HeuristicModule::getName().data(),
	  HeuristicModule::getHelp().data(),
	  mod_ctor,
	  mod_dtor },
	IT_NETWORK,
	PROTO_BIT__ALL,
	nullptr, // buffers
	nullptr, // service
	nullptr, // pinit
	nullptr, // pterm
	nullptr, // tinit
	nullptr, // tterm
	heu_ctor,
	heu_dtor,
	nullptr, // ssn
	nullptr, // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] = { &as_api.base, nullptr };
