#include "heuristic_module.hpp"
#include <memory>
#include "utils.hpp"

// THREAD_LOCAL SimpleStats asstats;

using namespace snort;

//-------------------------------------------------------------------------
// heurstic stuff
//-------------------------------------------------------------------------
static const Parameter heuristic_params[] = {{"sensitivity", Parameter::PT_REAL, nullptr, nullptr, "detection threshold"},
                                             {"entropy", Parameter::PT_REAL, nullptr, nullptr, "packet entropy threshold"},
                                             {"packet_value", Parameter::PT_REAL, nullptr, nullptr, "start packet value"},
                                             {"filename_malicious", Parameter::PT_STRING, nullptr, nullptr, "Path to .CSV with malicius IP address"},

                                             {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const Parameter s_params[] = {{"configuration", Parameter::PT_LIST, heuristic_params, nullptr, "heursitic configuration"},
                                     {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const RuleMap s_rules[] = {{1, "Jeszcze jak"}, {0, nullptr}};

//-------------------------------------------------------------------------
// arp_spoof module
//-------------------------------------------------------------------------
HeuristicModule::HeuristicModule() : Module(s_name, s_help, s_params), config(nullptr) {}

HeuristicModule::~HeuristicModule() = default;

const RuleMap *HeuristicModule::get_rules() const
{
    return s_rules;
}

ProfileStats *HeuristicModule::get_profile() const
{
    return &heuristicPerfStats;
}

bool HeuristicModule::set(const char *, Value &v, SnortConfig *)
{
    if (v.is("sensitivity"))
    {
        config->sensitivity = v.get_real();
    }
    else if (v.is("dangerous_entropy"))
    {
        config->dangerous_entropy = v.get_real();
    }
    else if (v.is("packet_value"))
    {
        config->packet_value = v.get_real();
    }
    else if (v.is("filename_malicious"))
    {
        config->filename_malicious = v.get_as_string();
    }
    else
    {
        return false;
    }

    return true;
}

bool HeuristicModule::begin(const char *, int, SnortConfig *)
{
    if (!config)
    {
        /* Set default vaule */
        double defaultSensitivity = 20.0;
        double defaultDangerousEntropy = 6.0;
        double defaultPacketValue = 15.0;
        std::string defaultFilenameMalicious = "";

        config = std::make_shared<HeuristicConfig>(defaultSensitivity, defaultDangerousEntropy, defaultPacketValue, defaultFilenameMalicious);
    }

    return true;
}

bool HeuristicModule::end(const char *, int idx, SnortConfig *)
{
    // if ( !config )
    // {
    //     config = new HeuristicConfig();
    // }
    return true;
}

std::shared_ptr<HeuristicConfig> HeuristicModule::get_config()
{
    std::shared_ptr<HeuristicConfig> temp = config;
    config = nullptr;
    return temp;
}

const PegInfo *HeuristicModule::get_pegs() const
{
    return simple_pegs;
}

PegCount *HeuristicModule::get_counts() const
{
    return (PegCount *)&asstats;
}

unsigned HeuristicModule::get_gid() const
{
    return gid_heuristic;
}

HeuristicModule::Usage HeuristicModule::get_usage() const
{
    return INSPECT;
}