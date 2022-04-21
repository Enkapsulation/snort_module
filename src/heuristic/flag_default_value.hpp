#pragma once
#include <string>

namespace Parameters
{
namespace Default
{
static constexpr float s_dangerousHigh{ 3.F };
static constexpr float s_dangerousMedium{ 2.F };
static constexpr float s_dangerousLow{ 1.F };

static constexpr float s_attackTypeDDoS{ 5.F };
static constexpr float s_attackTypePhishing{ 5.F };
static constexpr float s_attackTypeMalware{ 5.F };
static constexpr float s_attackTypeRansomware{ 5.F };
static constexpr float s_attackTypeDoS{ 5.F };

static constexpr float s_rangeSingle{ 1.F };
static constexpr float s_rangePartial{ 2.F };
static constexpr float s_rangeComplete{ 3.F };

static constexpr float s_accessNone{ 2.F };
static constexpr float s_accessUser{ 1.F };

static constexpr float s_availabilityNone{ 1.F };
static constexpr float s_availabilityPartial{ 2.F };
static constexpr float s_availabilityComplete{ 4.F };

static constexpr float s_dangerousFlagFactor{ 0.65F };
static constexpr float s_attackTypeFlagFactor{ 1.F - s_dangerousFlagFactor };
static constexpr float s_entropyFactor{ 0.5F };
} // namespace Default

namespace Name
{
static constexpr std::string_view s_sensitivityName{ "sensitivity" };
static constexpr std::string_view s_entropyName{ "entropy" };
static constexpr std::string_view s_packetValueName{ "packet_value" };
static constexpr std::string_view s_filenameMaliciousName{ "filename_malicious" };
static constexpr std::string_view s_dangerousName{ "dangerous" };
static constexpr std::string_view s_attackName{ "attack" };
static constexpr std::string_view s_rangeName{ "range" };
static constexpr std::string_view s_accessName{ "access" };
static constexpr std::string_view s_availabilityName{ "availability" };
} // namespace Name

} // namespace Parameters