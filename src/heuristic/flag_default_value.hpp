#pragma once

namespace Parameters::Default
{
static constexpr float s_highRisk{ 3.F };
static constexpr float s_mediumRisk{ 2.F };
static constexpr float s_lowRisk{ 1.F };

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

static constexpr float s_riskFlagFactor{ 0.65F };
static constexpr float s_attackTypeFlagFactor{ 1.F - s_riskFlagFactor };
static constexpr float s_entropyFactor{ 0.5F };
} // namespace Parameters::Default