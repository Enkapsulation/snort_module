#pragma once

namespace Parameters::Default
{
static constexpr float s_highRisk{ -3.0 };
static constexpr float s_mediumRisk{ -2.0 };
static constexpr float s_lowRisk{ -1.0 };

static constexpr float s_attackTypeDDoS{ -5 };
static constexpr float s_attackTypePhishing{ -5 };
static constexpr float s_attackTypeMalware{ -5 };
static constexpr float s_attackTypeRansomware{ -5 };
static constexpr float s_attackTypeDoS{ -5 };

static constexpr float s_rangeSingle{ -1 };
static constexpr float s_rangePartial{ -2 };
static constexpr float s_rangeComplete{ -3 };

static constexpr float s_accessNone{ -2 };
static constexpr float s_accessUser{ -1 };

static constexpr float s_availabilityNone{ -1 };
static constexpr float s_availabilityPartial{ -2 };
static constexpr float s_availabilityComplete{ -4 };

} // namespace Parameters::Default