#pragma once

namespace Parameters::Default
{
static constexpr double s_highRisk{ -3.0 };
static constexpr double s_mediumRisk{ -2.0 };
static constexpr double s_lowRisk{ -1.0 };

static constexpr int s_AttackTypeDDoS{ -5 };
static constexpr int s_AttackTypePhishing{ -5 };
static constexpr int s_AttackTypeMalware{ -5 };
static constexpr int s_AttackTypeRansomware{ -5 };
static constexpr int s_AttackTypeDoS{ -5 };

static constexpr int s_rangeSingle{ -1 };
static constexpr int s_rangePartial{ -2 };
static constexpr int s_rangeComplete{ -3 };

static constexpr int s_accessNone{ -2 };
static constexpr int s_accessUser{ -1 };

static constexpr int s_availabilityNone{ -1 };
static constexpr int s_availabilityPartial{ -2 };
static constexpr int s_availabilityComplete{ -4 };

} // namespace Parameters::Default