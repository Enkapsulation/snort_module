#pragma once

namespace defaultValueFlag
{
constexpr double s_defaultRiskHigh{ -3 };
constexpr double s_defaultRiskMedium{ -2 };
constexpr double s_defaultRiskLow{ -1 };

constexpr int s_defaultAttackTypeDDoS{ -5 };
constexpr int s_defaultAttackTypePhishing{ -5 };
constexpr int s_defaultAttackTypeMalware{ -5 };
constexpr int s_defaultAttackTypeRansomware{ -5 };
constexpr int s_defaultAttackTypeDoS{ -5 };

constexpr int s_defaultRangeSingle{ -1 };
constexpr int s_defaultRangePartial{ -2 };
constexpr int s_defaultRangeComplete{ -3 };

constexpr int s_defaultAccessNone{ -2 };
constexpr int s_defaultAccessUser{ -1 };

constexpr int s_defaultAvailabilityNone{ -1 };
constexpr int s_defaultAvailabilityPartial{ -2 };
constexpr int s_defaultAvailabilityComplete{ -4 };

} // namespace defaultValueFlag