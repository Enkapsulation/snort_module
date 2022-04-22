#include "flag.hpp"

namespace Parameters
{
Flag::Flag( std::string identifier, float value ) : m_value( value ), m_identifier( identifier ){};

Flag::~Flag() = default;

float Flag::getValue() const
{
	return m_value;
}

std::string Flag::getIdentifier() const
{
	return m_identifier;
}
} // namespace Parameters
