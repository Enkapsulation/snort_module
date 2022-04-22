#pragma once

#include <map>
#include <string>
namespace Parameters
{
class Flag
{
public:
	explicit Flag( std::string identifier, float value );
	~Flag();

	float getValue() const;
	std::string getIdentifier() const;

protected:
	float m_value;
	std::string m_identifier;
};
} // namespace Parameters
