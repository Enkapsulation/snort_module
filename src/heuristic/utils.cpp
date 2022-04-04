#include "utils.hpp"

bool CSVIterator::operator!=( CSVIterator const& rhs )
{
	return !( ( *this ) == rhs );
}
