
#include <functional>

struct ScopeExit
{
	ScopeExit(std::function<void (void)> f) : f_(f) {}
	~ScopeExit(void) { f_(); }
private:
	std::function<void (void)> f_;
};