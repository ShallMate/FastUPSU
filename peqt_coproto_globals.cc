#include <mutex>
#include <string>
#include <vector>

namespace coproto {

std::mutex ggMtx;
std::vector<std::string> ggLog;

}
