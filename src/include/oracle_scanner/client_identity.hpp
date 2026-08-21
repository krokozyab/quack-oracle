#pragma once

#include <string>

namespace oracle_scanner {

struct OracleClientIdentity {
    std::string program;
    std::string terminal;
    std::string machine;
    std::string process_id;
    std::string os_user;
};

// Returns an absolute path for the current executable. Oracle listeners can
// require CID.PROGRAM to be path-shaped, so a fixed short driver name is not
// sufficient on all deployments.
std::string CurrentExecutablePath();
OracleClientIdentity CurrentOracleClientIdentity(const std::string &program = {});

} // namespace oracle_scanner
