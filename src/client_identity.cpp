#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <string>
#include <vector>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#elif defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
// Same reason as openssl_stream.cpp: these headers define min and max as
// macros unless told not to.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace oracle_scanner {

std::string CurrentExecutablePath() {
#if defined(__APPLE__)
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not determine current executable path");
    }
    std::vector<char> path(size);
    if (_NSGetExecutablePath(path.data(), &size) != 0) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not determine current executable path");
    }
    char resolved[PATH_MAX];
    if (!realpath(path.data(), resolved)) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not resolve current executable path");
    }
    return resolved;
#elif defined(__linux__)
    std::vector<char> path(PATH_MAX);
    const auto size = readlink("/proc/self/exe", path.data(), path.size() - 1);
    if (size <= 0 || static_cast<size_t>(size) >= path.size() - 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not determine current executable path");
    }
    path[static_cast<size_t>(size)] = '\0';
    return path.data();
#elif defined(_WIN32)
    std::vector<char> path(32768);
    const auto size = GetModuleFileNameA(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (size == 0 || size >= path.size()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not determine current executable path");
    }
    return std::string(path.data(), size);
#else
    throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "current executable path is unsupported on this platform");
#endif
}

OracleClientIdentity CurrentOracleClientIdentity(const std::string &program) {
    OracleClientIdentity result;
    result.program = program.empty() ? CurrentExecutablePath() : program;
    // Thin's AUTH_PHASE_ONE capture sends this literal, independent of the
    // caller's shell.  Leaking TERM changes the protocol value and makes the
    // wire persona diverge from the negotiated python-oracledb profile.
    result.terminal = "unknown";
    if (const auto user = std::getenv("USER")) {
        result.os_user = user;
    }
    if (result.os_user.empty()) {
        result.os_user = "oracle_scanner";
    }
#if defined(__APPLE__) || defined(__linux__)
    char hostname[256] = {};
    if (gethostname(hostname, sizeof(hostname) - 1) != 0 || hostname[0] == '\0') {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not determine Oracle client host name");
    }
    result.machine = hostname;
    result.process_id = std::to_string(static_cast<unsigned long>(getpid()));
#elif defined(_WIN32)
    char hostname[256] = {};
    DWORD hostname_size = sizeof(hostname);
    if (!GetComputerNameA(hostname, &hostname_size) || hostname[0] == '\0') {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not determine Oracle client host name");
    }
    result.machine = hostname;
    result.process_id = std::to_string(static_cast<unsigned long>(GetCurrentProcessId()));
#else
    throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle client identity is unsupported on this platform");
#endif
    return result;
}

} // namespace oracle_scanner
