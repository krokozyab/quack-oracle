#include "oracle_scanner/ttc_o5logon.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_error.hpp"

#include <map>

namespace oracle_scanner {

O5LogonResponse RunO5Logon(TtcChannel &channel, const O5LogonRequest &request) {
    if (request.username.empty() || request.username.size() > 252 || request.password.empty() ||
        request.client_session_key.size() != 32 || request.password_salt.size() != 16 || request.speedy_key_salt.size() != 16) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON request is incomplete");
    }
    channel.Send(EncodeTtcAuthFunction(TTC_FUNCTION_AUTH_PHASE_ONE, 1, request.username, request.auth_mode,
                                       request.phase_one_parameters));
    auto challenge_response = channel.Receive();
    if (IsTtcErrorMessage(challenge_response)) {
        ThrowTtcServerError(challenge_response);
    }
    auto challenge = O5LogonChallengeFromParameters(DecodeTtcParameters(challenge_response));
    auto response = BuildO5LogonResponse(request.password, challenge, request.client_session_key, request.password_salt,
                                         request.speedy_key_salt);
    auto phase_two_parameters = BuildO5LogonPhaseTwoParameters(response);
    // This order matches the direct successful Thin capture: key material and
    // password proof precede session metadata.
    phase_two_parameters.insert(phase_two_parameters.end(), request.phase_two_parameters.begin(),
                                request.phase_two_parameters.end());
    channel.Send(EncodeTtcAuthFunction(TTC_FUNCTION_AUTH_PHASE_TWO, 2, request.username, 0x0101,
                                       phase_two_parameters));

    auto proof_response = channel.Receive();
    if (IsTtcErrorMessage(proof_response)) {
        ThrowTtcServerError(proof_response);
    }
    std::map<std::string, std::string> values;
    for (const auto &parameter : DecodeTtcParameters(proof_response)) {
        if (!values.emplace(parameter.key, parameter.value).second) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON phase-two response has duplicate parameters");
        }
    }
    const auto proof = values.find("AUTH_SVR_RESPONSE");
    if (proof == values.end() || !VerifyO5LogonServerResponse(response, proof->second)) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle O5LOGON server proof is invalid");
    }
    return response;
}

} // namespace oracle_scanner
