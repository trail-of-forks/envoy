#pragma once

#include "envoy/extensions/http/header_validators/envoy_default/v3/header_validator.pb.h"
#include "envoy/http/header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class PathNormalizer {
public:
  PathNormalizer(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config);

  ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult
  normalizePathUri(::Envoy::Http::RequestHeaderMap& header_map);

  /*
   * The result of attempting to normalize and decode a percent-encoded octet.
   */
  enum class PercentDecodeResult {
    // The percent encoding is invalid and could not be decoded.
    Invalid,
    // The percent encoding is valid but decodes to an unallowed character.
    Reject,
    // The percent encoding is valid and was normalized to UPPERCASE.
    Normalized,
    // The percent encoding is valid and was decoded.
    Decoded,
    // The percent ending is valid, was decoded, and, based on the active configuration, the
    // response should redirect to the normalized path.
    DecodedRedirect
  };

  /*
   * Normalize a percent encoded octet (%XX) to uppercase and decode to a character. The octet
   * argument must start with the "%" character and is modified in-place based on the return value:
   *
   * - Invalid - no modification was performed
   * - Reject, Normalized - the octet is normalized to UPPERCASE. octet[1] and octet[2] are
   *     UPPERCASE after returning.
   * - Decoded, DecodedRedirect - the octet is decoded to a single character at location octet[2].
   */
  PercentDecodeResult normalize_and_decode_octet(char* octet);

private:
  const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
      config_;
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
