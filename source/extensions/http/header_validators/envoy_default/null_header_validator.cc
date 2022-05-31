#include "source/extensions/http/header_validators/envoy_default/null_header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;

NullHeaderValidator::NullHeaderValidator(const HeaderValidatorConfig&, StreamInfo::StreamInfo&) {}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
NullHeaderValidator::validateRequestHeaderEntry(const HeaderString&, const HeaderString&) {
  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
NullHeaderValidator::validateResponseHeaderEntry(const HeaderString&, const HeaderString&) {
  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult
NullHeaderValidator::validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap&) {

  return ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult
NullHeaderValidator::validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap&) {
  return ::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult::Accept;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
