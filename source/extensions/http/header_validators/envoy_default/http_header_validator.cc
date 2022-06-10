#include "source/extensions/http/header_validators/envoy_default/http_header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;

HttpHeaderValidator::HttpHeaderValidator(const HeaderValidatorConfig& config,
                                         StreamInfo::StreamInfo&)
    : config_(config) {
  static_cast<void>(config_);
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateRequestHeaderEntry(const HeaderString&, const HeaderString&) {
  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateResponseHeaderEntry(const HeaderString&, const HeaderString&) {
  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult
HttpHeaderValidator::validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap&) {
  return ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult
HttpHeaderValidator::validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap&) {
  return ::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult::Accept;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
