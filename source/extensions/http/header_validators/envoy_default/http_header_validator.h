#pragma once

#include "envoy/extensions/http/header_validators/envoy_default/v3/header_validator.pb.h"
#include "envoy/http/header_validator.h"

#include "source/common/http/headers.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class HttpHeaderValidator : public ::Envoy::Http::HeaderValidator {
public:
  HttpHeaderValidator(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config,
      StreamInfo::StreamInfo& stream_info);

  // Validates the given method pseudo header value
  virtual HeaderEntryValidationResult
  validateMethodHeader(const ::Envoy::Http::HeaderString& value);

  // Configuration for validateStatusPseudoHeaderValue
  enum class StatusPseudoHeaderValidationMode {
    // No validation, just make sure it's numeric
    None,

    // Only accept values in the following range: 100->599
    ValueRange,

    // Allows all known codes
    AllowKnownValues,

    // Only allows standard codes
    Strict,
  };

  // Validates the given status pseudo header value
  virtual HeaderEntryValidationResult
  validateStatusHeader(const StatusPseudoHeaderValidationMode& mode,
                       const ::Envoy::Http::HeaderString& value);

  // Validates the given header key. Used when a more specific validator is not available
  virtual HeaderEntryValidationResult
  validateGenericHeaderName(const ::Envoy::Http::HeaderString& name);

  // Validates the given header value. Used when a more specific validator is not available
  virtual HeaderEntryValidationResult
  validateGenericHeaderValue(const ::Envoy::Http::HeaderString& value);

  // Validate the content-length header as whole-number integer.
  virtual HeaderEntryValidationResult
  validateContentLengthHeader(const ::Envoy::Http::HeaderString& value);

  // Validates the given scheme pseudo header value
  virtual HeaderEntryValidationResult
  validateSchemeHeader(const ::Envoy::Http::HeaderString& value);

  virtual HeaderEntryValidationResult validateHostHeader(const ::Envoy::Http::HeaderString& value);

protected:
  // Configuration
  const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig
      config_;
  const ::Envoy::Http::HeaderValues& header_values_;
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
