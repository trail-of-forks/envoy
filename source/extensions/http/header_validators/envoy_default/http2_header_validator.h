#pragma once

#include "envoy/extensions/http/header_validators/envoy_default/v3/header_validator.pb.h"
#include "envoy/http/header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class Http2HeaderValidator : public ::Envoy::Http::HeaderValidator {
public:
  Http2HeaderValidator(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config,
      StreamInfo::StreamInfo& stream_info);

  HeaderEntryValidationResult
  validateRequestHeaderEntry(const ::Envoy::Http::HeaderString& key,
                             const ::Envoy::Http::HeaderString& value) override;

  HeaderEntryValidationResult
  validateResponseHeaderEntry(const ::Envoy::Http::HeaderString& key,
                              const ::Envoy::Http::HeaderString& value) override;

  RequestHeaderMapValidationResult
  validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap& header_map) override;

  ResponseHeaderMapValidationResult
  validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap& header_map) override;

  // Configuration for validateResponseHeader and validateRequestHeader
  enum class GenericHeaderNameValidationMode {
    // Strict
    Strict,

    // Strict but reject underscores
    RejectUnderscores
  };

  // Validates the given method pseudo header value
  static HeaderEntryValidationResult
  validateMethodPseudoHeaderValue(const ::Envoy::Http::HeaderString& value);

  // Validates the given transfer encoding header value
  static HeaderEntryValidationResult
  validateTransferEncodingHeaderValue(const ::Envoy::Http::HeaderString& value);

  // Configuration for validateSchemePseudoHeaderValue
  enum class SchemaPseudoHeaderValidationMode {
    // Strict
    Strict,

    // Like strict, but allow uppercase characters
    AllowUppercase,
  };

  // Validates the given scheme pseudo header value
  static HeaderEntryValidationResult
  validateSchemePseudoHeaderValue(const SchemaPseudoHeaderValidationMode& mode,
                                  const ::Envoy::Http::HeaderString& value);

  // Validates the given authority pseudo header value
  static HeaderEntryValidationResult
  validateAuthorityPseudoHeaderValue(const ::Envoy::Http::HeaderString& value);

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
  static HeaderEntryValidationResult
  validateStatusPseudoHeaderValue(const StatusPseudoHeaderValidationMode& mode,
                                  const ::Envoy::Http::HeaderString& value);

  // Validates the given path pseudo header value
  static HeaderEntryValidationResult
  validatePathPseudoHeaderValue(const ::Envoy::Http::HeaderString& value);

  // Validates the given header key. Used when a more specific validator is not available
  static HeaderEntryValidationResult
  validateGenericHeaderKey(const GenericHeaderNameValidationMode& mode,
                           const ::Envoy::Http::HeaderString& key);

  // Validates the given header value. Used when a more specific validator is not available
  static HeaderEntryValidationResult
  validateGenericHeaderValue(const ::Envoy::Http::HeaderString& value);

private:
  // Configuration
  const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
      config_;
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
