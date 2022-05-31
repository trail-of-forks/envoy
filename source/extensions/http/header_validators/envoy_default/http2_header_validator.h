#pragma once

#include "source/extensions/http/header_validators/envoy_default/header_validator.h"

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

  // Validates the specified response header entry
  static HeaderEntryValidationResult
  validateResponseHeader(const ::Envoy::Http::HeaderString& key,
                         const ::Envoy::Http::HeaderString& value);

  // Validates the specified request header entry
  static HeaderEntryValidationResult
  validateRequestHeader(bool restrict_http_methods, const ::Envoy::Http::HeaderString& key,
                        const ::Envoy::Http::HeaderString& value);

  // Validates the header map keys, looking for pseudo header that should not present
  static RequestHeaderMapValidationResult
  validateRequestPseudoHeaderKeys(::Envoy::Http::RequestHeaderMap& header_map);

  // Validates the header map keys, looking for pseudo header that should not present
  static ResponseHeaderMapValidationResult
  validateResponsePseudoHeaderKeys(::Envoy::Http::ResponseHeaderMap& header_map);

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
  validateGenericHeaderKey(bool allow_underscores, const ::Envoy::Http::HeaderString& key);

  // Configuration for validateGenericHeaderValue
  enum class GenericHeaderValueValidationMode {
    // Strict
    Strict,

    // Use the old nghttp2 character table
    Compatibility,
  };

  // Validates the given header value. Used when a more specific validator is not available
  static HeaderEntryValidationResult
  validateGenericHeaderValue(const GenericHeaderValueValidationMode& mode,
                             const ::Envoy::Http::HeaderString& value);

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
