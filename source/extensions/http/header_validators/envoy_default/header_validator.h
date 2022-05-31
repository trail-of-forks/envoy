#pragma once

#include "envoy/extensions/http/header_validators/envoy_default/v3/header_validator.pb.h"
#include "envoy/http/header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

/**
 * Custom header IP detection extension.
 */
class HeaderValidator : public ::Envoy::Http::HeaderValidator {
public:
  HeaderValidator(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config,
      ::Envoy::Http::HeaderValidatorFactory::Protocol protocol,
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

  // Validates the specified HTTP2 response header entry
  static HeaderEntryValidationResult
  validateHttp2ResponseHeaderEntry(const ::Envoy::Http::HeaderString& key,
                                   const ::Envoy::Http::HeaderString& value);

  // Validates the specified HTTP2 request header entry
  static HeaderEntryValidationResult
  validateHttp2RequestHeaderEntry(bool restrict_http_methods,
                                  const ::Envoy::Http::HeaderString& key,
                                  const ::Envoy::Http::HeaderString& value);

  // Validates the HTTP2 header map keys, looking for pseudo header that should not present
  static RequestHeaderMapValidationResult
  validateHttp2RequestPseudoHeaderKeys(::Envoy::Http::RequestHeaderMap& header_map);

  // Validates the HTTP2 header map keys, looking for pseudo header that should not present
  static ResponseHeaderMapValidationResult
  validateHttp2ResponsePseudoHeaderKeys(::Envoy::Http::ResponseHeaderMap& header_map);

  // Validates the given method pseudo header value
  static HeaderEntryValidationResult
  validateMethodPseudoHeaderValue(const ::Envoy::Http::HeaderString& value);

  // Validates the given HTTP2 transfer encoding header value
  static HeaderEntryValidationResult
  validateHttp2TransferEncodingHeaderValue(const ::Envoy::Http::HeaderString& value);

  // Validates the given scheme pseudo header value
  static HeaderEntryValidationResult
  validateSchemePseudoHeaderValue(const ::Envoy::Http::HeaderString& value);

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
  validateGenericHeaderKey(const ::Envoy::Http::HeaderString& key);

  // Validates the given header value. Used when a more specific validator is not available
  static HeaderEntryValidationResult
  validateGenericHeaderValue(const ::Envoy::Http::HeaderString& value);

private:
  // Configuration
  const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
      config_;

  // Protocol
  const ::Envoy::Http::HeaderValidatorFactory::Protocol protocol_;
};

class HeaderValidatorFactory : public ::Envoy::Http::HeaderValidatorFactory {
public:
  HeaderValidatorFactory(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config);

  ::Envoy::Http::HeaderValidatorPtr create(::Envoy::Http::HeaderValidatorFactory::Protocol protocol,
                                           StreamInfo::StreamInfo& stream_info) override;

private:
  const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig
      config_;
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
