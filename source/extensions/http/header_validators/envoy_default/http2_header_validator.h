#pragma once

#include "source/extensions/http/header_validators/envoy_default/http_header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class Http2HeaderValidator : public HttpHeaderValidator {
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

  /*
   * Valdiate the TE header.
   */
  HeaderEntryValidationResult validateTEHeader(const ::Envoy::Http::HeaderString& value);

  /*
   * Validate the :authority pseudo header.
   */
  HeaderEntryValidationResult validateAuthorityHeader(const ::Envoy::Http::HeaderString& value);

  virtual HeaderEntryValidationResult
  validateGenericHeaderName(const ::Envoy::Http::HeaderString& name) override;
};

using Http2HeaderValidatorPtr = std::unique_ptr<Http2HeaderValidator>;

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
