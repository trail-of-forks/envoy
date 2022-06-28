#include "source/extensions/http/header_validators/envoy_default/header_validator_factory.h"

#include "source/extensions/http/header_validators/envoy_default/http1_header_validator.h"
#include "source/extensions/http/header_validators/envoy_default/http2_header_validator.h"
#include "source/extensions/http/header_validators/envoy_default/null_header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;

HeaderValidatorFactory::HeaderValidatorFactory(const HeaderValidatorConfig& config)
    : config_(config) {}

::Envoy::Http::HeaderValidatorPtr
HeaderValidatorFactory::create(::Envoy::Http::HeaderValidatorFactory::Protocol protocol,
                               StreamInfo::StreamInfo& stream_info) {
  switch (protocol) {
  case ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP2:
    return std::make_unique<Http2HeaderValidator>(config_, stream_info);
  case ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP1:
  case ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP09:
    return std::make_unique<Http1HeaderValidator>(config_, stream_info);
  default:
    return std::make_unique<NullHeaderValidator>(config_, stream_info);
  }
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
