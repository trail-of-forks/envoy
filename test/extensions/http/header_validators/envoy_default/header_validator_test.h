#include "envoy/extensions/http/header_validators/envoy_default/v3/header_validator.pb.h"

#include "source/extensions/http/header_validators/envoy_default/config.h"

#include "test/mocks/stream_info/mocks.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class HeaderValidatorTest : public testing::Test {
protected:
  void setHeaderStringUnvalidated(Envoy::Http::HeaderString& header_string,
                                  absl::string_view value) {
    header_string.setCopyUnvalidatedForTestOnly(value);
  }

  NiceMock<Envoy::StreamInfo::MockStreamInfo> stream_info_;

  static constexpr absl::string_view empty_config = "{}";

  static constexpr absl::string_view restrict_http_methods_config = R"EOF(
    restrict_http_methods: true
)EOF";

  static constexpr absl::string_view reject_headers_with_underscores_config = R"EOF(
    reject_headers_with_underscores: true
)EOF";
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
