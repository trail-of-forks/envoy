#include "envoy/extensions/http/header_validators/envoy_default/v3/header_validator.pb.h"

#include "source/common/network/utility.h"
#include "source/extensions/http/header_validators/envoy_default/config.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

class HeaderValidatorTest : public testing::Test {
protected:
  ::Envoy::Http::HeaderValidatorPtr create(absl::string_view config_yaml,
                                           Envoy::Http::HeaderValidatorFactory::Protocol protocol) {
    auto* factory =
        Registry::FactoryRegistry<Envoy::Http::HeaderValidatorFactoryConfig>::getFactory(
            "envoy.http.header_validators.envoy_default");
    ASSERT(factory != nullptr);

    envoy::config::core::v3::TypedExtensionConfig typed_config;
    TestUtility::loadFromYaml(std::string(config_yaml), typed_config);

    uhv_factory_ = factory->createFromProto(typed_config.typed_config(), context_);
    return uhv_factory_->create(protocol, stream_info_);
  }

  void setHeaderStringUnvalidated(Envoy::Http::HeaderString& header_string,
                                  absl::string_view value) {
    header_string.setCopyUnvalidatedForTestOnly(value);
  }

  NiceMock<Server::Configuration::MockFactoryContext> context_;
  ::Envoy::Http::HeaderValidatorFactorySharedPtr uhv_factory_;
  NiceMock<Envoy::StreamInfo::MockStreamInfo> stream_info_;

  static constexpr absl::string_view empty_config = R"EOF(
    name: envoy.http.header_validators.envoy_default
    typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.header_validators.envoy_default.v3.HeaderValidatorConfig
)EOF";
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
