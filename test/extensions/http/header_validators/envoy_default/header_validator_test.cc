#include "test/extensions/http/header_validators/envoy_default/header_validator_test.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {
namespace {

using ::Envoy::Http::HeaderString;

class Http1HeaderValidatorTest : public HeaderValidatorTest {
protected:
  ::Envoy::Http::HeaderValidatorPtr createH1(absl::string_view config_yaml) {
    return create(config_yaml, Envoy::Http::HeaderValidatorFactory::Protocol::HTTP1);
  }
};

TEST_F(Http1HeaderValidatorTest, Http1RequestHeaderNameValidation) {
  auto uhv = createH1(empty_config);
  // Since the default UHV does not yet check anything all header values should be accepted
  std::string key_value("aaa");
  HeaderString key(key_value);
  HeaderString value("valid");
  for (int c = 0; c <= 0xff; ++c) {
    key_value[1] = c;
    setHeaderStringUnvalidated(key, key_value);
    EXPECT_EQ(uhv->validateRequestHeaderEntry(key, value),
              ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept);
  }
}

TEST_F(Http1HeaderValidatorTest, Http1ResponseHeaderNameValidation) {
  auto uhv = createH1(empty_config);
  // Since the default UHV does not yet check anything all header values should be accepted
  std::string key_value("aaa");
  HeaderString key(key_value);
  HeaderString value("valid");
  for (int c = 0; c <= 0xff; ++c) {
    key_value[1] = c;
    setHeaderStringUnvalidated(key, key_value);
    EXPECT_EQ(uhv->validateResponseHeaderEntry(key, value),
              ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept);
  }
}

TEST_F(Http1HeaderValidatorTest, Http1RequestHeaderMapValidation) {
  auto uhv = createH1(empty_config);
  ::Envoy::Http::TestRequestHeaderMapImpl request_header_map{
      {":method", "GET"}, {":path", "/"}, {":scheme", "http"}, {":authority", "host"}};
  EXPECT_EQ(uhv->validateRequestHeaderMap(request_header_map),
            ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, Http1ResponseHeaderMapValidation) {
  auto uhv = createH1(empty_config);
  ::Envoy::Http::TestResponseHeaderMapImpl response_header_map{{":status", "200"}};
  EXPECT_EQ(uhv->validateResponseHeaderMap(response_header_map),
            ::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult::Accept);
}

} // namespace
} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
