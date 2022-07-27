#include "test/extensions/http/header_validators/envoy_default/header_validator_test.h"

#include "source/extensions/http/header_validators/envoy_default/http_header_validator.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {
namespace {

using ::Envoy::Http::HeaderString;
using ::Envoy::Http::HeaderValidator;

class BaseHttpHeaderValidator : public HttpHeaderValidator {
public:
  BaseHttpHeaderValidator(
      const envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig&
          config,
      StreamInfo::StreamInfo& stream_info)
      : HttpHeaderValidator(config, stream_info) {}

  virtual HeaderEntryValidationResult
  validateRequestHeaderEntry(const ::Envoy::Http::HeaderString&,
                             const ::Envoy::Http::HeaderString&) override {
    return HeaderEntryValidationResult::Accept;
  }

  virtual HeaderEntryValidationResult
  validateResponseHeaderEntry(const ::Envoy::Http::HeaderString&,
                              const ::Envoy::Http::HeaderString&) override {
    return HeaderEntryValidationResult::Accept;
  }

  virtual RequestHeaderMapValidationResult
  validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap&) override {
    return RequestHeaderMapValidationResult::Accept;
  }

  virtual ResponseHeaderMapValidationResult
  validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap&) override {
    return ResponseHeaderMapValidationResult::Accept;
  }
};

using BaseHttpHeaderValidatorPtr = std::unique_ptr<BaseHttpHeaderValidator>;

class BaseHeaderValidatorTest : public HeaderValidatorTest {
protected:
  BaseHttpHeaderValidatorPtr createBase(absl::string_view config_yaml) {
    envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig
        typed_config;
    TestUtility::loadFromYaml(std::string(config_yaml), typed_config);

    return std::make_unique<BaseHttpHeaderValidator>(typed_config, stream_info_);
  }
};

TEST_F(BaseHeaderValidatorTest, ValidateMethodPermissive) {
  HeaderString valid{"GET"};
  HeaderString custom{"CUSTOM-METHOD"};
  auto uhv = createBase(empty_config);
  EXPECT_EQ(uhv->validateMethodHeader(valid), HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateMethodHeader(custom),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(BaseHeaderValidatorTest, ValidateMethodStrict) {
  HeaderString valid{"GET"};
  HeaderString custom{"CUSTOM-METHOD"};
  auto uhv = createBase(restrict_http_methods_config);
  EXPECT_EQ(uhv->validateMethodHeader(valid), HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateMethodHeader(custom),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidMethod);
}

TEST_F(BaseHeaderValidatorTest, ValidateSchemeValid) {
  HeaderString valid{"https"};
  HeaderString valid_mixed_case{"hTtPs"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateSchemeHeader(valid), HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateSchemeHeader(valid_mixed_case),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(BaseHeaderValidatorTest, ValidateSchemeInvalidChar) {
  HeaderString invalid{"http_ssh"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateSchemeHeader(invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidScheme);
}

TEST_F(BaseHeaderValidatorTest, ValidateSchemeInvalidStartChar) {
  HeaderString invalid_first_char{"+http"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateSchemeHeader(invalid_first_char),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidScheme);
}

TEST_F(BaseHeaderValidatorTest, ValidateResponseStatusNoneValid) {
  auto mode = HttpHeaderValidator::StatusPseudoHeaderValidationMode::WholeNumber;
  HeaderString valid{"200"};
  HeaderString valid_outside_of_range{"1024"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateStatusHeader(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateStatusHeader(mode, valid_outside_of_range),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(BaseHeaderValidatorTest, ValidateResponseStatusNoneInvalid) {
  auto mode = HttpHeaderValidator::StatusPseudoHeaderValidationMode::WholeNumber;
  HeaderString invalid{"asdf"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateStatusHeader(mode, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(BaseHeaderValidatorTest, ValidateResponseStatusRangeValid) {
  auto mode = HttpHeaderValidator::StatusPseudoHeaderValidationMode::ValueRange;
  HeaderString valid{"200"};
  HeaderString invalid_max{"1024"};
  HeaderString invalid_min{"99"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateStatusHeader(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateStatusHeader(mode, invalid_max),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidStatus);
  EXPECT_EQ(uhv->validateStatusHeader(mode, invalid_min),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(BaseHeaderValidatorTest, ValidateResponseStatusRangeInvalidMin) {
  auto mode = HttpHeaderValidator::StatusPseudoHeaderValidationMode::ValueRange;
  HeaderString invalid_min{"99"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateStatusHeader(mode, invalid_min),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(BaseHeaderValidatorTest, ValidateResponseStatusRangeInvalidMax) {
  auto mode = HttpHeaderValidator::StatusPseudoHeaderValidationMode::ValueRange;
  HeaderString invalid_max{"1024"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateStatusHeader(mode, invalid_max),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(BaseHeaderValidatorTest, ValidateResponseStatusOfficalCodes) {
  auto mode = HttpHeaderValidator::StatusPseudoHeaderValidationMode::OfficialStatusCodes;
  HeaderString valid{"200"};
  HeaderString invalid_unregistered{"420"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateStatusHeader(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateStatusHeader(mode, invalid_unregistered),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderNameValid) {
  HeaderString valid{"x-foo"};
  auto uhv = createBase(reject_headers_with_underscores_config);

  EXPECT_EQ(uhv->validateGenericHeaderName(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderKeyRejectUnderscores) {
  HeaderString invalid_underscore{"x_foo"};
  auto uhv = createBase(reject_headers_with_underscores_config);

  EXPECT_EQ(uhv->validateGenericHeaderName(invalid_underscore),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidUnderscore);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderKeyInvalidChar) {
  HeaderString invalid_eascii{"x-foo\x80"};
  auto uhv = createBase(reject_headers_with_underscores_config);

  EXPECT_EQ(uhv->validateGenericHeaderName(invalid_eascii),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidCharacters);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderKeyStrictValid) {
  HeaderString valid{"x-foo"};
  HeaderString valid_underscore{"x_foo"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateGenericHeaderName(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateGenericHeaderName(valid_underscore),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderKeyStrictInvalidChar) {
  HeaderString invalid_eascii{"x-foo\x80"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateGenericHeaderName(invalid_eascii),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidCharacters);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderKeyStrictInvalidEmpty) {
  HeaderString invalid_empty{""};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateGenericHeaderName(invalid_empty),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().EmptyHeaderName);
}

TEST_F(BaseHeaderValidatorTest, ValidateGenericHeaderValue) {
  HeaderString valid{"hello world"};
  HeaderString valid_eascii{"value\x80"};
  HeaderString invalid_newline;
  auto uhv = createBase(empty_config);

  setHeaderStringUnvalidated(invalid_newline, "hello\nworld");

  EXPECT_EQ(uhv->validateGenericHeaderValue(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateGenericHeaderValue(valid_eascii),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateGenericHeaderValue(invalid_newline),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidCharacters);
}

TEST_F(BaseHeaderValidatorTest, ValidateContentLength) {
  HeaderString valid{"100"};
  HeaderString invalid{"10a2"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateContentLengthHeader(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateContentLengthHeader(invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidContentLength);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderValid) {
  HeaderString valid{"envoy.com:443"};
  HeaderString valid_no_port{"envoy.com"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(valid), HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateHostHeader(valid_no_port),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderInvalidEmpty) {
  HeaderString invalid_empty{""};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(invalid_empty),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderInvalidUserInfo) {
  HeaderString invalid_userinfo{"foo:bar@envoy.com"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(invalid_userinfo),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderInvalidPortNumber) {
  HeaderString invalid_port_int{"envoy.com:a"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(invalid_port_int),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderInvalidPortTrailer) {
  HeaderString invalid_port_trailer{"envoy.com:10a"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(invalid_port_trailer),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderInvalidPortMax) {
  HeaderString invalid_port_value{"envoy.com:66000"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(invalid_port_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(BaseHeaderValidatorTest, ValidateHostHeaderInvalidPort0) {
  HeaderString invalid_port_0{"envoy.com:0"};
  auto uhv = createBase(empty_config);

  EXPECT_EQ(uhv->validateHostHeader(invalid_port_0),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(stream_info_.responseCodeDetails(), UhvResponseCodeDetail::get().InvalidHost);
}

} // namespace
} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
