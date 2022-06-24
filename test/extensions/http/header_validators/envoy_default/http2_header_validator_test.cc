#include "source/extensions/http/header_validators/envoy_default/http2_header_validator.h"

#include "test/extensions/http/header_validators/envoy_default/header_validator_test.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {
namespace {

using ::Envoy::Extensions::Http::HeaderValidators::EnvoyDefault::Http2HeaderValidator;
using ::Envoy::Http::HeaderString;
using ::Envoy::Http::HeaderValidator;

class Http2HeaderValidatorTest : public HeaderValidatorTest {
protected:
  ::Envoy::Http::HeaderValidatorPtr createH2(absl::string_view config_yaml) {
    return create(config_yaml, ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP2);
  }
};

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapAllowed) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapMissingPath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapMissingMethod) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":path", "/"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapMissingScheme) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"}, {":path", "/"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapExtraPseudoHeader) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {":path", "/"}, {":foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapConnect) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":method", "CONNECT"}, {":authority", "envoy.com"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapConnectExtraPseudoHeader) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":method", "CONNECT"}, {":scheme", "https"}, {":authority", "envoy.com"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMapInvalidAuthority) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "user:pass@envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderMapValid) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderMapMissingStatus) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{"x-foo", "bar"}};
  auto uhv = createH2(empty_config);
  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderMapExtraPseudoHeader) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{
      {":status", "200"}, {":foo", "bar"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);
  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderMapInvalidStatus) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "1024"}, {"x-foo", "bar"}};
  auto uhv = createH2(empty_config);
  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateMethod) {
  HeaderString get{"GET"};
  HeaderString custom{"CUSTOM-METHOD"};
  EXPECT_EQ(Http2HeaderValidator::validateMethodPseudoHeaderValue(get),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateMethodPseudoHeaderValue(custom),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateTransferEncoding) {
  HeaderString trailers{"trailers"};
  HeaderString chunked{"chunked"};
  EXPECT_EQ(Http2HeaderValidator::validateTransferEncodingHeaderValue(trailers),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateTransferEncodingHeaderValue(chunked),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateSchemeStrict) {
  auto mode = Http2HeaderValidator::SchemaPseudoHeaderValidationMode::Strict;
  HeaderString valid{"https"};
  HeaderString invalid_first{"Https"};
  HeaderString invalid_middle{"http+Ssh"};
  EXPECT_EQ(Http2HeaderValidator::validateSchemePseudoHeaderValue(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateSchemePseudoHeaderValue(mode, invalid_first),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateSchemePseudoHeaderValue(mode, invalid_middle),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateSchemeUppercase) {
  auto mode = Http2HeaderValidator::SchemaPseudoHeaderValidationMode::AllowUppercase;
  HeaderString valid{"HTTPS"};
  HeaderString invalid_middle{"http_ssh"};
  EXPECT_EQ(Http2HeaderValidator::validateSchemePseudoHeaderValue(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateSchemePseudoHeaderValue(mode, invalid_middle),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateAuthority) {
  HeaderString valid{"envoy.com:443"};
  HeaderString valid_no_port{"envoy.com"};
  HeaderString invalid_empty{""};
  HeaderString invalid_userinfo{"foo:bar@envoy.com"};
  HeaderString invalid_port_int{"envoy.com:a"};
  HeaderString invalid_port_trailer{"envoy.com:10a"};
  HeaderString invalid_port_value{"envoy.com:66000"};
  HeaderString invalid_port_0{"envoy.com:0"};

  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(valid_no_port),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(invalid_empty),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(invalid_userinfo),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(invalid_port_int),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(invalid_port_trailer),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(invalid_port_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateAuthorityPseudoHeaderValue(invalid_port_0),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseStatusNone) {
  auto mode = Http2HeaderValidator::StatusPseudoHeaderValidationMode::None;
  HeaderString valid{"200"};
  HeaderString valid_outside_of_range{"1024"};
  HeaderString invalid{"asdf"};

  EXPECT_EQ(Http2HeaderValidator::validateStatusPseudoHeaderValue(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateStatusPseudoHeaderValue(mode, valid_outside_of_range),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateStatusPseudoHeaderValue(mode, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseStatusRange) {
  auto mode = Http2HeaderValidator::StatusPseudoHeaderValidationMode::ValueRange;
  HeaderString valid{"200"};
  HeaderString invalid_max{"1024"};
  HeaderString invalid_min{"99"};

  EXPECT_EQ(Http2HeaderValidator::validateStatusPseudoHeaderValue(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateStatusPseudoHeaderValue(mode, invalid_max),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateStatusPseudoHeaderValue(mode, invalid_min),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

// TODO(meilya) should we test validating response status with AllowKnownValues and Strict modes?
// this may be out of scope.

TEST_F(Http2HeaderValidatorTest, ValidatePath) {
  HeaderString valid{"/"};
  // TODO(meilya) - after path normalization has been approved and implemented
  EXPECT_EQ(Http2HeaderValidator::validatePathPseudoHeaderValue(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateGenericHeaderKeyRejectUnderscores) {
  auto mode = Http2HeaderValidator::GenericHeaderNameValidationMode::RejectUnderscores;
  HeaderString valid{"x-foo"};
  HeaderString invalid_underscore{"x_foo"};
  HeaderString invalid_eascii{"x-foo\x80"};

  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, invalid_underscore),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, invalid_eascii),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateGenericHeaderKeyStrict) {
  auto mode = Http2HeaderValidator::GenericHeaderNameValidationMode::Strict;
  HeaderString valid{"x-foo"};
  HeaderString valid_underscore{"x_foo"};
  HeaderString invalid_eascii{"x-foo\x80"};
  HeaderString invalid_empty{""};

  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, valid_underscore),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, invalid_eascii),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, invalid_empty),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateGenericHeaderKeyConnectionRejected) {
  auto mode = Http2HeaderValidator::GenericHeaderNameValidationMode::Strict;
  HeaderString transfer_encoding{"transfer-encoding"};
  HeaderString connection{"connection"};
  HeaderString keep_alive{"keep-alive"};
  HeaderString upgrade{"upgrade"};
  HeaderString proxy_connection{"proxy-connection"};

  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, transfer_encoding),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, connection),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, keep_alive),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, upgrade),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderKey(mode, proxy_connection),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateGenericHeaderValue) {
  HeaderString valid{"hello world"};
  HeaderString valid_eascii{"value\x80"};
  HeaderString invalid_newline;

  setHeaderStringUnvalidated(invalid_newline, "hello\nworld");

  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderValue(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderValue(valid_eascii),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateGenericHeaderValue(invalid_newline),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateContentLength) {
  HeaderString valid{"100"};
  HeaderString invalid{"10a2"};

  EXPECT_EQ(Http2HeaderValidator::validateContentLength(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(Http2HeaderValidator::validateContentLength(invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMethodAllowAllMethods) {
  HeaderString method{":method"};
  HeaderString valid{"GET"};
  HeaderString invalid{"CUSTOM-METHOD"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(method, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(method, invalid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderMethodRestrictMethods) {
  HeaderString method{":method"};
  HeaderString valid{"GET"};
  HeaderString invalid{"CUSTOM-METHOD"};
  auto uhv = createH2(restrict_http_methods_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(method, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(method, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderAuthority) {
  HeaderString authority{":authority"};
  HeaderString valid{"envoy.com"};
  HeaderString invalid{"user:pass@envoy.com"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(authority, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(authority, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderAuthorityHost) {
  HeaderString host{"host"};
  HeaderString valid{"envoy.com"};
  HeaderString invalid{"user:pass@envoy.com"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(host, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(host, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderContentLength) {
  HeaderString content_length{"content-length"};
  HeaderString valid{"100"};
  HeaderString invalid{"10a2"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(content_length, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(content_length, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderScheme) {
  HeaderString scheme{":scheme"};
  HeaderString valid{"https"};
  HeaderString invalid{"http_ssh"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(scheme, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(scheme, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderPath) {
  HeaderString path{":path"};
  HeaderString valid{"/"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(path, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  // TODO(meilya) - add invalid case when path normalization is ready
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderTransferEncoding) {
  HeaderString transfer_encoding{"TE"};
  HeaderString valid{"trailers"};
  HeaderString invalid{"chunked"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(transfer_encoding, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(transfer_encoding, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderGeneric) {
  HeaderString valid_name{"x-foo"};
  HeaderString invalid_name{""};
  HeaderString valid_value{"bar"};
  HeaderString invalid_value;
  auto uhv = createH2(empty_config);

  setHeaderStringUnvalidated(invalid_value, "hello\nworld");

  EXPECT_EQ(uhv->validateRequestHeaderEntry(valid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(invalid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(valid_name, invalid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderAllowUnderscores) {
  HeaderString name{"x_foo"};
  HeaderString value{"bar"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, value),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateRequestHeaderRejectUnderscores) {
  HeaderString name{"x_foo"};
  HeaderString value{"bar"};
  auto uhv = createH2(reject_headers_with_underscores_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderStatus) {
  HeaderString status{":status"};
  HeaderString valid{"200"};
  HeaderString invalid{"1024"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderEntry(status, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(status, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderGeneric) {
  HeaderString valid_name{"x-foo"};
  HeaderString invalid_name{""};
  HeaderString valid_value{"bar"};
  HeaderString invalid_value;
  auto uhv = createH2(empty_config);

  setHeaderStringUnvalidated(invalid_value, "hello\nworld");

  EXPECT_EQ(uhv->validateResponseHeaderEntry(valid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(invalid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(valid_name, invalid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderAllowUnderscores) {
  HeaderString name{"x_foo"};
  HeaderString value{"bar"};
  auto uhv = createH2(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderEntry(name, value),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http2HeaderValidatorTest, ValidateResponseHeaderRejectUnderscores) {
  HeaderString name{"x_foo"};
  HeaderString value{"bar"};
  auto uhv = createH2(reject_headers_with_underscores_config);

  EXPECT_EQ(uhv->validateResponseHeaderEntry(name, value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

} // namespace
} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
