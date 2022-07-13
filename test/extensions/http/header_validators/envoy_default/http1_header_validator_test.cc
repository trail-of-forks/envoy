#include "source/extensions/http/header_validators/envoy_default/http1_header_validator.h"

#include "test/extensions/http/header_validators/envoy_default/header_validator_test.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {
namespace {

using ::Envoy::Http::HeaderString;
using ::Envoy::Http::HeaderValidator;

class Http1HeaderValidatorTest : public HeaderValidatorTest {
protected:
  Http1HeaderValidatorPtr createH1(absl::string_view config_yaml) {
    envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig
        typed_config;
    TestUtility::loadFromYaml(std::string(config_yaml), typed_config);

    return std::make_unique<Http1HeaderValidator>(typed_config, stream_info_);
  }
};

TEST_F(Http1HeaderValidatorTest, ValidateTransferEncoding) {
  HeaderString valid{"CHunkeD"};
  HeaderString invalid{"deflate"};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateTransferEncodingHeader(valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateTransferEncodingHeader(invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidatePath) {
  HeaderString valid{"/"};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validatePathHeader(valid), HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryEmpty) {
  HeaderString empty{""};
  HeaderString value{"foo"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(empty, value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryMethodPermissive) {
  HeaderString name{":method"};
  HeaderString valid{"GET"};
  HeaderString invalid{"CUSTOM-METHOD"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryMethodStrict) {
  HeaderString name{":method"};
  HeaderString valid{"GET"};
  HeaderString invalid{"CUSTOM-METHOD"};
  auto uhv = createH1(restrict_http_methods_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryHost) {
  HeaderString name{"host"};
  HeaderString valid{"envoy.com"};
  HeaderString invalid{"user:pass@envoy.com"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryAuthority) {
  HeaderString name{":authority"};
  HeaderString valid{"envoy.com"};
  HeaderString invalid{"user:pass@envoy.com"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryScheme) {
  HeaderString scheme{":scheme"};
  HeaderString valid{"https"};
  HeaderString valid_mixed_case{"hTtPs"};
  HeaderString invalid{"http_ssh"};
  HeaderString invalid_first_char{"+http"};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(scheme, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(scheme, valid_mixed_case),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(scheme, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(scheme, invalid_first_char),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryPath) {
  HeaderString name{":path"};
  HeaderString valid{"/"};
  HeaderString invalid{"/ bad path"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryTransferEncoding) {
  HeaderString name{"transfer-encoding"};
  HeaderString valid{"chunked"};
  HeaderString invalid{"deflate"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestEntryHeaderContentLength) {
  HeaderString content_length{"content-length"};
  HeaderString valid{"100"};
  HeaderString invalid{"10a2"};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderEntry(content_length, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(content_length, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryGeneric) {
  HeaderString valid_name{"x-foo"};
  HeaderString invalid_name{"foo oo"};
  HeaderString valid_value{"bar"};
  HeaderString invalid_value{};
  auto uhv = createH1(empty_config);

  setHeaderStringUnvalidated(invalid_value, "hello\nworld");

  EXPECT_EQ(uhv->validateRequestHeaderEntry(valid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(invalid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(uhv->validateRequestHeaderEntry(valid_name, invalid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderEntryEmpty) {
  HeaderString name{""};
  HeaderString valid{"chunked"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderEntryStatus) {
  HeaderString name{":status"};
  HeaderString valid{"200"};
  HeaderString invalid{"1024"};
  auto uhv = createH1(empty_config);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(name, valid),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(name, invalid),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderEntryGeneric) {
  HeaderString valid_name{"x-foo"};
  HeaderString invalid_name{"foo oo"};
  HeaderString valid_value{"bar"};
  HeaderString invalid_value{};
  auto uhv = createH1(empty_config);

  setHeaderStringUnvalidated(invalid_value, "hello\nworld");

  EXPECT_EQ(uhv->validateResponseHeaderEntry(valid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Accept);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(invalid_name, valid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
  EXPECT_EQ(uhv->validateResponseHeaderEntry(valid_name, invalid_value),
            HeaderValidator::HeaderEntryValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapAllowed) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapAllowedHostAlias) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {"host", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapMissingPath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {":authority", "envoy.com"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapMissingMethod) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":path", "/"}, {":authority", "envoy.com"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapMissingHost) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {":path", "/"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapStarPathAccept) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "OPTIONS"},
                                                  {":path", "*"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapStarPathReject) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "*"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingValid) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingInvalid) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "deflate"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateConnectPathIsAuthorityForm) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "www.envoy.com:443"},
                                                  {":authority", "www.envoy.com:443"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateConnectPathInvalidAuthorityForm) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "user:pass@envoy.com"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingConnect) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingContentLengthReject) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingContentLengthAllow) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(allow_chunked_length_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
  EXPECT_EQ(headers.ContentLength(), nullptr);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapContentLengthConnectReject) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapContentLengthConnectAccept) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"content-length", "0"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Accept);
  EXPECT_EQ(headers.ContentLength(), nullptr);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapExtraPseudo) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {":status", "200"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapEmptyGeneric) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapInvalidGeneric) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"foo header", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateRequestHeaderMap(headers),
            HeaderValidator::RequestHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapValid) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Accept);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapMissingStatus) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapInvalidStatus) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "bar"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapExtraPseudoHeader) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {":foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapEmptyGenericName) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {"", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_EQ(uhv->validateResponseHeaderMap(headers),
            HeaderValidator::ResponseHeaderMapValidationResult::Reject);
}

} // namespace
} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
