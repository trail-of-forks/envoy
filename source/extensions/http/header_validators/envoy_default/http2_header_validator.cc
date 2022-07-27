#include "source/extensions/http/header_validators/envoy_default/http2_header_validator.h"

#include "absl/container/node_hash_map.h"
#include "absl/container/node_hash_set.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;
using ::Envoy::Http::HeaderValidator;
using HeaderValidatorFunction =
    HeaderValidator::HeaderEntryValidationResult (Http2HeaderValidator::*)(const HeaderString&);

struct Http2ResponseCodeDetailValues {
  const absl::string_view InvalidTE = "uhv.http2.invalid_te";
  const absl::string_view ConnectionHeaderSanitization = "uhv.http2.connection_header_rejected";
};

using Http2ResponseCodeDetail = ConstSingleton<Http2ResponseCodeDetailValues>;

/*
 * Header validation implementation for the Http/2 codec. This class follows guidance from
 * several RFCS:
 *
 * RFC 3986 <https://datatracker.ietf.org/doc/html/rfc3986> URI Generic Syntax
 * RFC 7230 <https://datatracker.ietf.org/doc/html/rfc7230> HTTP/1.1 Message Syntax
 * RFC 7231 <https://datatracker.ietf.org/doc/html/rfc7231> HTTP/1.1 Semantics and Content
 * RFC 7540 <https://datatracker.ietf.org/doc/html/rfc7540> HTTP/2
 *
 */
Http2HeaderValidator::Http2HeaderValidator(const HeaderValidatorConfig& config,
                                           StreamInfo::StreamInfo& stream_info)
    : HttpHeaderValidator(config, stream_info) {}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateRequestHeaderEntry(const HeaderString& key,
                                                 const HeaderString& value) {
  static const absl::node_hash_map<absl::string_view, HeaderValidatorFunction> kHeaderValidatorMap{
      {":method", &Http2HeaderValidator::validateMethodHeader},
      {":authority", &Http2HeaderValidator::validateAuthorityHeader},
      {"host", &Http2HeaderValidator::validateAuthorityHeader},
      {":scheme", &Http2HeaderValidator::validateSchemeHeader},
      {":path", &Http2HeaderValidator::validateGenericPathHeader},
      {"te", &Http2HeaderValidator::validateTEHeader},
      {"content-length", &Http2HeaderValidator::validateContentLengthHeader},
  };

  const auto& key_string_view = key.getStringView();
  if (key_string_view.empty()) {
    // reject empty header names
    stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().EmptyHeaderName);
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto result{HeaderValidator::HeaderEntryValidationResult::Reject};

  auto validator_it = kHeaderValidatorMap.find(key_string_view);
  if (validator_it != kHeaderValidatorMap.end()) {
    const auto& validator = validator_it->second;
    result = (*this.*validator)(value);

  } else {
    if (key_string_view.at(0) != ':') {
      // Validate the (non-pseudo) header name
      auto name_result = validateGenericHeaderName(key);
      if (name_result == HeaderValidator::HeaderEntryValidationResult::Reject) {
        return name_result;
      }
    }

    result = validateGenericHeaderValue(value);
  }

  return result;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateResponseHeaderEntry(const HeaderString& key,
                                                  const HeaderString& value) {
  const auto& key_string_view = key.getStringView();
  if (key_string_view.empty()) {
    // reject empty header names
    stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().EmptyHeaderName);
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  if (key_string_view == ":status") {
    // Validate the :status header against the RFC valid range (100 <= status < 600)
    return validateStatusHeader(StatusPseudoHeaderValidationMode::ValueRange, value);
  } else if (key_string_view == "content-length") {
    // Validate the Content-Length header
    return validateContentLengthHeader(value);
  } else if (key_string_view.at(0) != ':') {
    auto name_result = validateGenericHeaderName(key);
    if (name_result == HeaderValidator::HeaderEntryValidationResult::Reject) {
      return name_result;
    }
  }

  // Validate the header value
  return validateGenericHeaderValue(value);
}

HeaderValidator::RequestHeaderMapValidationResult
Http2HeaderValidator::validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeadersForConnect = {
      ":method",
      ":authority",
  };

  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {
      ":method", ":scheme", ":authority", ":path"};

  absl::string_view path = header_map.getPathValue();

  //
  // Step 1: verify that required pseudo headers are present.
  //
  // The method pseudo header is always mandatory.
  //
  if (header_map.getMethodValue().empty()) {
    stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().InvalidMethod);
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  auto is_connect_method = header_map.method() == header_values_.MethodValues.Connect;
  auto is_options_method = header_map.method() == header_values_.MethodValues.Options;
  bool path_is_asterisk = path == "*";
  bool path_is_absolute = !path.empty() && path.at(0) == '/';

  if (!is_connect_method && (header_map.getSchemeValue().empty() || path.empty())) {
    //
    // If this is not a connect request, then we also need the scheme and path pseudo headers.
    // This is based on RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.3:
    //
    // All HTTP/2 requests MUST include exactly one valid value for the ":method", ":scheme",
    // and ":path" pseudo-header fields, unless it is a CONNECT request (Section 8.3). An
    // HTTP request that omits mandatory pseudo-header fields is malformed (Section 8.1.2.6).
    //
    auto details = path.empty() ? UhvResponseCodeDetail::get().InvalidUrl
                                : UhvResponseCodeDetail::get().InvalidScheme;
    stream_info_.setResponseCodeDetails(details);
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  } else if (is_connect_method) {
    //
    // If this is a CONNECT request, :path and :scheme must be empty and :authority must be
    // provided. This is based on RFC 7540,
    // https://datatracker.ietf.org/doc/html/rfc7540#section-8.3:
    //
    //  * The ":method" pseudo-header field is set to "CONNECT".
    //  * The ":scheme" and ":path" pseudo-header fields MUST be omitted.
    //  * The ":authority" pseudo-header field contains the host and port to connect to
    //    (equivalent to the authority-form of the request-target of CONNECT requests (see
    //    [RFC7230], Section 5.3)).
    //
    absl::string_view details;
    if (!path.empty()) {
      details = UhvResponseCodeDetail::get().InvalidUrl;
    } else if (!header_map.getSchemeValue().empty()) {
      details = UhvResponseCodeDetail::get().InvalidScheme;
    } else if (header_map.authority().empty()) {
      details = UhvResponseCodeDetail::get().InvalidHost;
    }

    if (!details.empty()) {
      stream_info_.setResponseCodeDetails(details);
      return HeaderValidator::RequestHeaderMapValidationResult::Reject;
    }
  }

  //
  // Step 2: Validate and normalize the :path pseudo header
  //
  if (!is_options_method && path_is_asterisk) {
    //
    // Reject a request if the path is in asterisk-form, "*", and not an OPTIONS method. This is
    // based on RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.3:
    //
    // [The :path] pseudo-header field MUST NOT be empty for "http" or "https" URIs; "http" or
    // "https" URIs that do not contain a path component MUST include a value of '/'. The
    // exception to this rule is an OPTIONS request for an "http" or "https" URI that does not
    // include a path component; these MUST include a ":path" pseudo-header field with a value
    // of '*'.
    //
    stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().InvalidUrl);
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  if (path_is_absolute && !config_.uri_path_normalization_options().skip_path_normalization()) {
    // Normalize the path
    // TODO(meilya) - this will be something like:
    //
    // auto path_result = normalizePathUri(header_map);
    // if (path_result != HeaderValidator::RequestHeaderMapValidationResult::Accept) {
    //   return path_result;
    // }
  }

  // If path normalization is disabled or the path isn't absolute then the path will be validated
  // against the RFC character set in validateRequestHeaderEntry.

  //
  // Step 3: Verify each request header
  //
  const auto& allowed_headers =
      is_connect_method ? kAllowedPseudoHeadersForConnect : kAllowedPseudoHeaders;
  auto status = HeaderValidator::RequestHeaderMapValidationResult::Accept;

  header_map.iterate(
      [this, &status, &allowed_headers](
          const ::Envoy::Http::HeaderEntry& header_entry) -> ::Envoy::Http::HeaderMap::Iterate {
        const auto& header_name = header_entry.key();
        const auto& header_value = header_entry.value();
        const auto& string_header_name = header_name.getStringView();

        if (string_header_name.empty()) {
          // reject empty header names
          stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().EmptyHeaderName);
          status = HeaderValidator::RequestHeaderMapValidationResult::Reject;
        } else if (string_header_name.at(0) == ':' &&
                   !allowed_headers.contains(string_header_name)) {
          // This is an unrecognized pseudo header, reject the request
          stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().InvalidPseudoHeader);
          status = HeaderValidator::RequestHeaderMapValidationResult::Reject;
        } else if (validateRequestHeaderEntry(header_name, header_value) ==
                   HeaderValidator::HeaderEntryValidationResult::Reject) {
          status = HeaderValidator::RequestHeaderMapValidationResult::Reject;
        }

        return status == HeaderValidator::RequestHeaderMapValidationResult::Accept
                   ? ::Envoy::Http::HeaderMap::Iterate::Continue
                   : ::Envoy::Http::HeaderMap::Iterate::Break;
      });

  return status;
}

HeaderValidator::ResponseHeaderMapValidationResult
Http2HeaderValidator::validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {":status"};
  //
  // Step 1: verify that required pseudo headers are present
  //
  // For HTTP/2 responses, RFC 7540 states that only the :status
  // header is required: https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.4:
  //
  // For HTTP/2 responses, a single ":status" pseudo-header field is defined that carries the HTTP
  // status code field (see [RFC7231], Section 6). This pseudo-header field MUST be included in
  // all responses; otherwise, the response is malformed.
  //
  if (header_map.getStatusValue().empty()) {
    stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().InvalidStatus);
    return HeaderValidator::ResponseHeaderMapValidationResult::Reject;
  }

  //
  // Step 2: Verify each response header
  //
  auto status = HeaderValidator::ResponseHeaderMapValidationResult::Accept;
  header_map.iterate([this, &status](const ::Envoy::Http::HeaderEntry& header_entry)
                         -> ::Envoy::Http::HeaderMap::Iterate {
    const auto& header_name = header_entry.key();
    const auto& header_value = header_entry.value();
    const auto& string_header_name = header_name.getStringView();

    if (string_header_name.empty()) {
      stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().EmptyHeaderName);
      status = HeaderValidator::ResponseHeaderMapValidationResult::Reject;
    } else if (string_header_name.at(0) == ':' &&
               !kAllowedPseudoHeaders.contains(header_name.getStringView())) {
      // This is an unrecognized pseudo header, reject the response
      stream_info_.setResponseCodeDetails(UhvResponseCodeDetail::get().InvalidPseudoHeader);
      status = HeaderValidator::ResponseHeaderMapValidationResult::Reject;
    } else if (validateResponseHeaderEntry(header_name, header_value) ==
               HeaderValidator::HeaderEntryValidationResult::Reject) {
      status = HeaderValidator::ResponseHeaderMapValidationResult::Reject;
    }

    return status == HeaderValidator::ResponseHeaderMapValidationResult::Accept
               ? ::Envoy::Http::HeaderMap::Iterate::Continue
               : ::Envoy::Http::HeaderMap::Iterate::Break;
  });

  return status;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateTEHeader(const ::Envoy::Http::HeaderString& value) {
  //
  // Only allow a TE value of "trailers" for HTTP/2, based on
  // RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.2:
  //
  // The only exception to this is the TE header field, which MAY be present
  // in an HTTP/2 request; when it is, it MUST NOT contain any value other
  // than "trailers".
  //
  if (!absl::EqualsIgnoreCase(value.getStringView(), header_values_.TEValues.Trailers)) {
    stream_info_.setResponseCodeDetails(Http2ResponseCodeDetail::get().InvalidTE); // TODO
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateAuthorityHeader(const ::Envoy::Http::HeaderString& value) {
  //
  // From RFC 3986, https://datatracker.ietf.org/doc/html/rfc3986#section-3.2:
  //
  // authority = [ userinfo "@" ] host [ ":" port ]
  //
  // HTTP/2 deprecates the userinfo portion of the :authority header. Validate
  // the :authority header and reject the value if the userinfo is present. This
  // is based on RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.3
  //
  // The host portion can be any valid URI host, which this function does not
  // validate. The port, if present, is validated as a valid uint16_t port.
  //
  return validateHostHeader(value);
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateGenericHeaderName(const ::Envoy::Http::HeaderString& key) {
  //
  // For HTTP/2, connection-specific headers must be treated as malformed. From RFC 7540,
  // https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.2:
  //
  // any message containing connection-specific header fields MUST be treated
  // as malformed (Section 8.1.2.6).
  //
  static const absl::node_hash_set<absl::string_view> kRejectHeaderNames = {
      "transfer-encoding", "connection", "upgrade", "keep-alive", "proxy-connection"};

  const auto& key_string_view = key.getStringView();
  if (kRejectHeaderNames.contains(key_string_view)) {
    stream_info_.setResponseCodeDetails(
        Http2ResponseCodeDetail::get().ConnectionHeaderSanitization);
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  return HttpHeaderValidator::validateGenericHeaderName(key);
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
