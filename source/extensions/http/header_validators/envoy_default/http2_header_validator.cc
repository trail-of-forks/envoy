#include "source/extensions/http/header_validators/envoy_default/http2_header_validator.h"

#include <charconv>

#include "source/extensions/http/header_validators/envoy_default/nghttp2_character_maps.h"

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

Http2HeaderValidator::Http2HeaderValidator(const HeaderValidatorConfig& config,
                                           StreamInfo::StreamInfo&)
    : config_(config) {}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateRequestHeaderEntry(const HeaderString& key,
                                                 const HeaderString& value) {
  const auto& key_string_view = key.getStringView();

  if (!key_string_view.size()) {
    // reject empty header names
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  if (key_string_view == ":method" && config_.restrict_http_methods()) {
    // Verify that the :method matches a well known value if the configuration is set to
    // restrict methods. When not restricting methods, the generic validation will validate
    // the :method value.
    return validateMethodPseudoHeaderValue(value);
  } else if (key_string_view == ":authority" || key_string_view == "host") {
    // Validate the :authority or legacy host header
    return validateAuthorityPseudoHeaderValue(value);
  } else if (key_string_view == ":scheme") {
    // Validate the :scheme header, allowing for uppercase characters
    return validateSchemePseudoHeaderValue(SchemaPseudoHeaderValidationMode::AllowUppercase, value);
  } else if (key_string_view == ":path") {
    // Validate the :path header
    return validatePathPseudoHeaderValue(value);
  } else if (key_string_view == "TE") {
    // Validate the :transfer-encoding header
    return validateTransferEncodingHeaderValue(value);
  } else if (key_string_view == "content-length") {
    // Validate the content-length header
    return validateContentLength(value);
  } else if (key_string_view.at(0) != ':') {
    // Validate the (non-pseudo) header name
    auto mode = GenericHeaderNameValidationMode::Strict;
    if (config_.reject_headers_with_underscores()) {
      mode = GenericHeaderNameValidationMode::RejectUnderscores;
    }

    auto status = validateGenericHeaderKey(mode, key);
    if (status == HeaderValidator::HeaderEntryValidationResult::Reject) {
      return status;
    }
  }

  // Validate the header value
  return validateGenericHeaderValue(value);
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateResponseHeaderEntry(const HeaderString& key,
                                                  const HeaderString& value) {
  const auto& key_string_view = key.getStringView();
  if (!key_string_view.size()) {
    // reject empty header names
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  if (key_string_view == ":status") {
    // Validate the :status header against the RFC valid range (100 <= status < 600)
    return validateStatusPseudoHeaderValue(StatusPseudoHeaderValidationMode::ValueRange, value);
  } else if (key_string_view.at(0) != ':') {
    // Validate non-pseudo header names
    GenericHeaderNameValidationMode mode{GenericHeaderNameValidationMode::Strict};
    if (config_.reject_headers_with_underscores()) {
      mode = GenericHeaderNameValidationMode::RejectUnderscores;
    }

    auto status = validateGenericHeaderKey(mode, key);
    if (status == HeaderValidator::HeaderEntryValidationResult::Reject) {
      return status;
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

  //
  // Step 1: verify that required pseudo headers are present
  //
  // The method pseudo header is always mandatory.
  //
  if (header_map.getMethodValue().empty()) {
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  //
  // If this is not a connect request, then we also need the scheme and path pseudo headers.
  // This is based on RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.3:
  //
  // All HTTP/2 requests MUST include exactly one valid value for the ":method", ":scheme",
  // and ":path" pseudo-header fields, unless it is a CONNECT request (Section 8.3). An
  // HTTP request that omits mandatory pseudo-header fields is malformed (Section 8.1.2.6).
  //
  auto is_connect_method = header_map.method() == "CONNECT";
  if (!is_connect_method &&
      (header_map.getSchemeValue().empty() || header_map.getPathValue().empty())) {
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  // Finally, make sure this request only contains allowed headers
  const auto& allowed_headers =
      is_connect_method ? kAllowedPseudoHeadersForConnect : kAllowedPseudoHeaders;
  auto status = HeaderValidator::RequestHeaderMapValidationResult::Accept;

  //
  // Step 2: Verify each request header
  //
  header_map.iterate(
      [this, &status, &allowed_headers](
          const ::Envoy::Http::HeaderEntry& header_entry) -> ::Envoy::Http::HeaderMap::Iterate {
        const auto& header_name = header_entry.key();
        const auto& header_value = header_entry.value();
        const auto& string_header_name = header_name.getStringView();

        if (string_header_name.at(0) == ':' && !allowed_headers.contains(string_header_name)) {
          // This is an unrecognized pseudo header, reject the request
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
  // header is required: https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.4
  //
  if (header_map.getStatusValue().empty()) {
    return HeaderValidator::ResponseHeaderMapValidationResult::Reject;
  }

  //
  // Step 2: Verify each request header
  //
  auto status = HeaderValidator::ResponseHeaderMapValidationResult::Accept;
  header_map.iterate([this, &status](const ::Envoy::Http::HeaderEntry& header_entry)
                         -> ::Envoy::Http::HeaderMap::Iterate {
    const auto& header_name = header_entry.key();
    const auto& header_value = header_entry.value();
    const auto& string_header_name = header_name.getStringView();

    if (string_header_name.at(0) == ':' &&
        !kAllowedPseudoHeaders.contains(header_name.getStringView())) {
      // This is an unrecognized pseudo header, reject the response
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
Http2HeaderValidator::validateMethodPseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  // HTTP Method Registry, from iana.org
  // source: https://www.iana.org/assignments/http-methods/http-methods.xhtml
  static absl::node_hash_set<absl::string_view> kHttpMethodRegistry = {
      "ACL",
      "BASELINE-CONTROL",
      "BIND",
      "CHECKIN",
      "CHECKOUT",
      "CONNECT",
      "COPY",
      "DELETE",
      "GET",
      "HEAD",
      "LABEL",
      "LINK",
      "LOCK",
      "MERGE",
      "MKACTIVITY",
      "MKCALENDAR",
      "MKCOL",
      "MKREDIRECTREF",
      "MKWORKSPACE",
      "MOVE",
      "OPTIONS",
      "ORDERPATCH",
      "PATCH",
      "POST",
      "PRI",
      "PROPFIND",
      "PROPPATCH",
      "PUT",
      "REBIND",
      "REPORT",
      "SEARCH",
      "TRACE",
      "UNBIND",
      "UNCHECKOUT",
      "UNLINK",
      "UNLOCK",
      "UPDATE",
      "UPDATEREDIRECTREF",
      "VERSION-CONTROL",
      "*",
  };

  return kHttpMethodRegistry.contains(value.getStringView())
             ? HeaderValidator::HeaderEntryValidationResult::Accept
             : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateTransferEncodingHeaderValue(
    const ::Envoy::Http::HeaderString& value) {
  //
  // Only allow a transfer encoding of "trailers" for HTTP/2, based on
  // RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.2:
  //
  // The only exception to this is the TE header field, which MAY be present
  // in an HTTP/2 request; when it is, it MUST NOT contain any value other
  // than "trailers".
  //
  return value.getStringView() == "trailers" ? HeaderValidator::HeaderEntryValidationResult::Accept
                                             : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateSchemePseudoHeaderValue(const SchemaPseudoHeaderValidationMode& mode,
                                                      const ::Envoy::Http::HeaderString& value) {
  //
  // From RFC 3986, https://datatracker.ietf.org/doc/html/rfc3986#section-3.1:
  //
  // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  //
  // Although schemes are case-insensitive, the canonical form is lowercase and
  // documents that specify schemes must do so with lowercase letters. An
  // implementation should accept uppercase letters as equivalent to lowercase
  // in scheme names (e.g., allow "HTTP" as well as "http") for the sake of
  // robustness but should only produce lowercase scheme names for consistency.
  //
  // The validation mode controls whether uppercase letters are permitted.
  //

  // SchemaPseudoHeaderValidationMode::Strict
  static const absl::node_hash_set<char> kStrictCharacterList = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-', '.',
  };

  // SchemaPseudoHeaderValidationMode::AllowUppercase
  static const absl::node_hash_set<char> kExtendedCharacterList = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
      'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
      'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
      'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-', '.',
  };

  const auto& value_string_view = value.getStringView();

  if (value_string_view.empty()) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto character_it = value_string_view.begin();

  // The first character must be an ALPHA
  auto valid_first_character = (*character_it >= 'a' && *character_it <= 'z');
  if (!valid_first_character && mode == SchemaPseudoHeaderValidationMode::AllowUppercase) {
    valid_first_character = (*character_it >= 'A' && *character_it <= 'Z');
  }

  if (!valid_first_character) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  const auto& validation_map = mode == SchemaPseudoHeaderValidationMode::Strict
                                   ? kStrictCharacterList
                                   : kExtendedCharacterList;

  for (++character_it; character_it != value_string_view.end(); ++character_it) {
    if (!validation_map.contains(*character_it)) {
      return HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateAuthorityPseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  //
  // From RFC 3986, https://datatracker.ietf.org/doc/html/rfc3986#section-3.2:
  //
  // authority = [ userinfo "@" ] host [ ":" port ]
  //
  // HTTP/2 deprecates the userinfo portion of the :authority header. Validate
  // the :authority header and reject the value if the userinfo is present. This
  // is beased on RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.3
  //
  // The host portion can be any valid URI host, which this function deos not
  // validate. The port, if present, is validated as a valid uint16_t port.
  //
  const auto& value_string_view = value.getStringView();

  auto user_info_delimiter = value_string_view.find('@');
  if (user_info_delimiter != absl::string_view::npos) {
    // :authority cannot contain user info, reject the header
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  // identify and validate the port, if present
  auto port_delimiter = value_string_view.find(':');
  auto host_string_view = value_string_view.substr(0, port_delimiter);

  if (host_string_view.empty()) {
    // reject empty host, which happens if the authority is just the port (e.g.- ":80").
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  if (port_delimiter != absl::string_view::npos) {
    // Validate the port is an integer and a valid port number (uint16_t)
    auto port_string_view = value_string_view.substr(port_delimiter + 1);

    auto port_string_view_size = port_string_view.size();
    if (port_string_view_size == 0 || port_string_view_size > 5) {
      return HeaderValidator::HeaderEntryValidationResult::Reject;
    }

    auto buffer_start = port_string_view.data();
    auto buffer_end = buffer_start + port_string_view.size();

    std::uint32_t port_integer_value{};
    auto result = std::from_chars(buffer_start, buffer_end, port_integer_value);
    if (result.ec == std::errc::invalid_argument || result.ptr != buffer_end) {
      return HeaderValidator::HeaderEntryValidationResult::Reject;
    }

    if (port_integer_value == 0 || port_integer_value >= 65535) {
      return HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateStatusPseudoHeaderValue(const StatusPseudoHeaderValidationMode& mode,
                                                      const ::Envoy::Http::HeaderString& value) {
  //
  // This is based on RFC 7231, https://datatracker.ietf.org/doc/html/rfc7231#section-6,
  // describing the list of response status codes.
  //
  // https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
  //
  static const absl::node_hash_set<std::uint32_t> kOfficialStatusCodes = {
      100, 102, 103, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302,
      303, 304, 305, 306, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
      410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428,
      429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511,
  };

  static const absl::node_hash_set<std::uint32_t> kUnofficialStatusCodes = {
      419, 420, 420, 430, 450, 498, 499, 509, 529, 530, 598, 599,
  };

  static const absl::node_hash_set<std::uint32_t> kMicrosoftIISStatusCodes = {
      440,
      449,
      451,
  };

  static const absl::node_hash_set<std::uint32_t> kNginxStatusCodes = {
      444, 494, 495, 496, 497, 499,
  };

  static const absl::node_hash_set<std::uint32_t> kCloudFlareStatusCodes = {
      520, 521, 522, 523, 524, 525, 526, 527, 530,
  };

  static const absl::node_hash_set<std::uint32_t> kAwsElasticLoadBalancerCodes = {
      460,
      463,
      561,
  };

  const auto& value_string_view = value.getStringView();

  auto buffer_start = value_string_view.data();
  auto buffer_end = buffer_start + value_string_view.size();

  std::uint32_t status_value{};
  auto result = std::from_chars(buffer_start, buffer_end, status_value);
  if (result.ec == std::errc::invalid_argument) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto status{HeaderValidator::HeaderEntryValidationResult::Reject};

  switch (mode) {
  case StatusPseudoHeaderValidationMode::None:
    status = HeaderValidator::HeaderEntryValidationResult::Accept;
    break;

  case StatusPseudoHeaderValidationMode::ValueRange:
    if (status_value >= 100 && status_value <= 599) {
      status = HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  case StatusPseudoHeaderValidationMode::AllowKnownValues:
    if (kOfficialStatusCodes.contains(status_value) ||
        kUnofficialStatusCodes.contains(status_value) ||
        kMicrosoftIISStatusCodes.contains(status_value) ||
        kNginxStatusCodes.contains(status_value) || kCloudFlareStatusCodes.contains(status_value) ||
        kAwsElasticLoadBalancerCodes.contains(status_value)) {
      status = HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  case StatusPseudoHeaderValidationMode::Strict:
    if (kOfficialStatusCodes.contains(status_value)) {
      status = HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  default:
    break;
  }

  return status;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validatePathPseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  static_cast<void>(value);
  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateGenericHeaderKey(const GenericHeaderNameValidationMode& mode,
                                               const ::Envoy::Http::HeaderString& key) {
  //
  // Use the nghttp2 character map to verify that the header name is valid. This
  // also honors the underscore in header configuration setting.
  //
  // From RFC 7230, https://datatracker.ietf.org/doc/html/rfc7230:
  //
  // header-field   = field-name ":" OWS field-value OWS
  // field-name     = token
  // token          = 1*tchar
  //
  // tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
  //                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
  //                / DIGIT / ALPHA
  //                ; any VCHAR, except delimiters
  //
  //
  // Also, for HTTP/2, connection-specific headers must be treated as malformed.
  // From RFC 7540, https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.2:
  //
  // any message containing connection-specific header fields MUST be treated
  // as malformed (Section 8.1.2.6).
  //
  static const absl::node_hash_set<absl::string_view> kRejectHeaderNames = {
      "transfer-encoding", "connection", "upgrade", "keep-alive", "proxy-connection"};

  const auto& key_string_view = key.getStringView();
  bool allow_underscores = mode == GenericHeaderNameValidationMode::Strict;
  // This header name is initially invalid if the name is empty or if the name
  // matches an incompatible connection-specific header.
  bool is_valid = key_string_view.size() > 0 && !kRejectHeaderNames.contains(key_string_view);

  for (std::size_t i{0}; i < key_string_view.size() && is_valid; ++i) {
    const auto& c = key_string_view.at(i);
    is_valid = kNghttp2HeaderNameCharacterValidationMap[static_cast<unsigned char>(c)] &&
               (c != '_' || allow_underscores);
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateGenericHeaderValue(const ::Envoy::Http::HeaderString& value) {
  //
  // use the nghttp2 character map to verify the header value is valid.
  //
  // From RFC 7230, https://datatracker.ietf.org/doc/html/rfc7230:
  //
  // header-field   = field-name ":" OWS field-value OWS
  // field-value    = *( field-content / obs-fold )
  // field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
  // field-vchar    = VCHAR / obs-text
  // obs-text       = %x80-FF
  //
  // VCHAR          =  %x21-7E
  //                   ; visible (printing) characters
  //
  const auto& value_string_view = value.getStringView();
  bool is_valid = true;

  for (std::size_t i{0}; i < value_string_view.size() && is_valid; ++i) {
    const auto& c = value_string_view.at(i);
    is_valid = kNghttp2HeaderValueCharacterValidationMap[static_cast<unsigned char>(c)];
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
Http2HeaderValidator::validateContentLength(const ::Envoy::Http::HeaderString& value) {
  //
  // From RFC 7230, https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2:
  //
  // Content-Length = 1*DIGIT
  //
  const auto& value_string_view = value.getStringView();

  if (!value_string_view.size()) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto buffer_start = value_string_view.data();
  auto buffer_end = buffer_start + value_string_view.size();

  std::uint32_t int_value{};
  auto result = std::from_chars(buffer_start, buffer_end, int_value);
  if (result.ec == std::errc::invalid_argument || result.ptr != buffer_end) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
