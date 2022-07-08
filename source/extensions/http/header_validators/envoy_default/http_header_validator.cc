#include "source/extensions/http/header_validators/envoy_default/http_header_validator.h"

#include <charconv>

#include "source/extensions/http/header_validators/envoy_default/character_tables.h"

#include "absl/container/node_hash_set.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;
using ::Envoy::Http::HeaderValidator;

HttpHeaderValidator::HttpHeaderValidator(const HeaderValidatorConfig& config,
                                         StreamInfo::StreamInfo&)
    : config_(config), header_values_(::Envoy::Http::Headers::get()) {}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateMethodHeader(const HeaderString& value) {
  // HTTP Method Registry, from iana.org:
  // source: https://www.iana.org/assignments/http-methods/http-methods.xhtml
  //
  // From the RFC:
  //
  // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "."
  //       /  "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
  // token = 1*tchar
  // method = token
  //
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

  const auto& method = value.getStringView();
  bool is_valid = true;

  if (config_.restrict_http_methods()) {
    is_valid = kHttpMethodRegistry.contains(method);
  } else {
    is_valid = !method.empty();
    for (std::size_t i = 0; i < method.size() && is_valid; ++i) {
      is_valid = test_char(kMethodHeaderCharTable, method.at(i));
    }
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateSchemeHeader(const HeaderString& value) {
  //
  // From RFC 3986, https://datatracker.ietf.org/doc/html/rfc3986#section-3.1:
  //
  // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  //
  // Although schemes are case-insensitive, the canonical form is lowercase and documents that
  // specify schemes must do so with lowercase letters. An implementation should accept uppercase
  // letters as equivalent to lowercase in scheme names (e.g., allow "HTTP" as well as "http") for
  // the sake of robustness but should only produce lowercase scheme names for consistency.
  //
  // The validation mode controls whether uppercase letters are permitted.
  //
  const auto& value_string_view = value.getStringView();

  if (value_string_view.empty()) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto character_it = value_string_view.begin();

  // The first character must be an ALPHA
  auto valid_first_character = (*character_it >= 'a' && *character_it <= 'z') ||
                               (*character_it >= 'A' && *character_it <= 'Z');
  if (!valid_first_character) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  for (++character_it; character_it != value_string_view.end(); ++character_it) {
    if (!test_char(kSchemeHeaderCharTable, *character_it)) {
      return HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateStatusHeader(const StatusPseudoHeaderValidationMode& mode,
                                          const HeaderString& value) {
  //
  // This is based on RFC 7231, https://datatracker.ietf.org/doc/html/rfc7231#section-6,
  // describing the list of response status codes and the list of registered response status codes,
  // https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml.
  //
  static const absl::node_hash_set<std::uint32_t> kOfficialStatusCodes = {
      100, 102, 103, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302,
      303, 304, 305, 306, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
      410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428,
      429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511,
  };
  static const uint32_t kMinimumResponseStatusCode = 100;
  static const uint32_t kMaximumResponseStatusCode = 599;

  const auto& value_string_view = value.getStringView();

  auto buffer_start = value_string_view.data();
  auto buffer_end = buffer_start + value_string_view.size();

  // Convert the status to an integer.
  std::uint32_t status_value{};
  auto result = std::from_chars(buffer_start, buffer_end, status_value);
  if (result.ec == std::errc::invalid_argument || result.ptr != buffer_end) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto status{HeaderValidator::HeaderEntryValidationResult::Reject};

  switch (mode) {
  case StatusPseudoHeaderValidationMode::WholeNumber:
    status = HeaderValidator::HeaderEntryValidationResult::Accept;
    break;

  case StatusPseudoHeaderValidationMode::ValueRange:
    if (status_value >= kMinimumResponseStatusCode && status_value <= kMaximumResponseStatusCode) {
      status = HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  case StatusPseudoHeaderValidationMode::OfficialStatusCodes:
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
HttpHeaderValidator::validateGenericHeaderName(const HeaderString& name) {
  //
  // Verify that the header name is valid. This also honors the underscore in
  // header configuration setting.
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
  const auto& key_string_view = name.getStringView();
  bool allow_underscores = !config_.reject_headers_with_underscores();
  // This header name is initially invalid if the name is empty or if the name
  // matches an incompatible connection-specific header.
  bool is_valid = !key_string_view.empty();

  for (std::size_t i{0}; i < key_string_view.size() && is_valid; ++i) {
    char c = key_string_view.at(i);
    is_valid = test_char(kGenericHeaderNameCharTable, c) && (c != '_' || allow_underscores);
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateGenericHeaderValue(const HeaderString& value) {
  //
  // Verify that the header value is valid.
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
    is_valid = test_char(kGenericHeaderValueCharTable, value_string_view.at(i));
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateContentLengthHeader(const HeaderString& value) {
  //
  // From RFC 7230, https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2:
  //
  // Content-Length = 1*DIGIT
  //
  const auto& value_string_view = value.getStringView();

  if (value_string_view.empty()) {
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

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateHostHeader(const HeaderString& value) {
  //
  // From RFC 7230, https://datatracker.ietf.org/doc/html/rfc7230#section-5.4,
  // and RFC 3986, https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2:
  //
  // Host       = uri-host [ ":" port ]
  // uri-host   = IP-literal / IPv4address / reg-name
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

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
