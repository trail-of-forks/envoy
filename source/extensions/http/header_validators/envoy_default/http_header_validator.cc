#include "source/extensions/http/header_validators/envoy_default/http_header_validator.h"

#include <charconv>

#include "source/extensions/http/header_validators/envoy_default/nghttp2_character_maps.h"

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
    : config_(config) {
}

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

  static absl::node_hash_set<char> kHttpMethodChars = {'!', '#', '$', '%', '&', '\'', '*', '+',
                                                       '-', '.', '^', '_', '`', '|',  '~'};

  const auto& method = value.getStringView();
  bool is_valid = true;

  if (config_.restrict_http_methods()) {
    is_valid = kHttpMethodRegistry.contains(method);
  } else {
    is_valid = method.size() > 0;
    for (std::size_t i = 0; i < method.size() && is_valid; ++i) {
      char c = method[i];
      is_valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 kHttpMethodChars.contains(c);
    }
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateSchemeHeader(const SchemePseudoHeaderValidationMode& mode,
                                          const HeaderString& value) {
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

  // SchemePseudoHeaderValidationMode::Strict
  static const absl::node_hash_set<char> kStrictCharacterList = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-', '.',
  };

  // SchemePseudoHeaderValidationMode::AllowUppercase
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
  if (!valid_first_character && mode == SchemePseudoHeaderValidationMode::AllowUppercase) {
    valid_first_character = (*character_it >= 'A' && *character_it <= 'Z');
  }

  if (!valid_first_character) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  const auto& validation_map = mode == SchemePseudoHeaderValidationMode::Strict
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
HttpHeaderValidator::validateStatusHeader(const StatusPseudoHeaderValidationMode& mode,
                                          const HeaderString& value) {
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
HttpHeaderValidator::validateGenericHeaderName(const HeaderString& name) {
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
  const auto& key_string_view = name.getStringView();
  bool allow_underscores = !config_.reject_headers_with_underscores();
  // This header name is initially invalid if the name is empty or if the name
  // matches an incompatible connection-specific header.
  bool is_valid = key_string_view.size() > 0;

  for (std::size_t i{0}; i < key_string_view.size() && is_valid; ++i) {
    const auto& c = key_string_view.at(i);
    is_valid = kNghttp2HeaderNameCharacterValidationMap[static_cast<unsigned char>(c)] &&
               (c != '_' || allow_underscores);
  }

  return is_valid ? HeaderValidator::HeaderEntryValidationResult::Accept
                  : HeaderValidator::HeaderEntryValidationResult::Reject;
}

HeaderValidator::HeaderEntryValidationResult
HttpHeaderValidator::validateGenericHeaderValue(const HeaderString& value) {
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
HttpHeaderValidator::validateContentLengthHeader(const HeaderString& value) {
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
