#include "source/extensions/http/header_validators/envoy_default/header_validator.h"

#include <charconv>

#include "absl/container/node_hash_set.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::Envoy::Http::HeaderString;

namespace {

template <typename HeaderMapType, typename ReturnType>
ReturnType validateHeaderMap(const HeaderMapType& header_map,
                             const absl::node_hash_set<absl::string_view>& allowed_headers) {

  static_assert(std::is_same<HeaderMapType, ::Envoy::Http::RequestHeaderMap>::value ||
                    std::is_same<HeaderMapType, ::Envoy::Http::ResponseHeaderMap>::value,
                "Invalid HeaderMapType template parameter");

  static_assert(
      std::is_same<ReturnType,
                   ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult>::value ||
          std::is_same<ReturnType,
                       ::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult>::value,
      "Invalid ReturnType template parameter");

  auto result = ReturnType::Accept;

  header_map.iterate([&result, &allowed_headers](const ::Envoy::Http::HeaderEntry& header_entry)
                         -> ::Envoy::Http::HeaderMap::Iterate {
    const auto& header_name = header_entry.key();
    const auto& string_header_name = header_name.getStringView();

    if (string_header_name.at(0) != ':') {
      return ::Envoy::Http::HeaderMap::Iterate::Continue;
    }

    if (!allowed_headers.contains(header_name.getStringView())) {
      result = ReturnType::Reject;
      return ::Envoy::Http::HeaderMap::Iterate::Break;
    }

    return ::Envoy::Http::HeaderMap::Iterate::Continue;
  });

  return result;
}

} // namespace

HeaderValidatorFactory::HeaderValidatorFactory(const HeaderValidatorConfig& config)
    : config_(config) {}

::Envoy::Http::HeaderValidatorPtr
HeaderValidatorFactory::create(::Envoy::Http::HeaderValidatorFactory::Protocol protocol,
                               StreamInfo::StreamInfo& stream_info) {
  return std::make_unique<HeaderValidator>(config_, protocol, stream_info);
}

HeaderValidator::HeaderValidator(const HeaderValidatorConfig& config,
                                 ::Envoy::Http::HeaderValidatorFactory::Protocol protocol,
                                 StreamInfo::StreamInfo&)
    : config_(config), protocol_(protocol) {}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateRequestHeaderEntry(const HeaderString& key, const HeaderString& value) {

  auto status{::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept};

  if (protocol_ == ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP2) {
    status = validateHttp2RequestHeaderEntry(config_.restrict_http_methods(), key, value);
  }

  return status;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateResponseHeaderEntry(const HeaderString& key, const HeaderString& value) {
  auto status{::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept};

  if (protocol_ == ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP2) {
    status = validateHttp2ResponseHeaderEntry(key, value);
  }

  return status;
}

::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult
HeaderValidator::validateRequestHeaderMap(::Envoy::Http::RequestHeaderMap& header_map) {

  auto status{::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Accept};

  if (protocol_ == ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP2) {
    status = validateHttp2RequestPseudoHeaderKeys(header_map);
  }

  return status;
}

::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult
HeaderValidator::validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap& header_map) {
  auto status{::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult::Accept};

  if (protocol_ == ::Envoy::Http::HeaderValidatorFactory::Protocol::HTTP2) {
    status = validateHttp2ResponsePseudoHeaderKeys(header_map);
  }

  return status;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateHttp2ResponseHeaderEntry(const ::Envoy::Http::HeaderString& key,
                                                  const ::Envoy::Http::HeaderString& value) {
  const auto& key_string_view = key.getStringView();

  if (key_string_view == ":status") {
    return validateStatusPseudoHeaderValue(StatusPseudoHeaderValidationMode::AllowKnownValues,
                                           value);
  }

  auto status = validateGenericHeaderKey(key);
  if (status != ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept) {
    return status;
  }

  return validateGenericHeaderValue(value);
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateHttp2RequestHeaderEntry(bool restrict_http_methods,
                                                 const ::Envoy::Http::HeaderString& key,
                                                 const ::Envoy::Http::HeaderString& value) {
  const auto& key_string_view = key.getStringView();

  if (key_string_view == ":method") {
    auto status{::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept};

    if (restrict_http_methods) {
      status = validateMethodPseudoHeaderValue(value);
    }

    return status;

  } else if (key_string_view == ":authority") {
    return validateAuthorityPseudoHeaderValue(value);

  } else if (key_string_view == ":scheme") {
    return validateSchemePseudoHeaderValue(value);

  } else if (key_string_view == ":path") {
    return validatePathPseudoHeaderValue(value);

  } else if (key_string_view == "TE") {
    return validateHttp2TransferEncodingHeaderValue(value);
  }

  auto status = validateGenericHeaderKey(key);
  if (status != ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept) {
    return status;
  }

  return validateGenericHeaderValue(value);
}

::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult
HeaderValidator::validateHttp2RequestPseudoHeaderKeys(::Envoy::Http::RequestHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeadersForConnect = {
      ":method",
      ":authority",
      ":content-length",
  };

  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {
      ":method", ":scheme", ":authority", ":path", ":content-length",
  };

  // The method pseudo header is always mandatory
  if (header_map.getMethodValue().empty()) {
    return ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  // If this is not a connect request, then we also need the scheme and path pseudo headers
  auto is_connect_method = header_map.method() == "CONNECT";
  if (!is_connect_method &&
      (header_map.getSchemeValue().empty() || header_map.getPathValue().empty())) {
    return ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  // Finally, make sure this request only contains allowed headers
  const auto& allowed_headers =
      is_connect_method ? kAllowedPseudoHeadersForConnect : kAllowedPseudoHeaders;

  auto status = validateHeaderMap<::Envoy::Http::RequestHeaderMap,
                                  ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult>(
      header_map, allowed_headers);

  if (status == ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Reject) {
    return status;
  }

  return ::Envoy::Http::HeaderValidator::RequestHeaderMapValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult
HeaderValidator::validateHttp2ResponsePseudoHeaderKeys(
    ::Envoy::Http::ResponseHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {
      ":status",
      ":content-length",
  };

  if (header_map.getStatusValue().empty()) {
    return ::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult::Reject;
  }

  return validateHeaderMap<::Envoy::Http::ResponseHeaderMap,
                           ::Envoy::Http::HeaderValidator::ResponseHeaderMapValidationResult>(
      header_map, kAllowedPseudoHeaders);
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateMethodPseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  // HTTP Method Registry, from iana.org
  // source: https://www.iana.org/assignments/http-methods/http-methods.xhtml
  absl::node_hash_set<absl::string_view> kHttpMethodRegistry = {
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
             ? ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept
             : ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateHttp2TransferEncodingHeaderValue(
    const ::Envoy::Http::HeaderString& value) {
  return value.getStringView() == "trailers"
             ? ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept
             : ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateSchemePseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  // From the RFC:
  //
  //   scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  //

  static const absl::node_hash_set<char> kAllowedCharacterList = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-', '.',
  };

  const auto& value_string_view = value.getStringView();

  if (value_string_view.empty()) {
    return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto character_it = value_string_view.begin();
  if (*character_it < 'a' || *character_it > 'z') {
    return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  for (++character_it; character_it != value_string_view.end(); ++character_it) {
    if (!kAllowedCharacterList.contains(*character_it)) {
      return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateAuthorityPseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  // From the RFC:
  //
  //   authority = [ userinfo "@" ] host [ ":" port ]
  //
  // The `userinfo` portion is deprecated in HTTP2, so reject the value
  // if it is present.

  const auto& value_string_view = value.getStringView();

  auto user_info_delimiter = value_string_view.find('@');
  if (user_info_delimiter != absl::string_view::npos) {
    return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto port_delimiter = value_string_view.find(':');
  auto host_string_view = value_string_view.substr(0, port_delimiter);

  if (host_string_view.empty()) {
    return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  if (port_delimiter != absl::string_view::npos) {
    auto port_string_view = value_string_view.substr(port_delimiter + 1);

    auto port_string_view_size = port_string_view.size();
    if (port_string_view_size == 0 || port_string_view_size > 5) {
      return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
    }

    auto buffer_start = port_string_view.data();
    auto buffer_end = buffer_start + port_string_view.size();

    std::uint32_t port_integer_value{};
    auto result = std::from_chars(buffer_start, buffer_end, port_integer_value);
    if (result.ec == std::errc::invalid_argument) {
      return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
    }

    if (port_integer_value == 0 || port_integer_value >= 65535) {
      return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateStatusPseudoHeaderValue(const StatusPseudoHeaderValidationMode& mode,
                                                 const ::Envoy::Http::HeaderString& value) {
  // https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
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
    return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  auto status{::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject};

  switch (mode) {
  case StatusPseudoHeaderValidationMode::None:
    status = ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
    break;

  case StatusPseudoHeaderValidationMode::ValueRange:
    if (status_value >= 100 && status_value <= 599) {
      status = ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  case StatusPseudoHeaderValidationMode::AllowKnownValues:
    if (kOfficialStatusCodes.contains(status_value) ||
        kUnofficialStatusCodes.contains(status_value) ||
        kMicrosoftIISStatusCodes.contains(status_value) ||
        kNginxStatusCodes.contains(status_value) || kCloudFlareStatusCodes.contains(status_value) ||
        kAwsElasticLoadBalancerCodes.contains(status_value)) {
      status = ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  case StatusPseudoHeaderValidationMode::Strict:
    if (kOfficialStatusCodes.contains(status_value)) {
      status = ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
    }

    break;

  default:
    break;
  }

  return status;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validatePathPseudoHeaderValue(const ::Envoy::Http::HeaderString& value) {
  static_cast<void>(value);
  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateGenericHeaderKey(const ::Envoy::Http::HeaderString& key) {
  const auto& key_string_view = key.getStringView();

  for (std::size_t i{0}; i < key_string_view.size(); ++i) {
    const auto& c = key_string_view.at(i);

    auto is_valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c == '_') || (c == '-');
    if (!is_valid) {
      return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

::Envoy::Http::HeaderValidator::HeaderEntryValidationResult
HeaderValidator::validateGenericHeaderValue(const ::Envoy::Http::HeaderString& value) {
  // https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format/
  static const absl::node_hash_set<char> kAllowedCharacterList = {
      '_', ' ', ':', ';', '.', ',', '\\', '/', '"', '\'', '?', '!', '(', ')', '{', '}', '[',
      ']', '@', '<', '>', '=', '-', '+',  '*', '#', '$',  '&', '`', '|', '~', '^', '%'};

  const auto& value_string_view = value.getStringView();

  for (std::size_t i{0}; i < value_string_view.size(); ++i) {
    const auto& c = value_string_view.at(i);

    auto is_valid =
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || kAllowedCharacterList.contains(c);
    if (!is_valid) {
      return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Reject;
    }
  }

  return ::Envoy::Http::HeaderValidator::HeaderEntryValidationResult::Accept;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
