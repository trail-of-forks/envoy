#include "source/extensions/http/header_validators/envoy_default/http1_header_validator.h"

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
using ::Envoy::Http::RequestHeaderMap;
using HeaderValidatorFunction =
    HeaderValidator::HeaderEntryValidationResult (Http1HeaderValidator::*)(const HeaderString&);

/*
 * Header validation implementation for the Http/1 codec. This class follows guidance from
 * several RFCS:
 *
 * RFC 3986 <https://datatracker.ietf.org/doc/html/rfc3986> URI Generic Syntax
 * RFC 7230 <https://datatracker.ietf.org/doc/html/rfc7230> HTTP/1.1 Message Syntax
 * RFC 7231 <https://datatracker.ietf.org/doc/html/rfc7231> HTTP/1.1 Semantics and Content
 *
 */
Http1HeaderValidator::Http1HeaderValidator(const HeaderValidatorConfig& config,
                                           StreamInfo::StreamInfo& stream_info)
    : HttpHeaderValidator(config, stream_info) {}

HeaderValidator::HeaderEntryValidationResult
Http1HeaderValidator::validateRequestHeaderEntry(const HeaderString& key,
                                                 const HeaderString& value) {
  static const absl::node_hash_map<absl::string_view, HeaderValidatorFunction> kHeaderValidatorMap{
      {":method", &Http1HeaderValidator::validateMethodHeader},
      {":authority", &Http1HeaderValidator::validateHostHeader},
      {"host", &Http1HeaderValidator::validateHostHeader},
      {":scheme", &Http1HeaderValidator::validateSchemeHeader},
      {":path", &Http1HeaderValidator::validateGenericPathHeader},
      {"transfer-encoding", &Http1HeaderValidator::validateTransferEncodingHeader},
      {"content-length", &Http1HeaderValidator::validateContentLengthHeader},
  };

  const auto& key_string_view = key.getStringView();
  if (key_string_view.empty()) {
    // reject empty header names
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
Http1HeaderValidator::validateResponseHeaderEntry(const HeaderString& key,
                                                  const HeaderString& value) {
  const auto& key_string_view = key.getStringView();
  if (key_string_view.empty()) {
    // reject empty header names
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }

  if (key_string_view == ":status") {
    // Validate the :status header against the RFC valid range (100 <= status <= 599)
    return validateStatusHeader(StatusPseudoHeaderValidationMode::ValueRange, value);
  } else if (key_string_view == "content-length") {
    // Validate the Content-Length header
    return validateContentLengthHeader(value);
  } else if (key_string_view.at(0) != ':') {
    // Validate the generic header name.
    auto name_result = validateGenericHeaderName(key);
    if (name_result == HeaderValidator::HeaderEntryValidationResult::Reject) {
      return name_result;
    }
  }

  // Validate the header value
  return validateGenericHeaderValue(value);
}

HeaderValidator::RequestHeaderMapValidationResult
Http1HeaderValidator::validateRequestHeaderMap(RequestHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {
      ":method", ":scheme", ":authority", ":path"};
  //
  // Step 1: verify that required pseudo headers are present. HTTP/1.1 requests requries the
  // :method and :path headers based on RFC 7230
  // https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1:
  //
  // request-line   = method SP request-target SP HTTP-version CRLF
  //
  if (header_map.getPathValue().empty() || header_map.getMethodValue().empty()) {
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  //
  // HTTP/1.1 also requires the Host header,
  // https://datatracker.ietf.org/doc/html/rfc7230#section-5.4:
  //
  // A client MUST send a Host header field in all HTTP/1.1 request messages.
  // ...
  // A client MUST send a Host header field in an HTTP/1.1 request even if the
  // request-target is in the absolute-form
  // ...
  // If the authority component is missing or undefined for the target URI, then a
  // client MUST send a Host header field with an empty field-value.
  //
  if (header_map.getHostValue().empty()) {
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  //
  // Verify that the path and Host/:authority header matches based on the method.
  // From RFC 7230, https://datatracker.ietf.org/doc/html/rfc7230#section-5.4:
  //
  // When a proxy receives a request with an absolute-form of request-target, the
  // proxy MUST ignore the received Host header field (if any) and instead replace
  // it with the host information of the request-target. A proxy that forwards
  // such a request MUST generate a new Host field-value based on the received
  // request-target rather than forward the received Host field-value.
  // ...
  // If the target URI includes an authority component, then a client MUST send a
  // field-value for Host that is identical to that authority component,
  // excluding any userinfo subcomponent and its "@" delimiter (Section 2.7.1).
  //
  // TODO(meilya) - should this be implemented here in UHV or the H1 codec?
  //
  auto is_connect_method = header_map.method() == header_values_.MethodValues.Connect;
  auto is_options_method = header_map.method() == header_values_.MethodValues.Options;
  auto path_is_star = header_map.path() == "*";
  auto path_is_absolute = header_map.path().at(0) == '/';

  //
  // HTTP/1.1 allows for a path of "*" when for OPTIONS requests, based on RFC
  // 7230, https://datatracker.ietf.org/doc/html/rfc7230#section-5.3.4:
  //
  // The asterisk-form of request-target is only used for a server-wide OPTIONS
  // request
  // ...
  // asterisk-form  = "*"
  //
  if (!is_options_method && path_is_star) {
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  //
  // Step 2: Validate Transfer-Encoding and Content-Length headers.
  // HTTP/1.1 disallows a Transfer-Encoding and Content-Length headers,
  // https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2:
  //
  // A sender MUST NOT send a Content-Length header field in any message that
  // contains a Transfer-Encoding header field.
  //
  // The http1_protocol_options.allow_chunked_length config setting can
  // override the RFC compliance to allow a Transfer-Encoding of "chunked" with
  // a Content-Length set. In this exception case, we remove the Content-Length
  // header.
  //
  if (header_map.TransferEncoding()) {
    //
    // CONNECT methods must not contain a Transfer-Encoding, per RFC 7231,
    // https://tools.ietf.org/html/rfc7231#section-4.3.6:
    //
    // A payload within a CONNECT request message has no defined semantics; sending
    // a payload body on a CONNECT request might cause some existing
    // implementations to reject the request.
    //
    bool is_chunked = absl::EqualsIgnoreCase(header_map.getTransferEncodingValue(),
                                             header_values_.TransferEncodingValues.Chunked);
    if (!is_chunked || is_connect_method) {
      return HeaderValidator::RequestHeaderMapValidationResult::Reject;
    }

    if (header_map.ContentLength()) {
      if (!config_.http1_protocol_options().allow_chunked_length()) {
        // Configuration does not allow chunked length, reject the request
        return HeaderValidator::RequestHeaderMapValidationResult::Reject;
      } else {
        // Allow a chunked transfer encoding and remove the content length.
        header_map.removeContentLength();
      }
    }
  } else if (header_map.ContentLength() && is_connect_method) {
    if (header_map.getContentLengthValue() == "0") {
      // Remove a 0 content length from a CONNECT request
      header_map.removeContentLength();
    } else {
      // A content length in a CONNECT request is malformed
      return HeaderValidator::RequestHeaderMapValidationResult::Reject;
    }
  }

  //
  // Step 3: Normalize and validate :path header
  //
  if (is_connect_method) {
    //
    // The :path must be authority-form for CONNECT method requests. From RFC
    // 7230: https://datatracker.ietf.org/doc/html/rfc7230#section-5.3.3:
    //
    // The authority-form of request-target is only used for CONNECT
    // requests (Section 4.3.6 of [RFC7231]).
    //
    //    authority-form = authority
    //
    //  When making a CONNECT request to establish a tunnel through one or
    //  more proxies, a client MUST send only the target URI's authority
    //  component (excluding any userinfo and its "@" delimiter) as the
    //  request-target.
    //
    if (validateHostHeader(header_map.Path()->value()) == HeaderEntryValidationResult::Reject) {
      return HeaderValidator::RequestHeaderMapValidationResult::Reject;
    }
  } else if (!config_.uri_path_normalization_options().skip_path_normalization() &&
             path_is_absolute) {
    // Validate and normalize the path, which must be a valid URI
    //
    // TODO(meilya) - this will be something like:
    //
    // auto path_result = path_normalizer_.normalizePathUri(header_map);
    // if (path_result != HeaderValidator::RequestHeaderMapValidationResult::Accept) {
    //   return path_result;
    // }
  }

  // If path normalization is disabled or the path isn't absolute then the path will be validated
  // against the RFC character set in validateRequestHeaderEntry.

  //
  // Step 4: Verify each request header
  //
  auto status = HeaderValidator::RequestHeaderMapValidationResult::Accept;
  header_map.iterate([this, &status](const ::Envoy::Http::HeaderEntry& header_entry)
                         -> ::Envoy::Http::HeaderMap::Iterate {
    const auto& header_name = header_entry.key();
    const auto& header_value = header_entry.value();
    const auto& string_header_name = header_name.getStringView();

    if (string_header_name.empty() ||
        (string_header_name.at(0) == ':' && !kAllowedPseudoHeaders.contains(string_header_name))) {
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
Http1HeaderValidator::validateResponseHeaderMap(::Envoy::Http::ResponseHeaderMap& header_map) {
  static const absl::node_hash_set<absl::string_view> kAllowedPseudoHeaders = {":status"};

  //
  // Step 1: verify that required pseudo headers are present
  //
  // For HTTP/1.1 responses, RFC 7230 states that only the :status
  // header is required: https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2
  //
  // status-line = HTTP-version SP status-code SP reason-phrase CRLF
  //
  if (header_map.getStatusValue().empty()) {
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

    if (string_header_name.empty() ||
        (string_header_name.at(0) == ':' &&
         !kAllowedPseudoHeaders.contains(header_name.getStringView()))) {
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
Http1HeaderValidator::validateTransferEncodingHeader(const HeaderString& value) {
  //
  // HTTP/1.1 states that requests with an unrecognized transfer encoding should
  // be rejected, from RFC 7230, https://tools.ietf.org/html/rfc7230#section-3.3.1:
  //
  // A server that receives a request message with a transfer coding it does not
  // understand SHOULD respond with 501 (Not Implemented).
  //
  const auto& encoding = value.getStringView();
  if (!absl::EqualsIgnoreCase(encoding, header_values_.TransferEncodingValues.Chunked)) {
    return HeaderValidator::HeaderEntryValidationResult::Reject;
  }
  return HeaderValidator::HeaderEntryValidationResult::Accept;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
