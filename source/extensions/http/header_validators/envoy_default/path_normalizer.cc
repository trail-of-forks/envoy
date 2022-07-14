#include "source/extensions/http/header_validators/envoy_default/path_normalizer.h"

#include "source/extensions/http/header_validators/envoy_default/character_tables.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

using ::envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig;
using ::envoy::extensions::http::header_validators::envoy_default::v3::
    HeaderValidatorConfig_UriPathNormalizationOptions;
using ::Envoy::Http::HeaderValidator;
using ::Envoy::Http::RequestHeaderMap;

PathNormalizer::PathNormalizer(const HeaderValidatorConfig& config) : config_(config) {}

PathNormalizer::PercentDecodeResult PathNormalizer::normalize_and_decode_octet(char* octet) {
  //
  // From RFC 3986: https://datatracker.ietf.org/doc/html/rfc3986#section-2.1
  //
  // pct-encoded = "%" HEXDIG HEXDIG
  //
  // The uppercase hexadecimal digits 'A' through 'F' are equivalent to
  // the lowercase digits 'a' through 'f', respectively. If two URIs
  // differ only in the case of hexadecimal digits used in percent-encoded
  // octets, they are equivalent. For consistency, URI producers and
  // normalizers should use uppercase hexadecimal digits for all percent-
  // encodings.
  //
  // Also from RFC 3986: https://datatracker.ietf.org/doc/html/rfc3986#section-2.4
  //
  // When a URI is dereferenced, the components and subcomponents significant
  // to the scheme-specific dereferencing process (if any) must be parsed and
  // separated before the percent-encoded octets within those components can
  // be safely decoded, as otherwise the data may be mistaken for component
  // delimiters. The only exception is for percent-encoded octets corresponding
  // to characters in the unreserved set, which can be decoded at any time.
  //
  char ch;
  PercentDecodeResult result{PercentDecodeResult::Invalid};

  if (!isxdigit(octet[1]) || !isxdigit(octet[2])) {
    return result;
  }

  // normalize to UPPERCASE
  octet[1] = octet[1] >= 'a' && octet[1] <= 'z' ? octet[1] ^ 0x20 : octet[1];
  octet[2] = octet[2] >= 'a' && octet[2] <= 'z' ? octet[2] ^ 0x20 : octet[2];

  // decode to character
  ch = octet[1] >= 'A' ? (octet[1] - 'A' + 10) : (octet[1] - '0');
  ch *= 16;
  ch += octet[2] >= 'A' ? (octet[2] - 'A' + 10) : (octet[2] - '0');

  if (test_char(kUnreservedCharTable, ch)) {
    // sBased on RFC, only decode characters in the UNRESERVED set.
    octet[2] = ch;
    result = PercentDecodeResult::Decoded;
  } else if (ch == '/' || ch == '\\') {
    // We decoded a slash character and how we handle it depends on the active configuration.
    switch (config_.uri_path_normalization_options().path_with_escaped_slashes_action()) {
    case HeaderValidatorConfig_UriPathNormalizationOptions::IMPLEMENTATION_SPECIFIC_DEFAULT:
    case HeaderValidatorConfig_UriPathNormalizationOptions::KEEP_UNCHANGED:
      // default implementation: normalize the encoded octet and accept the path
      result = PercentDecodeResult::Normalized;
      break;

    case HeaderValidatorConfig_UriPathNormalizationOptions::REJECT_REQUEST:
      // Reject the entire request
      result = PercentDecodeResult::Reject;
      break;

    case HeaderValidatorConfig_UriPathNormalizationOptions::UNESCAPE_AND_FORWARD:
      // Decode the slash and accept the path.
      octet[2] = ch;
      result = PercentDecodeResult::Decoded;
      break;

    case HeaderValidatorConfig_UriPathNormalizationOptions::UNESCAPE_AND_REDIRECT:
      // Decode the slash and response with a redirect to the normalized path.
      octet[2] = ch;
      result = PercentDecodeResult::DecodedRedirect;
      break;

    default:
      break;
    }
  } else {
    // The octet is a valid encoding but it wasn't be decoded because it was outside the UNRESERVED
    // character set.
    result = PercentDecodeResult::Normalized;
  }

  return result;
}

HeaderValidator::RequestHeaderMapValidationResult
PathNormalizer::normalizePathUri(RequestHeaderMap& header_map) {
  // Make a copy of the original path so we can edit it in place.
  absl::string_view original_path = header_map.path();
  size_t length = original_path.size();
  char* path = new char[length + 1];
  std::unique_ptr<char> path_ptr{path}; // auto free on return

  original_path.copy(path, length);

  // We rely on the string being null terminated so that we can safely look forward 1 character.
  path[length] = '\0';

  // Start normalizing the path.
  char* read = path;
  char* write = path;
  char* end = path + length;
  bool redirect = false;

  if (*read != '/') {
    // Reject relative paths
    return HeaderValidator::RequestHeaderMapValidationResult::Reject;
  }

  ++read;
  ++write;

  //
  // Path normalization is based on RFC 3986:
  // https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
  //
  // path          = path-abempty    ; begins with "/" or is empty
  //               / path-absolute   ; begins with "/" but not "//"
  //               / path-noscheme   ; begins with a non-colon segment
  //               / path-rootless   ; begins with a segment
  //               / path-empty      ; zero characters
  //
  // path-abempty  = *( "/" segment )
  // path-absolute = "/" [ segment-nz *( "/" segment ) ]
  // path-noscheme = segment-nz-nc *( "/" segment )
  // path-rootless = segment-nz *( "/" segment )
  // path-empty    = 0<pchar>
  // segment       = *pchar
  // segment-nz    = 1*pchar
  // segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
  //               ; non-zero-length segment without any colon ":"
  //
  // pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
  //

  while (read < end) {
    char ch = *read;
    char prev = *(write - 1);

    switch (ch) {
    case '%': {
      // Potential percent-encoded octet
      auto decode_result = normalize_and_decode_octet(read);
      if (decode_result == PercentDecodeResult::Reject) {
        // invalid encoding
        return HeaderValidator::RequestHeaderMapValidationResult::Reject;
      } else if (decode_result == PercentDecodeResult::Normalized) {
        // valid encoding but outside the UNRESERVED character set
        // copy the normalized encoding (3 characters)
        *write++ = *read++;
        *write++ = *read++;
        *write++ = *read++;
      } else if (decode_result == PercentDecodeResult::Decoded) {
        // the decoded character is stored as the last character in
        // the octet. advance read to the decoded character so it'll
        // be processed in the next iteration
        read += 2;
      } else if (decode_result == PercentDecodeResult::DecodedRedirect) {
        // the decoded character is stored as the last character in
        // the octet. advance read to the decoded character so it'll
        // be processed in the next iteration
        read += 2;
        redirect = true;
      }
      break;
    }

    case '.': {
      // Potential "/./" or "/../" sequence
      if (*(read + 1) == '/' || (read + 1) == end) {
        // this is a "./" token.
        if (prev == '/') {
          // ignore "/./"
          read += 2;
        } else if (prev == '.' && *(write - 2) == '/') {
          // process "/../"
          // back write up to the previous slash
          write -= 2;
          if (write == path) {
            // the full input is: /.., this is a bad request
            return HeaderValidator::RequestHeaderMapValidationResult::Reject;
          }

          // reset write to overwrite the parent segment
          while (write > path && *(write - 1) != '/') {
            --write;
          }

          // skip the "./" token since it's been handled
          read += 2;
        } else {
          // just a dot in a normal path segment, copy it
          *write++ = *read++;
        }
      } else {
        // just a dot in a normal path segment, copy it
        *write++ = *read++;
      }
      break;
    }

    case '/': {
      if (prev == '/' && !config_.uri_path_normalization_options().skip_merging_slashes()) {
        // merge duplicate slash
        ++read;
      } else {
        *write++ = *read++;
      }
      break;
    }

    default: {
      if (test_char(kPathHeaderCharTable, ch)) {
        *write++ = *read++;
      } else {
        return HeaderValidator::RequestHeaderMapValidationResult::Reject;
      }
    }
    }
  }

  *write = '\0';

  auto normalized_length = static_cast<size_t>(write - path);
  absl::string_view normalized_path{path, normalized_length};
  header_map.setPath(normalized_path);

  return redirect ? HeaderValidator::RequestHeaderMapValidationResult::Redirect
                  : HeaderValidator::RequestHeaderMapValidationResult::Accept;
}

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
