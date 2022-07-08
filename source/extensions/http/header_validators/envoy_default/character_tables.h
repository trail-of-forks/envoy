#pragma once

#include <cstdint>

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {

inline bool test_char(const uint32_t table[8], char c) {
  uint8_t uc = static_cast<uint8_t>(c);
  return (table[uc >> 5] & (0x80000000 >> (uc & 0x1f))) != 0;
}

//
// Header name character table.
// From RFC 7230: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
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
const uint32_t kGenericHeaderNameCharTable[] = {
    // control characters
    0b00000000000000000000000000000000,
    // !"#$%&'()*+,-./0123456789:;<=>?
    0b01011111001101101111111111000000,
    //@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
    0b01111111111111111111111111100011,
    //`abcdefghijklmnopqrstuvwxyz{|}~
    0b11111111111111111111111111101010,
    // extended ascii
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
};

//
// Header value character table.
// From RFC 7230: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
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
const uint32_t kGenericHeaderValueCharTable[] = {
    // control characters
    0b00000000010000000000000000000000,
    // !"#$%&'()*+,-./0123456789:;<=>?
    0b11111111111111111111111111111111,
    //@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
    0b11111111111111111111111111111111,
    //`abcdefghijklmnopqrstuvwxyz{|}~
    0b11111111111111111111111111111111,
    // extended ascii
    0b11111111111111111111111111111111,
    0b11111111111111111111111111111111,
    0b11111111111111111111111111111111,
    0b11111111111111111111111111111111,
};

//
// :method header character table.
// From RFC 7230: https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1
//
// method = token
// token = 1*tchar
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "."
//       /  "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
//
const uint32_t kMethodHeaderCharTable[] = {
    // control characters
    0b00000000000000000000000000000000,
    // !"#$%&'()*+,-./0123456789:;<=>?
    0b01011111001101101111111111000000,
    //@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
    0b01111111111111111111111111100011,
    //`abcdefghijklmnopqrstuvwxyz{|}~
    0b11111111111111111111111111101010,
    // extended ascii
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
};

//
// :scheme header character table.
// From RFC 3986: https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
//
// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//
const uint32_t kSchemeHeaderCharTable[] = {
    // control characters
    0b00000000000000000000000000000000,
    // !"#$%&'()*+,-./0123456789:;<=>?
    0b00000000000101101111111111000000,
    //@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
    0b01111111111111111111111111100000,
    //`abcdefghijklmnopqrstuvwxyz{|}~
    0b01111111111111111111111111100000,
    // extended ascii
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
};

} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
