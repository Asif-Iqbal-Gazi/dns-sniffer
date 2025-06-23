#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h> // For uint8_t, uint16_t, uint32_t

// --- Constants ---
#define DNS_PORT 53
#define MAX_DOMAINS 256
#define MAX_LINE_LEN 256
#define DNS_MAX_LABEL_LENGTH 63 // Max length of a single DNS label (www, example, com are labels)
#define DNS_MAX_NAME_LENGTH 256 // Max length of a full DNS domain name (including null terminator)
#define DNS_MAX_PAYLOAD_SIZE 512
#define ETH_HDR_SIZE sizeof(struct ether_header)
#define IP_HDR_SIZE sizeof(struct ip)
#define UDP_HDR_SIZE sizeof(struct udphdr)
#define DNS_HDR_SIZE 12
#define DNS_LABEL_COMPRESSION_MASK 0xC000

// --- Main DNS Packet Structure ---

// All DNS packets have a structure:
//      +--------------------+
//      | Header             |
//      +--------------------+
//      | Question           | Question for the name server
//      +--------------------+
//      | Answer             | Answers to the question
//      +--------------------+
//      | Authority          | Authority records (e.g., NS records for
//      authoraitative servers)
//      +--------------------+
//      | Additional         | Additional records (e.g., A records for NS
//      servers)
//      +--------------------+

// DNS Header:
//                                      1  1  1  1  1  1
//        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                       ID                      |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |QR| Opcode |AA|TC|RD|RA|    Z   |     RCODE    |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                   QDCOUNT                     |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                   ANCOUNT                     |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                   NSCOUNT                     |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                   ARCOUNT                     |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//      DNS questions:
//                                      1  1  1  1  1  1
//        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                                               |
//      /                     QNAME                     /
//      /                                               /
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                     QTYPE                     |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                     QCLASS                    |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//      DNS Answers:
//                                      1  1  1  1  1  1
//        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                                               |
//      /                                               /
//      /                       NAME                    /
//      |                                               |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                       TYPE                    |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                      CLASS                    |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                        TTL                    |
//      |                                               |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//      |                     RDLENGTH                  |
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//      /                       RDATA                   /
//      /                                               /
//      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNS Header: (12 bytes)
// All fields are in Network Byte Order.
// Use nthos() for 16-bit fields adn ntohl() for 32-bit fields.
typedef struct __attribute__((packed)) {
  uint16_t id; // Identification number. Assigned by the querier to match replies.

  // Flags field breakdown (16 bits):
  //  15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // |QR| Opcode |AA|TC|RD|RA|   Z    |     RCODE    |
  // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  // QR (Query/Response):       0 for query, 1 for response.
  // Opcode:                    Type of query (see dns_opcode_t).
  // AA (Authoritative):        1 if response if form authoritative server.
  // TC (Trucncated):           1 if message was truncated.
  // RD (Recursion Desired):    1 if recursive query is desired.
  // RA (Recursion Avail):      1 if server supports recursion.
  // Z (Reserved):              Must be zero.
  // RCODE:                     Response code (see dns_rcode_t).
  uint16_t flags;

  uint16_t qdcount; // Number of questions in the Questions section.
  uint16_t ancount; // Number of resource records in the Answer section.
  uint16_t nscount; // Number of resource records in the Authority section.
  uint16_t arcount; // Number of resource records in the Additional section.
} dns_header_t;

// Flags masks and shifts
#define DNS_FLAG_QR_MASK 0x8000     // Query (0) / Response (1)
#define DNS_FLAG_OPCODE_MASK 0x7800 // Opcode (4 bits)
#define DNS_FLAG_OPCODE_SHIFT 11
#define DNS_FLAG_AA_MASK 0x0400    // Authoritative Answer
#define DNS_FLAG_TC_MASK 0x0200    // Truncated Message
#define DNS_FLAG_RD_MASK 0x0100    // Recursion Desired
#define DNS_FLAG_RA_MASK 0x0080    // Recursion Available
#define DNS_FLAG_Z_MASK 0x0070     // Reserved (must be zero)
#define DNS_FLAG_AD_MASK 0x0020    // Authenticated Data (RFC 4035)
#define DNS_FLAG_CD_MASK 0x0010    // Checking Disabled (RFC 4035)
#define DNS_FLAG_RCODE_MASK 0x000F // Response Code (4 bits)

// --- Enums for DNS Header Fields ---

// DNS Opcode (4 bits in flags)
typedef enum {
  DNS_OPCODE_QUERY  = 0, // Standard query
  DNS_OPCODE_IQUERY = 1, // Inverse query (obsolete)
  DNS_OPCODE_STATUS = 2, // Server status request (obsolete)
  // Opcodes 3-15 are reserved
  DNS_OPCODE_NOTIFY = 4, // Notify (RFC 1996)
  DNS_OPCODE_UPDATE = 5  // Update (RFC 2136)
} dns_opcode_t;

// DNS Response Code (RCODE - 4 bits in flags)
typedef enum {
  DNS_RCODE_NOERROR    = 0, // No error
  DNS_RCODE_FORMAT_ERR = 1, // Format error - The name server was unable to interpret the query.
  DNS_RCODE_SERV_FAIL  = 2, // Server failure - The name server was unable to process this query
                            // due to a problem with the name server.
  DNS_RCODE_NXDOMAIN = 3,   // Non-Existent Domain
  DNS_RCODE_NOT_IMPL = 4,   // Not Implemented - The name server does not support
                            // the requested kind of query.
  DNS_RCODE_REFUSED = 5,    // Refused - The name server refuses to perform the
                            // specified operation for policy reasons.
                            // ... (other extended RCODEs beyond RFC 1035)
} dns_rcode_t;

// --- Enums for Resource Record Types (QTYPE/TYPE) ---
// These are used in the Question section (QTYPE) and Resource Record sections
// (TYPE). Only common types are listed.
typedef enum {
  DNS_TYPE_A     = 1,  // a host address (IPv4)
  DNS_TYPE_NS    = 2,  // an authoritative name server
  DNS_TYPE_MD    = 3,  // a mail destination (obsolete)
  DNS_TYPE_MF    = 4,  // a mail forwarder (obsolete)
  DNS_TYPE_CNAME = 5,  // the canonical name for an alias
  DNS_TYPE_SOA   = 6,  // marks the start of a zone of authority
  DNS_TYPE_MB    = 7,  // a mailbox domain name (experimental)
  DNS_TYPE_MG    = 8,  // a mail group member (experimental)
  DNS_TYPE_MR    = 9,  // a mail rename domain name (experimental)
  DNS_TYPE_NULL  = 10, // a null RR (experimental)
  DNS_TYPE_WKS   = 11, // a well known service description
  DNS_TYPE_PTR   = 12, // a domain name pointer
  DNS_TYPE_HINFO = 13, // host information
  DNS_TYPE_MINFO = 14, // mailbox or mail list information
  DNS_TYPE_MX    = 15, // mail exchange
  DNS_TYPE_TXT   = 16, // text strings
  DNS_TYPE_AAAA  = 28, // IPv6 host address (RFC 3596)
  DNS_TYPE_SRV   = 33, // Service record (RFC 2782)
  DNS_TYPE_ALL   = 255 // A request for all records (ANY)
} dns_rr_type_t;

// --- Enums for Resource Record Classes (QCLASS/CLASS) ---
// These are used in the Question section (QCLASS) and Resource Record sections
// (CLASS).
typedef enum {
  DNS_CLASS_IN = 1, // Internet (most common)
  DNS_CLASS_CS = 2, // CSNET class (obsolete)
  DNS_CLASS_CH = 3, // CHAOS class
  DNS_CLASS_HS = 4, // Hesiod class
  // Classes 5-254 are reserved
  DNS_CLASS_ANY = 255 // A request for any class
} dns_rr_class_t;

// --- Conceptual DNS Resource Record (RR) Structure ---
// This structure is common to Answer, Authority, and Additional sections.
// NOTE: NAME and RDATA are variable-length fields (and can be compressed).
// Therefore, this struct represents the *parsed* components, not a direct
// memory map. NAME needs to be parsed separately, and RDATA's format depends on
// TYPE.
typedef struct __attribute__((packed)) {
  // char name[DNS_MAX_NAME_LENGTH + 1]; // Store parsed domain name here
  // dns_rr_type_t type;   // Type of record (e.g., DNS_TYPE_A, DNS_TYPE_MX)
  uint16_t rtype; // Type of record (e.g., DNS_TYPE_A, DNS_TYPE_MX)
  // dns_rr_class_t class; // Class of record (e.g., DNS_CLASS_IN)
  uint16_t rclass;   // Class of record (e.g., DNS_CLASS_IN)
  uint32_t ttl;      // Time To Live in seconds.
  uint16_t rdlength; // Length of the RDATA field in bytes.
                     // union {                   // RDATA can be union if
                     // parsing specific types
                     //   uint32_t a_record;      // For A records (IPv4)
                     //   uint8_t aaaa_record[16]; // For AAAA records (IPv6)
                     //   // ... other RDATA types
                     // } rdata;
  // const uint8_t *rdata_ptr; // Pointer to raw RDATA bytes for generic
  // handling
} dns_rr_fixed_part_t; // Fixed part of Resource Record

// --- Specific RDATA Structures for Common Record Types (for parsing into) ---
// These are not directly in the packet but are targets for parsed RDATA.

// A Record RDATA (IPv4 Address)
typedef struct {
  uint32_t address; // IPv4 address in network byte order
} dns_rdata_a_t;

// AAAA Record RDATA (IPv6 Address)
typedef struct {
  uint8_t address[16]; // IPv6 address in network byte order
} dns_rdata_aaaa_t;

// MX Record RDATA (Mail Exchange)
// Note: 'exchange' is a domain name, so it's variable length and compressed.
typedef struct {
  uint16_t preference; // Preference value (lower is preferred)
  // char exchange[DNS_MAX_NAME_LENGTH + 1]; // The mail exchange domain name
  // (parsed)
} dns_rdata_mx_t;

// SOA Record RDATA (Start of Authority)
// Note: mname and rname are domain names, variable length and compressed.
typedef struct {
  // char mname[DNS_MAX_NAME_LENGTH + 1]; // Primary name server for this zone
  // (parsed) char rname[DNS_MAX_NAME_LENGTH + 1]; // Responsible person's email
  // (parsed, with '.' instead of
  // '@')
  uint32_t serial;  // Version number of the zone
  uint32_t refresh; // Time interval (seconds) before zone is refreshed
  uint32_t retry;   // Time interval (seconds) before failed refresh is retried
  uint32_t expire;  // Upper limit (seconds) for secondary to cache data if
                    // master is unreachable
  uint32_t minimum; // Minimum TTL (seconds) for records in this zone
} dns_rdata_soa_t;

// SRV Record RDATA (Service Record)
// Note: target is a domain name, variable length and compressed.
typedef struct {
  uint16_t priority; // Priority of this target host (lower is preferred)
  uint16_t weight;   // Relative weight for records with same priority
  uint16_t port;     // Port on which the service is to be found
  // char target[DNS_MAX_NAME_LENGTH + 1]; // Domain name of the target host
  // (parsed)
} dns_rdata_srv_t;

// TXT Record RDATA (Text String)
// Note: RDATA contains length-prefixed strings. Multiple strings can be
// concatenated. This struct is simplified for a single string.
typedef struct {
  uint8_t length; // Length of the text data that follows
                  // char text[256]; // Text data (up to 255 bytes, plus null
                  // terminator)
} dns_rdata_txt_t;

// // domainmapentry with precomputed data
// typedef struct {
//   char    domain[128];
//   char    ip[inet_addrstrlen];
//   int     precomputed_dns_payload_len;
//   uint8_t precomputed_dns_payload[dns_max_payload_size];
// } domainmapentry;
//
// // global variables
// extern int            domain_count;
// extern DomainMapEntry domain_map[MAX_DOMAINS];

#endif // !DNS_PROTOCOL_H
