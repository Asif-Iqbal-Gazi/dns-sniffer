#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <stdint.h> // For uint16_t, unint32_t

// --- Main DNS Packet Structure ---

// All DNS packets have a structure:
//      +--------------------+
//      | Header             |
//      +--------------------+
//      | Question           | Question for the name server
//      +--------------------+
//      | Answer             | Answers to the question
//      +--------------------+
//      | Authority          | Authority records (e.g., NS records for authoraitative servers)
//      +--------------------+
//      | Additional         | Additional records (e.g., A records for NS servers)
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
typedef struct {
  uint16_t id;      // Identification number. Assigned by the querier to match replies.
  uint16_t flags;   // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
  uint16_t qdcount; // Number of questions
  uint16_t ancount; // Number of answer resource records
  uint16_t nscount; // Number of authority resource records
  uint16_t arcount; // Number of additional resource records
} dns_header_t;

// --- Conceptual DNS Question Structure ---
// Note: QNAME is variable length and requires special parsing,
// so this struct cannot hold the QNAME directly in a fixed size array.
// It's more of a conceptual layout or used for pointers after parsing QNAME.
typedef struct {
  // char qname[]; // QNAME is variable and often compressed. Parsed separately.
  uint16_t qtype;  // Query Type (e.g., 1 for A record, 28 for AAAA)
  uint16_t qclass; // Query Class (e.g., 1 for IN - Internet)
} dns_question_t;

// --- Conceptual DNS Resource Record (Answer/Authority/Additional) Structure ---
// Similar to question, NAME and RDATA are variable and complex.
typedef struct {
  // char name[];   // Variable length name, potentially compressed
  uint16_t rtype;    // Resource Record Type
  uint16_t rclass;   // Resource Record Class
  uint32_t ttl;      // Time To Live (seconds)
  uint16_t rdlength; // Length of RDATA field
  // unsigned char rdata[]; // Variable length resource data
} dns_resource_record_t;

#endif // !DNS_PROTOCOL_H
