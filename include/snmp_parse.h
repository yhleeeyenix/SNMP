#ifndef SNMP_PARSE_H
#define SNMP_PARSE_H

#include "snmp.h"

// Function to read length field in ASN.1 BER format
int read_length(unsigned char *buffer, int *index);

// Function to read integer value in ASN.1 BER format
int read_integer(unsigned char *buffer, int *index, int len);

// Function to encode length field in ASN.1 BER format
int write_length(unsigned char *buffer, int len);

// Function to encode length at a specific position
int encode_length_at(unsigned char *buffer, int length);

// Function to encode length field
int encode_length(unsigned char *buffer, int length);

// Function to encode integer value
int encode_integer(long value, unsigned char *buffer);

// Function to encode OID to binary format
int encode_oid(const oid *oid_numbers, int oid_len, unsigned char *buffer);

// Function to compare OIDs
int oid_compare(const unsigned char *oid1, int oid1_len, const unsigned char *oid2, int oid2_len);

// SNMP message parsing functions
void parse_tlv(unsigned char *buffer, int *index, int length, SNMPPacket *snmp_packet);
void parse_pdu(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet, unsigned char pdu_type);
void parse_scoped_pdu(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet);
void parse_usm_security_parameters(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet);
void parse_snmpv3_message(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet);

#endif // SNMP_PARSE_H
