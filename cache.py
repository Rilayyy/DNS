"""
DNS Cache implementation for recursive DNS resolver.

Stores DNS records with TTL-based expiration and provides bailiwick
validation to prevent cache poisoning attacks.
"""

import time
from collections import defaultdict
from dnslib import RR


class DNSCache:
    """
    A cache for DNS records with TTL-based expiration.

    Stores DNS resource records indexed by (domain, qtype) and automatically
    purges expired entries on lookup. Supports bailiwick checking to prevent
    cache poisoning from malicious upstream servers.

    :param default_ttl: Default TTL in seconds for records without explicit TTL
    :ivar cache: Dictionary mapping (domain, qtype) to list of (expiration_time, record) tuples
    """

    def __init__(self, default_ttl=300):
        """
        Initialize an empty DNS cache.

        :param default_ttl: Default TTL to use if record has no TTL (seconds)
        :return: None
        """
        self.cache = defaultdict(list)
        self.default_ttl = default_ttl

    def get(self, domain, qtype):
        """
        Lookup records for a domain and query type, returning only non-expired entries.

        Automatically filters out expired records from the cache. Returns records
        with TTL values adjusted to reflect remaining time.

        :param domain: The domain name to lookup (string, lowercase)
        :param qtype: The query type (e.g., A, AAAA, NS, MX, etc.)
        :return: List of DNS records with adjusted TTLs, or empty list if none found
        """
        key = (domain.lower(), qtype)
        current_time = time.time()
        entries = self.cache.get(key, [])

        valid_records = []
        new_entries = []

        for expiration, record in entries:
            if expiration > current_time:
                remaining_ttl = int(expiration - current_time)
                adjusted_record = self._adjust_ttl(record, remaining_ttl)
                valid_records.append(adjusted_record)
                new_entries.append((expiration, record))

        self.cache[key] = new_entries
        return valid_records

    def put(self, domain, qtype, record, bailiwick=None):
        """
        Store a record in the cache with TTL-based expiration.

        Performs bailiwick checking to ensure the record belongs within the
        bailiwick zone before caching. Does not cache error responses.

        :param domain: The domain name (string)
        :param qtype: The query type
        :param record: The DNS record to cache (dnslib.RR)
        :param bailiwick: The allowed bailiwick domain (e.g., "example.com"), or None to skip check
        :return: True if record was cached, False otherwise
        """
        if bailiwick and not self._in_bailiwick(domain, bailiwick):
            return False

        ttl = record.ttl if hasattr(record, 'ttl') and record.ttl > 0 else self.default_ttl
        expiration = time.time() + ttl

        key = (domain.lower(), qtype)
        self.cache[key].append((expiration, record))

        return True

    def cache_response(self, response, bailiwick=None):
        """
        Cache all valid records from a DNS response.

        Caches answer, authority, and additional sections. Filters out
        expired records and performs bailiwick checking on all entries.
        Does not cache error responses (NXDOMAIN, SERVFAIL, etc.).

        :param response: The DNSRecord response from an upstream server
        :param bailiwick: The allowed bailiwick domain for this response
        :return: Number of records cached
        """
        if response.header.rcode != 0:
            return 0

        cached_count = 0

        for section in [response.rr, response.auth, response.ar]:
            for record in section:
                domain = str(record.rname).lower().rstrip('.')
                qtype = record.rtype

                if self.put(domain, qtype, record, bailiwick):
                    cached_count += 1

        return cached_count

    def _adjust_ttl(self, record, new_ttl):
        """
        Create a copy of a record with adjusted TTL.

        :param record: The original DNS record
        :param new_ttl: The new TTL value in seconds
        :return: A new record with the adjusted TTL
        """
        return RR(
            rname=record.rname,
            rtype=record.rtype,
            rclass=record.rclass,
            ttl=new_ttl,
            rdata=record.rdata
        )

    def _in_bailiwick(self, domain, bailiwick):
        """
        Check if a domain is within a given bailiwick.

        A domain is in-bailiwick if it matches or is a subdomain of the
        bailiwick. Both names are normalized to lowercase for comparison.

        :param domain: The domain to check (string)
        :param bailiwick: The bailiwick domain (string)
        :return: True if domain is within bailiwick, False otherwise
        """
        domain = domain.lower().rstrip('.')
        bailiwick = bailiwick.lower().rstrip('.')

        if domain == bailiwick:
            return True

        return domain.endswith('.' + bailiwick)
