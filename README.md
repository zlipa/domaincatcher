# Domaincatcher
Script to catch domains and register them automatically once they drop back into the registry.

### About
This is something I made quickly, it should work as I catched some domains. It uses the OpenProvider API (free) to obtains the status of a batch of domains, then optionally uses the Versio API to register a domain (requires funds in your Versio accoutn).
Once the domain is free, the script will try to register it automatically. I designed this for .NL domains only, but it can be extended to make it work for other TLDs too.

You can add up to 50 domains per line in the variable $domains.