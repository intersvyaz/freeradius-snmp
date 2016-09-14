# FreeRADIUS 3.x SNMP module

Simple module for performing SNMPv2c get/set operations.

### Usage examples

```
snmp snmp_get_example {
    # Perform an SNMP get
    action = "get"
    
    # Server name or IP (support attributes substitution)
    server = &NAS-IP-Address
    
    # Server port (optional, default is 162)
    port = 162
    
    # Community string (support attributes substitution)
    community = "mysecret"
    
    # Request OID (support attributes substitution)
    oid = "..."
    
    # Name of output attribute
    output_attr = &User-Name
    
    # Number of milliseconds before timeout (optional, default value is -1)
    timeout = -1
    
    # Nubmer of retries before timeout (optional, default value is -1 for unlimited retries)
    retries = -1
}

snmp snmp_set_example {
    # Perform an SNMP set
    action = "get"
    
    # Server name or IP (support attributes substitution)
    server = &NAS-IP-Address
    
    # Server port (optional, default is 162)
    port = 162
    
    # Community string (support attributes substitution)
    community = "mysecret"
    
    # Request OID (support attributes substitution)
    oid = "..."
    
    # value type code (optional, default is '=')
    # =: auto detect type by OID
    # i: integer         u: unsigned integer
    # I: signed int64    U: unsigned int64
    # F: float           D: double
    # t: timeticks       a: ipaddress
    # o: objid           s: string
    # x: hex string      d: decimal string
    value_type = "="
    
    # Value to send (support attributes substitution)
    value = "123"
    
    # Number of ms until first timeout, then exponential backoff (optional, default is -1)
    timeout = -1
    
    # Nubmer of retries before timeout (optional, default is -1 for unlimited retries)
    retries = -1
}
```
