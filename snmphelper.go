// Package snmphelper implements some functions on top of gosnmp.
package snmphelper

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Version of release
const Version = "1.0.0"

// SNMP session object
type Session struct {
	Host, User, Prot, Pass, Slevel, PrivProt, PrivPass string
	Ver                                                int
	MaxRepetitions, Timeout                            uint32 // Defaults: MaxRepetitions: 5, Timeout: 2
	Snmp                                               *gosnmp.GoSNMP
}

// Session.Result data type. SNMP query results will appear here.
type SnmpOut map[string]snmpValue

// Initializes and returns *gosnmp.GoSNMP in Session.Snmp
func (s *Session) New() (*Session, error) {
	// Setup SNMP security model
	usm := &gosnmp.UsmSecurityParameters{
		UserName:                 s.User,
		AuthenticationPassphrase: s.Pass,
		PrivacyPassphrase:        s.PrivPass,
	}

	//Initialise the SNMP object
	snmp := &gosnmp.GoSNMP{
		Target:             s.Host,
		Port:               161,
		Community:          s.User,
		Timeout:            time.Duration(2) * time.Second,
		SecurityModel:      gosnmp.UserSecurityModel,
		MaxRepetitions:     5,
		Retries:            1,
		ExponentialTimeout: false,
		SecurityParameters: usm,
	}

	// set some non default parameters if present
	if s.MaxRepetitions != 0 {
		snmp.MaxRepetitions = s.MaxRepetitions
	}

	if s.Timeout != 0 {
		snmp.Timeout = time.Duration(s.Timeout) * time.Second
	}

	// Set seclevel
	switch s.Slevel {
	case "noAuthNoPriv":
		snmp.MsgFlags = gosnmp.NoAuthNoPriv
	case "authNoPriv":
		snmp.MsgFlags = gosnmp.AuthNoPriv
	case "authPriv":
		snmp.MsgFlags = gosnmp.AuthPriv
	default:
		return nil, fmt.Errorf("invalid SNMP sec level - %s", s.Slevel)
	}

	// Set version
	switch s.Ver {
	case 1:
		snmp.Version = gosnmp.Version1
	case 2:
		snmp.Version = gosnmp.Version2c
	case 3:
		snmp.Version = gosnmp.Version3
	default:
		return nil, fmt.Errorf("invalid SNMP version - %d", s.Ver)
	}

	// Set AuthenticationProtocol
	switch s.Prot {
	case "NoAuth":
		usm.AuthenticationProtocol = gosnmp.NoAuth
	case "MD5":
		usm.AuthenticationProtocol = gosnmp.MD5
	case "SHA":
		usm.AuthenticationProtocol = gosnmp.SHA
	default:
		return nil, fmt.Errorf("invalid SNMP authentication protocol - %s", s.Prot)
	}

	// Set PrivacyProtocol
	switch s.PrivProt {
	case "NoPriv":
		usm.PrivacyProtocol = gosnmp.NoPriv
	case "DES":
		usm.PrivacyProtocol = gosnmp.DES
	case "AES":
		usm.PrivacyProtocol = gosnmp.AES
	case "AES192":
		usm.PrivacyProtocol = gosnmp.AES192
	case "AES192C":
		usm.PrivacyProtocol = gosnmp.AES192C
	case "AES256":
		usm.PrivacyProtocol = gosnmp.AES256
	case "AES256C":
		usm.PrivacyProtocol = gosnmp.AES256C
	default:
		return nil, fmt.Errorf("invalid SNMP privacy protocol - %s", s.PrivProt)
	}

	s.Snmp = snmp
	return s, nil
}

// Do SNMP get
func (s *Session) Get(oids []string) (SnmpOut, error) {
	var out = SnmpOut{}

	snmp := s.Snmp
	if err := snmp.Connect(); err != nil {
		return out, err
	}
	defer snmp.Conn.Close()

	// Do get
	res, err := snmp.Get(oids)
	if err != nil {
		return out, err
	}

	// Make formatted output
	for _, p := range res.Variables {
		k, v, err2 := formatValue(p, "", false)
		if err2 != nil {
			return out, err2
		}
		out[k] = v
	}

	return out, nil
}

// Do SNMP walk or bulkwalk
func (s *Session) Walk(oid string, bulk bool, stripoid bool) (SnmpOut, error) {
	var out = SnmpOut{}
	var pdus []gosnmp.SnmpPDU

	snmp := s.Snmp
	err := snmp.Connect()
	if err != nil {
		return out, err
	}
	defer snmp.Conn.Close()

	// Get all returned PDU's returned by SNMP query
	getResults := func(pdu gosnmp.SnmpPDU) error {
		pdus = append(pdus, pdu)
		return nil
	}

	// Do walk
	if bulk {
		err = snmp.BulkWalk(oid, getResults)
	} else {
		err = snmp.Walk(oid, getResults)
	}

	if err != nil {
		return out, err
	}

	// Make formatted output
	for _, p := range pdus {
		k, v, err2 := formatValue(p, oid, stripoid)
		if err2 != nil {
			return out, err2
		}
		out[k] = v
	}

	return out, err
}

// Local part

// SNMP guery result value
type snmpValue struct {
	Raw   interface{}
	Vtype string

	Counter32        uint64
	Counter64        uint64
	Gauge32          uint64
	Integer          int64
	IPAddress        string
	ObjectIdentifier string
	Opaque           string
	OctetString      string
	OpaqueDouble     float64
	OpaqueFloat      float64
	TimeTicks        uint64
}

// Format SNMP return value
func formatValue(pdu gosnmp.SnmpPDU, oid string, stripoid bool) (string, snmpValue, error) {
	key := pdu.Name
	if stripoid {
		key = strings.TrimPrefix(pdu.Name, oid+".")
	}
	value := snmpValue{
		Raw:   pdu.Value,
		Vtype: pdu.Type.String(),
	}
	err := value.snmpValDecode()

	return key, value, err
}

// Decode SNMP return value
func (v *snmpValue) snmpValDecode() error {
	// Type assertions
	switch v.Vtype {
	case "Integer": // 0x02. signed
		val, _ := v.Raw.(int)
		v.Integer = int64(val)
	case "Counter32": // 0x41. unsigned
		val, _ := v.Raw.(uint32)
		v.Counter32 = uint64(val)
	case "Counter64": // 0x46. unsigned
		val, _ := v.Raw.(uint64)
		v.Counter64 = uint64(val)
	case "Gauge32": // 0x42. unsigned
		val, _ := v.Raw.(uint)
		v.Gauge32 = uint64(val)
	case "TimeTicks": // 0x43. unsigned
		val, _ := v.Raw.(uint32)
		v.TimeTicks = uint64(val)
	case "ObjectIdentifier": // 0x06
		val, _ := v.Raw.(string)
		v.ObjectIdentifier = val
	case "OctetString": // 0x04
		b, _ := v.Raw.([]byte)
		v.OctetString = string(b)
	case "IPAddress": // 0x40
		val, _ := v.Raw.(string)
		v.IPAddress = val
	case "Opaque": // 0x44. NOT TESTED!
		b, _ := v.Raw.([]byte)
		v.Opaque = string(b)
	case "OpaqueDouble": // 0x79. NOT TESTED!
		b, _ := v.Raw.([]byte)
		var bits uint64
		if len(b) > 4 {
			// We'll overflow a uint64 in this case.
			return fmt.Errorf("OpaqueDouble too large")
		}
		bits = binary.BigEndian.Uint64(b)
		v.OpaqueDouble = math.Float64frombits(bits)
	case "OpaqueFloat": // 0x78. NOT TESTED!
		b, _ := v.Raw.([]byte)
		var bits uint64
		if len(b) > 4 {
			// We'll overflow a uint32 in this case.
			return fmt.Errorf("OpaqueFloat too large")
		}
		bits = binary.BigEndian.Uint64(b)
		v.OpaqueFloat = math.Float64frombits(bits)
	default:
		return fmt.Errorf("SNMP error - %v", v.Vtype)
	}

	return nil
}
