package adidns

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

func ParseIP(data []byte) string {
	ip := net.IP(data)
	return ip.String()
}

func ParseAddrArray(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	numIPs := int(data[0])
	if len(data) < 32*numIPs+32 {
		return nil
	}

	addrArr := data[32:]

	ips := make([]string, numIPs)
	for x := 0; x < numIPs; x += 1 {
		family := binary.LittleEndian.Uint16(addrArr[:4])

		var ip net.IP
		if family == 0x0002 {
			// IPv4
			ip = net.IP(addrArr[x*32+4 : x*32+8])
		} else if family == 0x0017 {
			// IPv6
			ip = net.IP(addrArr[x*32+8 : x*32+24])
		} else {
			continue
		}

		ips[x] = ip.String()
	}

	return ips
}

func ParseIP4Array(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	numIP4s := int(data[0])
	if len(data) < 4*numIP4s+1 {
		return nil
	}

	ip4s := make([]string, numIP4s)
	for x := 0; x < numIP4s; x += 1 {
		ip := net.IP(data[1+x*4 : 1+(x+1)*4])
		ip4s = append(ip4s, ip.String())
	}

	return ip4s
}

func FormatHours(val uint64) string {
	days := 0
	if val > 24 {
		days = int(math.Floor(float64(val / 24)))
	}

	text := ""
	if days > 0 {
		text = fmt.Sprintf("%d days", days)
		if val%24 != 0 {
			text += fmt.Sprintf(", %d hours", val%24)
		}
	} else {
		text = fmt.Sprintf("%d hours", val)
	}

	return text
}

// msTime is defined as the number of seconds since Jan 1th of 1601
// to calculate it we just compute a unix timestamp after
// removing the difference in seconds
// between 01/01/1601 and 01/01/1970
func MSTimeToUnixTimestamp(msTime uint64) int64 {
	if msTime == 0 {
		return -1
	}

	baseTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

	secondsSince := msTime - uint64(11644473600)

	elapsedDuration := time.Duration(secondsSince) * time.Second

	targetTime := baseTime.Add(elapsedDuration)

	unixTimestamp := targetTime.Unix()

	return unixTimestamp
}
