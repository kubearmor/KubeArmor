package ssl

import "strings"

// WIP 

// StructOffsets holds version-specific SSL struct field offsets.
type StructOffsets struct {
    SSLRBIOOffset int32
    BIONumOffset  int32
}

// known offsets per OpenSSL major.minor prefix
var knownOffsets = map[string]StructOffsets{
    "1.0.": {SSLRBIOOffset: 96, BIONumOffset: 40},
    "1.1.": {SSLRBIOOffset: 16, BIONumOffset: 48},
    "3.":   {SSLRBIOOffset: 16, BIONumOffset: 48},
}

func OffsetsForVersion(version string) (StructOffsets, bool) {
    for prefix, off := range knownOffsets {
        if strings.Contains(version, prefix) {
            return off, true
        }
    }
    return StructOffsets{}, false
}

