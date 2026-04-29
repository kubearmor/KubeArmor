//go:build windows

package monitor

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/sys/windows"
)

const (
	DataTypeUChar         = 1
	DataTypeUShort        = 2
	DataTypeULong         = 3
	DataTypeULongLong     = 4
	DataTypeChar          = 5
	DataTypeShort         = 6
	DataTypeLong          = 7
	DataTypeLongLong      = 8
	DataTypeUnicodeString = 9
	DataTypeBinary        = 10
	DataTypeBoolean       = 11
)

// Event types
const (
	EventTypeProcessCreate    = 1
	EventTypeProcessTerminate = 2
	EventTypeThreadCreate     = 3
	EventTypeThreadTerminate  = 4
	EventTypeImageLoad        = 5

	EventTypeFileCreate  = 100
	EventTypeFileCLOSE   = 101
	EventTypeFileRead    = 102
	EventTypeFileWrite   = 103
	EventTypeFileDelete  = 104
	EventTypeFileRename  = 105
	EventTypeFileSetInfo = 106
)

// Common field IDs (1-99)
const (
	FieldEventType = 1
	FieldTimestamp = 2
	FieldProcessID = 3
	FieldThreadID  = 4
	FieldSessionID = 5
)

// File volume field IDs
const (
	FieldVolumeGUID = 50
	FieldVolumeType = 51
	FieldVolumeName = 52
)

// Process event field IDs (100-149)
const (
	FieldParentProcessID           = 100
	FieldCreatorProcessID          = 101
	FieldImagePath                 = 102
	FieldCommandLine               = 103
	FieldExitCode                  = 104
	FieldCreateFlags               = 105
	FieldParentProcessImagePath    = 106
	FieldCreatorProcessImagePath   = 107
	FieldProcessUserSID            = 108
	FieldProcessTokenElevation     = 109
	FieldProcessTokenElevationType = 110
)

// File event field IDs (150-199)
const (
	FieldFilePath          = 150
	FieldFileName          = 151
	FieldDesiredAccess     = 152
	FieldCreateOptions     = 153
	FieldCreateDisposition = 154
	FieldFileAttributes    = 155
	FieldShareAccess       = 156
	FieldFileOffset        = 157
	FieldBytesTransferred  = 158
	FieldIoStatus          = 159
	FieldFileID            = 160
)

// Thread event field IDs (200-249)
const (
	FieldCreatorThreadID = 200
	FieldStartAddress    = 201
)

// EventHeader type
type EventHeader struct {
	FieldID  byte
	DataType byte
}

func parseEventHeader(r io.Reader) (*EventHeader, error) {
	var h EventHeader
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

type Field struct {
	FieldID  byte
	DataType byte
	RawBytes interface{}
}

type EventType struct {
	FieldID  byte
	DataType byte
	Type     uint32
}

func parseEventType(r io.Reader) (*EventType, error) {
	var eT EventType
	if err := binary.Read(r, binary.LittleEndian, &eT); err != nil {
		return nil, err
	}
	return &eT, nil
}

func parseField(r io.Reader) (*Field, error) {
	eh, err := parseEventHeader(r)
	if err != nil {
		return nil, err
	}

	// fixed length data
	// | field-id | data-type | data |

	// variable length data
	// | field-id | data-type | length | data |

	f := &Field{}
	f.FieldID = eh.FieldID
	f.DataType = eh.DataType

	switch eh.DataType {
	case DataTypeUChar:
		val, err := readUInt8FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeUShort:
		val, err := readUInt16FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeULong:
		val, err := readUInt32FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeULongLong:
		val, err := readUInt64FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeChar:
		val, err := readUInt8FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeShort:
		val, err := readInt16FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeLong:
		val, err := readInt32FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeLongLong:
		val, err := readInt64FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeUnicodeString: // variable length data
		length, err := readUInt16FromBuff(r)
		if err != nil {
			return nil, err
		}
		if length == 0 {
			f.RawBytes = ""
			return f, nil
		}
		buf, err := readByteSliceFromBuff(r, int(length))
		if err != nil {
			return nil, err
		}
		// convert bytes to UTF-16 safely
		u16Str := make([]uint16, length/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(buf[i*2:])
		}
		f.RawBytes = windows.UTF16ToString(u16Str)
		return f, nil
	case DataTypeBinary: // variable length data
		length, err := readInt32FromBuff(r)
		if err != nil {
			return nil, err
		}
		val, err := readByteSliceFromBuff(r, int(length))
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case DataTypeBoolean:
		val, err := readUInt8FromBuff(r)
		if err != nil {
			return nil, err
		}
		f.RawBytes = val
		return f, nil
	case 0: // indicates end of the event
		fmt.Println("====event end=====")
		return nil, nil
	default:
		return f, fmt.Errorf("unsupported data type: %v", eh.DataType)
	}
}

func (f *Field) UChar() string {
	return f.RawBytes.(string)
}
func (f *Field) UShort() uint16 {
	return f.RawBytes.(uint16)
}
func (f *Field) ULong() uint32 {
	return f.RawBytes.(uint32)
}
func (f *Field) ULongLong() uint64 {
	return f.RawBytes.(uint64)
}
func (f *Field) Char() string {
	return f.RawBytes.(string)
}
func (f *Field) Short() int16 {
	return f.RawBytes.(int16)
}
func (f *Field) Long() int32 {
	return f.RawBytes.(int32)
}
func (f *Field) LongLong() int64 {
	return f.RawBytes.(int64)
}
func (f *Field) UnicodeString() string {
	return f.RawBytes.(string)
}
func (f *Field) Binary() []byte {
	return f.RawBytes.([]byte)
}
func (f *Field) Boolean() bool {
	val := f.RawBytes.(uint8)
	return val == 0
}

func getProcessEvent(e uint32) string {
	switch e {
	case EventTypeProcessCreate:
		return "Create"
	case EventTypeProcessTerminate:
		return "Terminate"
	default:
		return "UNKNOWN"
	}
}

func getFileEvent(e uint32) string {
	switch e {
	case EventTypeFileCLOSE:
		return "Close"
	case EventTypeFileCreate:
		return "Create"
	case EventTypeFileDelete:
		return "Delete"
	case EventTypeFileRead:
		return "Read"
	case EventTypeFileRename:
		return "Rename"
	case EventTypeFileSetInfo:
		return "SetInfo"
	case EventTypeFileWrite:
		return "Write"
	default:
		return "UNKNOWN"
	}
}
