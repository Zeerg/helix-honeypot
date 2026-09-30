package redis

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxCommandBytes = 64 << 10
const maxArguments = 128
const maxBulkBytes = 32 << 10

// readCommand accepts flat RESP bulk-string arrays, including pipelined and
// fragmented frames. Inline commands support simple whitespace-separated args.
// Nested, null, oversized, and malformed frames terminate the connection.
func readCommand(reader *bufio.Reader) ([]string, int, error) {
	var line []byte
	var err error
	consumed := 0
	for {
		line, err = reader.ReadSlice('\n')
		consumed += len(line)
		if consumed > maxCommandBytes {
			return nil, consumed, errors.New("command exceeds protocol limits")
		}
		if err != nil {
			return nil, consumed, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, consumed, errors.New("invalid protocol terminator")
		}
		line = line[:len(line)-2]
		// Redis CLI --pipe prefixes its final ECHO sentinel with a blank CRLF.
		// Ignore blank lines, while charging them against the command budget.
		if len(line) > 0 {
			break
		}
	}
	if line[0] != '*' {
		args := strings.Fields(string(line))
		if len(args) == 0 || len(args) > maxArguments {
			return nil, consumed, errors.New("invalid inline command")
		}
		return args, consumed, nil
	}
	count, err := strconv.Atoi(string(line[1:]))
	if err != nil || count < 1 || count > maxArguments {
		return nil, consumed, errors.New("invalid argument count")
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := reader.ReadSlice('\n')
		consumed += len(header)
		if err != nil {
			return nil, consumed, err
		}
		if len(header) < 4 || header[0] != '$' || header[len(header)-2] != '\r' {
			return nil, consumed, errors.New("expected bulk argument")
		}
		length, err := strconv.Atoi(string(header[1 : len(header)-2]))
		if err != nil || length < 0 || length > maxBulkBytes || consumed+length+2 > maxCommandBytes {
			return nil, consumed, errors.New("argument exceeds protocol limits")
		}
		data := make([]byte, length+2)
		n, err := io.ReadFull(reader, data)
		consumed += n
		if err != nil {
			return nil, consumed, err
		}
		if data[length] != '\r' || data[length+1] != '\n' {
			return nil, consumed, errors.New("invalid bulk terminator")
		}
		args = append(args, string(data[:length]))
	}
	return args, consumed, nil
}

type bulk string
type simple string
type protocolError string
type respMap []any // alternating key/value entries, preserving HELLO order

func encode(value any, protocol int) []byte {
	var out bytes.Buffer
	var write func(any)
	write = func(value any) {
		switch value := value.(type) {
		case nil:
			if protocol == 3 {
				out.WriteString("_\r\n")
			} else {
				out.WriteString("$-1\r\n")
			}
		case bulk:
			fmt.Fprintf(&out, "$%d\r\n", len(value))
			out.WriteString(string(value))
			out.WriteString("\r\n")
		case simple:
			out.WriteString("+" + string(value) + "\r\n")
		case protocolError:
			out.WriteString("-" + string(value) + "\r\n")
		case int:
			fmt.Fprintf(&out, ":%d\r\n", value)
		case int64:
			fmt.Fprintf(&out, ":%d\r\n", value)
		case []any:
			fmt.Fprintf(&out, "*%d\r\n", len(value))
			for _, item := range value {
				write(item)
			}
		case respMap:
			if protocol == 3 {
				fmt.Fprintf(&out, "%%%d\r\n", len(value)/2)
			} else {
				fmt.Fprintf(&out, "*%d\r\n", len(value))
			}
			for _, item := range value {
				write(item)
			}
		default:
			out.WriteString("-ERR response unavailable\r\n")
		}
	}
	write(value)
	return out.Bytes()
}
