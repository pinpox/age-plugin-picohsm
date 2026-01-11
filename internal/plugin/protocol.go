package plugin

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"filippo.io/age"
)

// Stanza represents an age plugin protocol stanza.
type Stanza struct {
	Type string
	Args []string
	Body []byte
}

// Protocol handles the age plugin protocol communication.
type Protocol struct {
	in          *bufio.Reader
	out         io.Writer
	pendingLine string // line read but not consumed (for lookahead)
}

// NewProtocol creates a new Protocol for plugin communication.
func NewProtocol(in io.Reader, out io.Writer) *Protocol {
	return &Protocol{
		in:  bufio.NewReader(in),
		out: out,
	}
}

// readLine reads the next line, using pending line if available.
func (p *Protocol) readLine() (string, error) {
	if p.pendingLine != "" {
		line := p.pendingLine
		p.pendingLine = ""
		return line, nil
	}
	line, err := p.in.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(line, "\n"), nil
}

const bytesPerLine = 48 // age protocol: 48 bytes = 64 base64 chars per line

// ReadStanza reads a stanza from the input.
func (p *Protocol) ReadStanza() (*Stanza, error) {
	// Read the header line: -> type [args...]
	line, err := p.readLine()
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(line, "-> ") {
		return nil, fmt.Errorf("invalid stanza header: %q", line)
	}

	parts := strings.Split(line[3:], " ")
	if len(parts) == 0 {
		return nil, errors.New("empty stanza type")
	}

	s := &Stanza{
		Type: parts[0],
		Args: parts[1:],
	}

	// Read body lines - a stanza body always ends with a short line (< 48 decoded bytes)
	for {
		line, err := p.readLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Decode the line
		decoded, err := base64.RawStdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("failed to decode body line: %w", err)
		}

		s.Body = append(s.Body, decoded...)

		// A short line (< 48 bytes decoded) ends the stanza
		if len(decoded) < bytesPerLine {
			break
		}
	}

	return s, nil
}

// WriteStanza writes a stanza to the output.
func (p *Protocol) WriteStanza(s *Stanza) error {
	// Write header
	line := "-> " + s.Type
	for _, arg := range s.Args {
		line += " " + arg
	}

	// Build complete stanza as a single write to avoid buffering issues
	var buf strings.Builder
	buf.WriteString(line)
	buf.WriteString("\n")

	// Write body - age protocol requires a short final line (< 64 chars)
	encoded := base64.RawStdEncoding.EncodeToString(s.Body)
	// Split into 64-character lines
	for len(encoded) >= 64 {
		buf.WriteString(encoded[:64])
		buf.WriteString("\n")
		encoded = encoded[64:]
	}
	// Write the final short line (may be empty if body was multiple of 48 bytes)
	buf.WriteString(encoded)
	buf.WriteString("\n")

	// Write entire stanza at once
	if _, err := io.WriteString(p.out, buf.String()); err != nil {
		return err
	}

	return nil
}

// WriteDone writes the done command (no body, just header).
func (p *Protocol) WriteDone() error {
	// Commands without bodies still need a short (empty) body line
	if _, err := fmt.Fprintln(p.out, "-> done"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(p.out)
	return err
}

// WriteOK writes an ok response (no body, just header).
func (p *Protocol) WriteOK() error {
	if _, err := fmt.Fprintln(p.out, "-> ok"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(p.out)
	return err
}

// WriteFail writes a fail response (no body, just header).
func (p *Protocol) WriteFail() error {
	if _, err := fmt.Fprintln(p.out, "-> fail"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(p.out)
	return err
}

// WriteError writes an error stanza.
func (p *Protocol) WriteError(errType string, index int, message string) error {
	s := &Stanza{
		Type: "error",
		Args: []string{errType, strconv.Itoa(index)},
		Body: []byte(message),
	}
	return p.WriteStanza(s)
}

// WriteInternalError writes an internal error stanza.
func (p *Protocol) WriteInternalError(message string) error {
	s := &Stanza{
		Type: "error",
		Args: []string{"internal"},
		Body: []byte(message),
	}
	return p.WriteStanza(s)
}

// RequestSecret requests a secret value from the user.
func (p *Protocol) RequestSecret(message string) (string, error) {
	s := &Stanza{
		Type: "request-secret",
		Body: []byte(message),
	}
	if err := p.WriteStanza(s); err != nil {
		return "", err
	}

	resp, err := p.ReadStanza()
	if err != nil {
		return "", err
	}

	if resp.Type == "fail" {
		return "", errors.New("user cancelled")
	}
	if resp.Type != "ok" {
		return "", fmt.Errorf("unexpected response: %s", resp.Type)
	}

	return string(resp.Body), nil
}

// DisplayMessage displays a message to the user.
func (p *Protocol) DisplayMessage(message string) error {
	s := &Stanza{
		Type: "msg",
		Body: []byte(message),
	}
	if err := p.WriteStanza(s); err != nil {
		return err
	}

	resp, err := p.ReadStanza()
	if err != nil {
		return err
	}

	if resp.Type != "ok" {
		return fmt.Errorf("message display failed: %s", resp.Type)
	}

	return nil
}

// WriteRecipientStanza writes a recipient-stanza response.
func (p *Protocol) WriteRecipientStanza(fileIndex int, stanza *age.Stanza) error {
	// Format: -> recipient-stanza <file_index> <stanza_type> [stanza_args...]
	args := []string{strconv.Itoa(fileIndex), stanza.Type}
	args = append(args, stanza.Args...)

	s := &Stanza{
		Type: "recipient-stanza",
		Args: args,
		Body: stanza.Body,
	}
	return p.WriteStanza(s)
}

// WriteFileKey writes a file-key response.
func (p *Protocol) WriteFileKey(fileIndex int, fileKey []byte) error {
	s := &Stanza{
		Type: "file-key",
		Args: []string{strconv.Itoa(fileIndex)},
		Body: fileKey,
	}
	return p.WriteStanza(s)
}
