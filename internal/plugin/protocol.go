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
	in  *bufio.Reader
	out io.Writer
}

// NewProtocol creates a new Protocol for plugin communication.
func NewProtocol(in io.Reader, out io.Writer) *Protocol {
	return &Protocol{
		in:  bufio.NewReader(in),
		out: out,
	}
}

// ReadStanza reads a stanza from the input.
func (p *Protocol) ReadStanza() (*Stanza, error) {
	// Read the header line: -> type [args...]
	line, err := p.in.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\n")

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

	// Read body lines until we hit an empty line or another stanza
	var bodyParts []string
	for {
		line, err := p.in.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line = strings.TrimSuffix(line, "\n")

		// Empty line or next stanza header ends the body
		if line == "" || strings.HasPrefix(line, "-> ") {
			// If it's a new stanza, we need to "unread" it
			if strings.HasPrefix(line, "-> ") {
				// Put the line back by creating a new reader with the line prepended
				// This is a simplified approach - in practice we'd buffer this
				return nil, fmt.Errorf("unexpected stanza in body")
			}
			break
		}

		bodyParts = append(bodyParts, line)
	}

	if len(bodyParts) > 0 {
		bodyB64 := strings.Join(bodyParts, "")
		body, err := base64.RawStdEncoding.DecodeString(bodyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode body: %w", err)
		}
		s.Body = body
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
	if _, err := fmt.Fprintln(p.out, line); err != nil {
		return err
	}

	// Write body if present
	if len(s.Body) > 0 {
		encoded := base64.RawStdEncoding.EncodeToString(s.Body)
		// Split into 64-character lines
		for len(encoded) > 64 {
			if _, err := fmt.Fprintln(p.out, encoded[:64]); err != nil {
				return err
			}
			encoded = encoded[64:]
		}
		if len(encoded) > 0 {
			if _, err := fmt.Fprintln(p.out, encoded); err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteDone writes the done command.
func (p *Protocol) WriteDone() error {
	_, err := fmt.Fprintln(p.out, "-> done")
	return err
}

// WriteOK writes an ok response.
func (p *Protocol) WriteOK() error {
	_, err := fmt.Fprintln(p.out, "-> ok")
	return err
}

// WriteFail writes a fail response.
func (p *Protocol) WriteFail() error {
	_, err := fmt.Fprintln(p.out, "-> fail")
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
