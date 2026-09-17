package models

import (
	"testing"
)

func TestValidateIdentifierName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"", true},
		{"valid-name", false},
		{"valid_name", false},
		{"Valid Name 123", false},
		{"name.with.dots", false},
		{"alpha123numeric", false},
		// Non-ASCII Unicode names must PASS (reject-list, not allowlist)
		{"Мой телефон", false},
		{"گوشی من", false},
		{"我的手机", false},
		{"Téléphone", false},
		{"Home Laptop", false},
		{"café", false},
		// Shell metacharacters must be rejected
		{"name;rm -rf /", true},
		{"name|cat /etc/passwd", true},
		{"name&bg", true},
		{"name$HOME", true},
		{"name`whoami`", true},
		{"name\nnewline", true},
		{"name(evil)", true},
		{"name<file", true},
		{"name>file", true},
		{"name{evil}", true},
		{"name!bang", true},
		{"name#hash", true},
		{"name\\backslash", true},
		{"name'quote", true},
		{`name"doublequote`, true},
		{"name\x00null", true},
		// Additional shell injection patterns
		{"test;rm -rf /", true},
		{"name$(id)", true},
		{"a|b", true},
		{"x`id`", true},
		{"foo&bar", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIdentifierName(tc.name)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateIdentifierName(%q) error = %v, wantErr %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestValidateIdentifierName_RejectsShellMetacharacters(t *testing.T) {
	metachars := []string{
		";", "|", "&", "$", "`", "(", ")", "<", ">", "{", "}", "!", "#", "\\",
		"'", `"`, "\n", "\x00",
	}
	for _, mc := range metachars {
		name := "evil" + mc + "name"
		if err := ValidateIdentifierName(name); err == nil {
			t.Errorf("ValidateIdentifierName(%q) should have returned an error for shell metacharacter %q", name, mc)
		}
	}
}

func TestValidateIdentifierName_AcceptsValidNames(t *testing.T) {
	validNames := []string{
		"My VPN Connection",
		"server-1",
		"client_name",
		"conn.123",
		"A",
		"Alpha Numeric 123",
		// Unicode names should pass
		"Мой телефон",
		"گوشی من",
		"我的手机",
		"Téléphone",
		"café",
	}
	for _, name := range validNames {
		if err := ValidateIdentifierName(name); err != nil {
			t.Errorf("ValidateIdentifierName(%q) should have passed, got error: %v", name, err)
		}
	}
}

func TestValidateIdentifierName_RejectsEmptyAndTooLong(t *testing.T) {
	if err := ValidateIdentifierName(""); err == nil {
		t.Errorf("ValidateIdentifierName(\"\") should reject empty name")
	}
	longName := string(make([]byte, 256))
	for i := range longName {
		longName = longName[:i] + "a" + longName[i+1:]
	}
	if err := ValidateIdentifierName(longName); err == nil {
		t.Errorf("ValidateIdentifierName with 256 chars should reject")
	}
}

func TestAddConnectionRequestValidate_RejectsShellMetacharacters(t *testing.T) {
	req := AddConnectionRequest{
		Protocol: "awg",
		Name:     "evil;rm -rf /",
	}
	if err := req.Validate(); err == nil {
		t.Errorf("AddConnectionRequest.Validate() should reject shell metacharacters in name")
	}
}

func TestAddConnectionRequestValidate_AcceptsValidName(t *testing.T) {
	req := AddConnectionRequest{
		Protocol: "awg",
		Name:     "My Valid Connection",
	}
	if err := req.Validate(); err != nil {
		t.Errorf("AddConnectionRequest.Validate() should accept valid name, got: %v", err)
	}
}

func TestAddConnectionRequestValidate_AcceptsUnicodeName(t *testing.T) {
	req := AddConnectionRequest{
		Protocol: "awg",
		Name:     "Мой телефон",
	}
	if err := req.Validate(); err != nil {
		t.Errorf("AddConnectionRequest.Validate() should accept Unicode name, got: %v", err)
	}
}

func TestRenameServerRequestValidate_RejectsShellMetacharacters(t *testing.T) {
	req := RenameServerRequest{
		Name: "evil|cat /etc/passwd",
	}
	if err := req.Validate(); err == nil {
		t.Errorf("RenameServerRequest.Validate() should reject shell metacharacters in name")
	}
}

func TestRenameServerRequestValidate_AcceptsValidName(t *testing.T) {
	req := RenameServerRequest{
		Name: "My-Server_1",
	}
	if err := req.Validate(); err != nil {
		t.Errorf("RenameServerRequest.Validate() should accept valid name, got: %v", err)
	}
}

func TestRenameConnectionRequestValidate_RejectsShellMetacharacters(t *testing.T) {
	req := RenameConnectionRequest{
		Name: "evil`whoami`",
	}
	if err := req.Validate(); err == nil {
		t.Errorf("RenameConnectionRequest.Validate() should reject shell metacharacters in name")
	}
}

func TestRenameConnectionRequestValidate_AcceptsValidName(t *testing.T) {
	req := RenameConnectionRequest{
		Name: "Connection.1",
	}
	if err := req.Validate(); err != nil {
		t.Errorf("RenameConnectionRequest.Validate() should accept valid name, got: %v", err)
	}
}

func TestEditConnectionRequestValidate_RejectsShellMetacharacters(t *testing.T) {
	evilName := "evil;echo"
	req := EditConnectionRequest{
		Protocol: "awg",
		ClientID: "somekey123",
		Name:     &evilName,
	}
	if err := req.Validate(); err == nil {
		t.Errorf("EditConnectionRequest.Validate() should reject shell metacharacters in name")
	}
}

func TestEditConnectionRequestValidate_AcceptsValidName(t *testing.T) {
	validName := "Valid Name"
	req := EditConnectionRequest{
		Protocol: "awg",
		ClientID: "somekey123",
		Name:     &validName,
	}
	if err := req.Validate(); err != nil {
		t.Errorf("EditConnectionRequest.Validate() should accept valid name, got: %v", err)
	}
}

// TestEditConnectionRequestValidate_EmptyProtocolPreservesBackwardCompat
// verifies that an EditConnectionRequest with empty Protocol and valid ClientID
// passes validation — preserving the behavior before IsValidProtocol was added.
func TestEditConnectionRequestValidate_EmptyProtocolPreservesBackwardCompat(t *testing.T) {
	req := EditConnectionRequest{
		Protocol: "",
		ClientID: "somekey123",
	}
	if err := req.Validate(); err != nil {
		t.Errorf("EditConnectionRequest.Validate() with empty protocol should pass, got: %v", err)
	}
}
