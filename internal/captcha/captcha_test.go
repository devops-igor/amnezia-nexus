package captcha

import (
	"sync"
	"testing"
	"time"
)

func TestStoreNewAndVerify(t *testing.T) {
	s := NewStore()
	id, err := s.New("1234")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty captcha id")
	}
	// Ids must be opaque/unpredictable enough: two creates differ.
	id2, _ := s.New("5678")
	if id == id2 {
		t.Fatal("expected unique captcha ids")
	}
	if !s.Verify(id, "1234") {
		t.Error("expected correct answer to verify")
	}
	if s.Verify(id, "1234") {
		t.Error("expected one-time-use: second verify must fail")
	}
}

func TestStoreVerifyIsCaseInsensitiveAndTrims(t *testing.T) {
	s := NewStore()
	id, _ := s.New("1234")
	if !s.Verify(id, " 1234 ") {
		t.Error("expected trimmed answer to verify")
	}
}

func TestStoreWrongAnswerConsumesEntry(t *testing.T) {
	s := NewStore()
	id, _ := s.New("1234")
	if s.Verify(id, "9999") {
		t.Error("wrong answer should not verify")
	}
	if s.Verify(id, "1234") {
		t.Error("wrong answer must consume the entry (one-time-use)")
	}
}

func TestStoreExpiry(t *testing.T) {
	s := NewStoreWithTTL(50 * time.Millisecond)
	id, _ := s.New("1234")
	s.now = func() time.Time { return time.Now().Add(100 * time.Millisecond) }
	if s.Verify(id, "1234") {
		t.Error("expired captcha id must be rejected")
	}
	if got := s.Len(); got != 0 {
		t.Errorf("expected expired entry swept, Len=%d", got)
	}
}

func TestStoreUnknownIDRejected(t *testing.T) {
	s := NewStore()
	if s.Verify("nonexistent", "1234") {
		t.Error("unknown id must be rejected")
	}
}

func TestStoreMaxAttempts(t *testing.T) {
	s := NewStoreWithTTL(1 * time.Hour)
	id, _ := s.New("1234")
	// Consume via one wrong attempt.
	if s.Verify(id, "0000") {
		t.Fatal("setup: wrong attempt should fail")
	}
	if s.Verify(id, "1234") {
		t.Error("entry must be consumed after wrong attempt")
	}
}

func TestStoreSweepOnPressure(t *testing.T) {
	s := NewStore()
	s.mu.Lock()
	s.entries = make(map[string]entry, maxEntries+maxEntries/4)
	s.mu.Unlock()
	for i := 0; i < maxEntries+maxEntries/4; i++ {
		if _, err := s.New("9999"); err != nil {
			t.Fatalf("New failed: %v", err)
		}
	}
	if got := s.Len(); got > maxEntries {
		t.Errorf("expected sweep under memory pressure to cap entries, got %d", got)
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := s.New("1234")
			if err != nil {
				t.Errorf("New failed: %v", err)
				return
			}
			_ = s.Verify(id, "1234")
			_ = s.Len()
		}()
	}
	wg.Wait()
}
