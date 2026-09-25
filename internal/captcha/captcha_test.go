package captcha

import (
	"encoding/base64"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateSlide(t *testing.T) {
	challenge, err := GenerateSlide()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		src  string
		w, h int
	}{
		{challenge.Image, ImageWidth, ImageHeight},
		{challenge.Thumb, TileSize, TileSize},
	} {
		parts := strings.SplitN(test.src, ",", 2)
		if len(parts) != 2 {
			t.Fatal("image must be a data URL")
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		img, _, err := image.Decode(strings.NewReader(string(decoded)))
		if err != nil || img.Bounds().Dx() != test.w || img.Bounds().Dy() != test.h {
			t.Fatalf("invalid challenge image: %v", err)
		}
		if test.w == TileSize {
			r, g, b, a := img.At(TileSize/2, TileSize/2).RGBA()
			if a < 0x8000 || (r > 0xc000 && g > 0xc000 && b > 0xc000) {
				t.Fatal("tile center lost its background texture")
			}
		}
	}
	if challenge.TargetX <= challenge.ThumbX || challenge.TargetX > ImageWidth-TileSize || challenge.TargetY != challenge.ThumbY {
		t.Fatalf("invalid slide coordinates: %+v", challenge)
	}
}

func TestSlideToleranceAndOneUse(t *testing.T) {
	for _, test := range []struct {
		name  string
		x, y  int
		valid bool
	}{
		{"exact", 120, 50, true},
		{"left edge", 116, 50, true},
		{"right edge", 124, 50, true},
		{"vertical edge", 120, 54, true},
		{"outside horizontal tolerance", 125, 50, false},
		{"outside vertical tolerance", 120, 45, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := NewStore()
			id, err := s.NewSlide(120, 50)
			if err != nil {
				t.Fatal(err)
			}
			ticket, valid, err := s.VerifySlide(id, test.x, test.y)
			if err != nil || valid != test.valid {
				t.Fatalf("verify = %v, %v", valid, err)
			}
			if _, retry, _ := s.VerifySlide(id, 120, 50); retry {
				t.Error("challenge replay succeeded")
			}
			if valid {
				if ticket == "" || !s.ConsumeTicket(id, ticket) {
					t.Fatal("valid ticket rejected")
				}
				if s.ConsumeTicket(id, ticket) {
					t.Fatal("ticket replay succeeded")
				}
			} else if ticket != "" {
				t.Error("failed verification issued ticket")
			}
		})
	}
}

func TestTicketBoundToSessionAndExpires(t *testing.T) {
	s := NewStoreWithTTL(time.Second)
	id, _ := s.NewSlide(100, 50)
	ticket, ok, err := s.VerifySlide(id, 100, 50)
	if err != nil || !ok {
		t.Fatalf("verify failed: %v", err)
	}
	if s.ConsumeTicket("another-session", ticket) {
		t.Fatal("ticket used in a different session")
	}
	if s.ConsumeTicket(id, ticket) {
		t.Fatal("cross-session attempt did not consume ticket")
	}
	id, _ = s.NewSlide(100, 50)
	ticket, _, _ = s.VerifySlide(id, 100, 50)
	s.now = func() time.Time { return time.Now().Add(TicketTTL + time.Second) }
	if s.ConsumeTicket(id, ticket) {
		t.Fatal("expired ticket accepted")
	}
	if s.Len() != 0 {
		t.Fatal("expired entries were not swept")
	}
}

func TestSlideExpiryAndPressure(t *testing.T) {
	s := NewStoreWithTTL(time.Second)
	id, _ := s.NewSlide(100, 50)
	s.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if _, ok, _ := s.VerifySlide(id, 100, 50); ok {
		t.Fatal("expired challenge accepted")
	}
	s = NewStoreWithTTL(time.Hour)
	for i := 0; i < maxEntries+1; i++ {
		if _, err := s.NewSlide(100, 50); err != nil {
			t.Fatal(err)
		}
	}
	if s.Len() > maxEntries {
		t.Fatal("unbounded challenge store")
	}
}

func TestConcurrentTicketConsumption(t *testing.T) {
	s := NewStore()
	id, _ := s.NewSlide(100, 50)
	ticket, _, _ := s.VerifySlide(id, 100, 50)
	var successful atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			if s.ConsumeTicket(id, ticket) {
				successful.Add(1)
			}
		})
	}
	wg.Wait()
	if successful.Load() != 1 {
		t.Fatalf("%d logins consumed same ticket", successful.Load())
	}
}
