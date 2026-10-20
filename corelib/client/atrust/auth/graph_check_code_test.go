package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

func TestGraphChallengeDeliversImageInMemoryAndPropagatesCancel(t *testing.T) {
	image := buildPNG(t, 40, 30)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/passport/v1/public/checkCode" {
			_, _ = w.Write(image)
		} else if r.URL.Path == "/passport/v1/public/authConfig" {
			_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
		} else {
			t.Errorf("unexpected captcha route: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	for _, cancelled := range []bool{false, true} {
		session := newTLSTestSession(server)
		defer session.Close()
		calls := 0
		session.challengeHandler = authchallenge.HandlerFuncs{ClickCaptcha: func(c authchallenge.ClickCaptchaChallenge) (authchallenge.ClickCaptchaResponse, error) {
			if !bytes.Equal(c.Image, image) {
				t.Fatal("handler did not receive the original image")
			}
			if cancelled {
				return authchallenge.ClickCaptchaResponse{}, context.Canceled
			}
			return authchallenge.ClickCaptchaResponse{Points: []authchallenge.Point{{X: 3, Y: 4}}}, nil
		}}
		err := session.withGraphCheckCode(func(code string) (int, error) {
			calls++
			if calls == 1 {
				return 1, nil
			}
			var payload graphCheckCodePayload
			if json.Unmarshal([]byte(code), &payload) != nil || payload.Width != 40 || payload.Height != 30 || len(payload.Coordinates) != 1 || payload.Coordinates[0][0] != 3 || payload.Coordinates[0][1] != 4 {
				t.Fatalf("invalid image response: %s", code)
			}
			return 0, nil
		})
		if cancelled {
			if !errors.Is(err, context.Canceled) || calls != 1 {
				t.Fatalf("cancel = %v; submissions = %d", err, calls)
			}
		} else if err != nil || calls != 2 {
			t.Fatalf("captcha = %v; submissions = %d", err, calls)
		}
	}
}

func buildPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestGraphCheckCodeFromResponse(t *testing.T) {
	imgData := buildPNG(t, 300, 150)
	raw, err := graphCheckCodeFromResponse(authchallenge.ClickCaptchaResponse{
		Points: []authchallenge.Point{{X: 11, Y: 22}, {X: 33, Y: 44}},
	}, imgData)
	if err != nil {
		t.Fatal(err)
	}
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 300 || payload.Height != 150 || len(payload.Coordinates) != 2 {
		t.Fatalf("unexpected graph check code payload: %+v", payload)
	}
}

func TestGraphCheckCodeFromResponsePreservesDimensions(t *testing.T) {
	raw, err := graphCheckCodeFromResponse(authchallenge.ClickCaptchaResponse{
		Points: []authchallenge.Point{{X: 11, Y: 22}},
		Width:  640,
		Height: 360,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 640 || payload.Height != 360 {
		t.Fatalf("unexpected graph check code dimensions: %dx%d", payload.Width, payload.Height)
	}
}

func TestGraphCheckCodeFromResponseReplacesIncompleteDimensions(t *testing.T) {
	imgData := buildPNG(t, 300, 150)
	raw, err := graphCheckCodeFromResponse(authchallenge.ClickCaptchaResponse{
		Points: []authchallenge.Point{{X: 11, Y: 22}},
		Width:  640,
	}, imgData)
	if err != nil {
		t.Fatal(err)
	}
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Width != 300 || payload.Height != 150 {
		t.Fatalf("unexpected graph check code dimensions: %dx%d", payload.Width, payload.Height)
	}
}
