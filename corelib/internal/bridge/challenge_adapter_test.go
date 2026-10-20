package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

func TestProtocolChallengeAdapterPreservesHostResponse(t *testing.T) {
	cases := []struct {
		kind     string
		run      func(authchallenge.Handler) error
		response Response
	}{
		{"trusted_device", func(h authchallenge.Handler) error {
			confirmed, err := h.HandleTrustedDevice()
			if err == nil && !confirmed {
				return fmt.Errorf("confirmation lost")
			}
			return err
		}, Response{Action: "confirm"}},
		{"sms", func(h authchallenge.Handler) error {
			r, err := h.HandleCodeChallenge(authchallenge.CodeChallenge{Kind: authchallenge.CodeSMS, CanSkipSecondaryAuth: true})
			if err == nil && (r.Code != "fixture-code" || !r.SkipSecondaryAuth) {
				return fmt.Errorf("code or secondary-auth flag lost")
			}
			return err
		}, Response{Code: "fixture-code", SkipSecondaryAuth: true}},
		{"text_captcha", func(h authchallenge.Handler) error {
			r, err := h.HandleTextCaptcha(authchallenge.TextCaptchaChallenge{Image: []byte{1, 2}})
			if err == nil && r.Code != "fixture-code" {
				return fmt.Errorf("text code lost")
			}
			return err
		}, Response{Code: "fixture-code"}},
		{"click_captcha", func(h authchallenge.Handler) error {
			r, err := h.HandleClickCaptcha(authchallenge.ClickCaptchaChallenge{Image: []byte{1, 2}})
			if err == nil && (r.Width != 20 || r.Height != 10 || len(r.Points) != 1 || r.Points[0] != (authchallenge.Point{X: 3, Y: 4})) {
				return fmt.Errorf("captcha coordinates lost")
			}
			return err
		}, Response{Points: []Point{{X: 3, Y: 4}}, Width: 20, Height: 10}},
	}
	for _, kind := range []authchallenge.ExternalLoginKind{authchallenge.ExternalLoginCAS, authchallenge.ExternalLoginOAuth2} {
		cases = append(cases, struct {
			kind     string
			run      func(authchallenge.Handler) error
			response Response
		}{string(kind), func(h authchallenge.Handler) error {
			r, err := h.HandleExternalLogin(authchallenge.ExternalLoginChallenge{Kind: kind, LoginURL: "https://idp.test/login"})
			if err == nil && r.CallbackURL != "https://gateway.test/callback" {
				return fmt.Errorf("callback URL lost")
			}
			return err
		}, Response{CallbackURL: "https://gateway.test/callback"}})
	}
	for _, test := range cases {
		t.Run(test.kind, func(t *testing.T) {
			e := New(func(ctx context.Context, _ Config, s *Session) Status {
				if err := test.run(challengeHandler(ctx, s)); err != nil {
					return Internal
				}
				return OK
			})
			h := create(t, e)
			if _, status := e.Start(h, []byte(configJSON)); status != OK {
				t.Fatal(status)
			}
			read(t, e, h)
			ev := read(t, e, h)
			if ev.Challenge == nil || ev.Challenge.Kind != test.kind {
				t.Fatal(ev)
			}
			response := test.response
			response.SchemaVersion = ABIVersion
			response.Generation = ev.Generation
			response.RequestID = ev.RequestID
			if response.Action == "" {
				response.Action = "submit"
			}
			data, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if status := e.Respond(h, data); status != OK {
				t.Fatalf("adapter response = %d", status)
			}
			if ev := read(t, e, h); ev.Type != "terminal" || ev.Status != OK {
				t.Fatal(ev)
			}
		})
	}
}
