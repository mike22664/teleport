/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package mfa

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/utils/prompt"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
	"github.com/gravitational/teleport/lib/auth/webauthnwin"
)

// CLIMFAType is the CLI display name for an MFA type.
type CLIMFAType string

const (
	CLIMFATypeOTP      = "OTP"
	CLIMFATypeWebauthn = "WEBAUTHN"
	CLIMFATypeSSO      = "SSO"
)

// CLIPrompt is the default CLI mfa prompt implementation.
type CLIPrompt struct {
	PromptConfig
	// Writer is where the prompt outputs the prompt. Defaults to os.Stderr.
	Writer io.Writer
	// AllowStdinHijack allows stdin hijack during MFA prompts.
	// Stdin hijack provides a better login UX, but it can be difficult to reason
	// about and is often a source of bugs.
	// Do not set this options unless you deeply understand what you are doing.
	// If false then only the strongest auth method is prompted.
	AllowStdinHijack bool
	// PreferOTP favors OTP challenges, if applicable.
	// Takes precedence over AuthenticatorAttachment settings.
	PreferOTP bool
	// PreferSSO favors SSO challenges, if applicable.
	// Takes precedence over AuthenticatorAttachment settings.
	PreferSSO bool
	// StdinFunc allows tests to override prompt.Stdin().
	// If nil prompt.Stdin() is used.
	StdinFunc func() prompt.StdinReader
}

// NewCLIPrompt returns a new CLI mfa prompt with the config and writer.
// TODO(Joerger): Delete once /e is no longer dependent on it.
func NewCLIPrompt(cfg PromptConfig, writer io.Writer) *CLIPrompt {
	return &CLIPrompt{
		PromptConfig: cfg,
		Writer:       writer,
	}
}

func (c *CLIPrompt) stdin() prompt.StdinReader {
	if c.StdinFunc == nil {
		return prompt.Stdin()
	}
	return c.StdinFunc()
}

// Run prompts the user to complete an MFA authentication challenge.
func (c *CLIPrompt) Run(ctx context.Context, chal *proto.MFAAuthenticateChallenge) (*proto.MFAAuthenticateResponse, error) {
	if c.Writer == nil {
		c.Writer = os.Stderr
	}

	if c.PromptReason != "" {
		fmt.Fprintln(c.Writer, c.PromptReason)
	}

	promptOTP := chal.TOTP != nil
	promptWebauthn := chal.WebauthnChallenge != nil && c.WebauthnSupported
	promptSSO := false // TODO(Joerger): check for SSO challenge once added in separate PR.

	// No prompt to run, no-op.
	if !promptOTP && !promptWebauthn && !promptSSO {
		return &proto.MFAAuthenticateResponse{}, nil
	}

	var availableMethods []string
	if promptWebauthn {
		availableMethods = append(availableMethods, CLIMFATypeWebauthn)
	}
	if promptSSO {
		availableMethods = append(availableMethods, CLIMFATypeSSO)
	}
	if promptOTP {
		availableMethods = append(availableMethods, CLIMFATypeOTP)
	}

	// Use stronger auth methods if hijack is not allowed.
	if !c.AllowStdinHijack && (promptWebauthn || promptSSO) {
		promptOTP = false
	}

	// Prefer Webauthn > SSO > OTP, or whatever method is requested or required by the client.
	var chosenMethod string
	switch {
	case promptWebauthn && c.AuthenticatorAttachment != wancli.AttachmentAuto:
		// Prefer Webauthn if a specific webauthn attachment was requested.
		chosenMethod = CLIMFATypeWebauthn
		promptSSO, promptOTP = false, false
	case c.PreferSSO && promptSSO:
		chosenMethod = CLIMFATypeSSO
		promptWebauthn, promptOTP = false, false
	case c.PreferOTP && promptOTP:
		chosenMethod = CLIMFATypeOTP
		promptWebauthn, promptSSO = false, false
	case promptWebauthn:
		// prefer webauthn over sso, but allow dual prompt with totp.
		chosenMethod = CLIMFATypeWebauthn
		promptSSO = false
		if promptOTP {
			chosenMethod = fmt.Sprintf("%v and %v", CLIMFATypeWebauthn, CLIMFATypeOTP)
		}
	case promptSSO:
		// prefer sso over otp
		chosenMethod = CLIMFATypeSSO
		promptOTP = false
	case promptOTP:
		chosenMethod = CLIMFATypeOTP
	}

	fmt.Fprintf(c.Writer, "Available MFA methods [%v]. Continuing with %v.\n", strings.Join(availableMethods, ", "), chosenMethod)
	fmt.Fprintln(c.Writer, "If you wish to perform MFA with another method, specify with flag --mfa-mode=<sso,otp>.")

	// Depending on the run opts, we may spawn a TOTP goroutine, webauth goroutine, or both.
	spawnGoroutines := func(ctx context.Context, wg *sync.WaitGroup, respC chan<- MFAGoroutineResponse) {
		dualPrompt := promptOTP && promptWebauthn

		// Print the prompt message directly here in case of dualPrompt.
		// This avoids problems with a goroutine failing before any message is
		// printed.
		if dualPrompt {
			var message string
			if runtime.GOOS == constants.WindowsOS {
				message = "Follow the OS dialogs for platform authentication, or enter an OTP code here:"
				webauthnwin.SetPromptPlatformMessage("")
			} else {
				message = fmt.Sprintf("Tap any %ssecurity key or enter a code from a %sOTP device", c.promptDevicePrefix(), c.promptDevicePrefix())
			}
			fmt.Fprintln(c.Writer, message)
		}

		// Fire OTP goroutine.
		var otpCancelAndWait func()
		if promptOTP {
			otpCtx, otpCancel := context.WithCancel(ctx)
			otpDone := make(chan struct{})
			otpCancelAndWait = func() {
				otpCancel()
				<-otpDone
			}

			wg.Add(1)
			go func() {
				defer func() {
					wg.Done()
					otpCancel()
					close(otpDone)
				}()

				quiet := c.Quiet || dualPrompt
				resp, err := c.promptOTP(otpCtx, quiet)
				respC <- MFAGoroutineResponse{Resp: resp, Err: trace.Wrap(err, "TOTP authentication failed")}
			}()
		}

		// Fire Webauthn goroutine.
		if promptWebauthn {
			wg.Add(1)
			go func() {
				defer func() {
					wg.Done()
					// Important for dual-prompt, harmless otherwise.
					webauthnwin.ResetPromptPlatformMessage()
				}()

				// Get webauthn prompt and wrap with otp context handler.
				prompt := &webauthnPromptWithOTP{
					LoginPrompt:      c.getWebauthnPrompt(ctx, dualPrompt),
					otpCancelAndWait: otpCancelAndWait,
				}

				resp, err := c.promptWebauthn(ctx, chal, prompt)
				respC <- MFAGoroutineResponse{Resp: resp, Err: trace.Wrap(err, "Webauthn authentication failed")}
			}()
		}
	}

	return HandleMFAPromptGoroutines(ctx, spawnGoroutines)
}

func (c *CLIPrompt) promptOTP(ctx context.Context, quiet bool) (*proto.MFAAuthenticateResponse, error) {
	var msg string
	if !quiet {
		msg = fmt.Sprintf("Enter an OTP code from a %sdevice", c.promptDevicePrefix())
	}

	otp, err := prompt.Password(ctx, c.Writer, c.stdin(), msg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &proto.MFAAuthenticateResponse{
		Response: &proto.MFAAuthenticateResponse_TOTP{
			TOTP: &proto.TOTPResponse{Code: otp},
		},
	}, nil
}

func (c *CLIPrompt) getWebauthnPrompt(ctx context.Context, dualPrompt bool) wancli.LoginPrompt {
	writer := c.Writer
	if c.Quiet {
		writer = io.Discard
	}

	prompt := wancli.NewDefaultPrompt(ctx, writer)
	prompt.StdinFunc = c.StdinFunc
	prompt.SecondTouchMessage = fmt.Sprintf("Tap your %ssecurity key to complete login", c.promptDevicePrefix())
	prompt.FirstTouchMessage = fmt.Sprintf("Tap any %ssecurity key", c.promptDevicePrefix())

	// Skip when both OTP and WebAuthn are possible, as the prompt happens
	// externally.
	if dualPrompt {
		prompt.FirstTouchMessage = ""
	}

	return prompt
}

func (c *CLIPrompt) promptWebauthn(ctx context.Context, chal *proto.MFAAuthenticateChallenge, prompt wancli.LoginPrompt) (*proto.MFAAuthenticateResponse, error) {
	opts := &wancli.LoginOpts{AuthenticatorAttachment: c.AuthenticatorAttachment}
	resp, _, err := c.WebauthnLoginFunc(ctx, c.GetWebauthnOrigin(), wantypes.CredentialAssertionFromProto(chal.WebauthnChallenge), prompt, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return resp, nil
}

func (c *CLIPrompt) promptDevicePrefix() string {
	if c.DeviceType != "" {
		return fmt.Sprintf("*%s* ", c.DeviceType)
	}
	return ""
}

// webauthnPromptWithOTP implements wancli.LoginPrompt for MFA logins.
// In most cases authenticators shouldn't require PINs or additional touches for
// MFA, but the implementation exists in case we find some unusual
// authenticators out there.
type webauthnPromptWithOTP struct {
	wancli.LoginPrompt

	otpCancelAndWaitOnce sync.Once
	otpCancelAndWait     func()
}

func (w *webauthnPromptWithOTP) cancelOTP() {
	if w.otpCancelAndWait == nil {
		return
	}
	w.otpCancelAndWaitOnce.Do(w.otpCancelAndWait)
}

func (w *webauthnPromptWithOTP) PromptTouch() (wancli.TouchAcknowledger, error) {
	ack, err := w.LoginPrompt.PromptTouch()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return func() error {
		err := ack()

		// Stop the OTP goroutine when the first touch is acknowledged.
		w.cancelOTP()

		return trace.Wrap(err)
	}, nil
}

func (w *webauthnPromptWithOTP) PromptPIN() (string, error) {
	// Stop the OTP goroutine before asking for PIN, in case it wasn't already
	// stopped through PromptTouch.
	w.cancelOTP()

	return w.LoginPrompt.PromptPIN()
}
