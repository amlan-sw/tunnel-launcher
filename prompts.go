package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// CredentialPrompts is what the SSH layer asks for when it needs the user's
// help. All methods block the calling goroutine until the user responds.
type CredentialPrompts interface {
	Passphrase(identityPath string) (pass string, ok bool)
	Password(user, host string) (pass string, ok bool)
	HostKeyMismatch(host, oldFingerprint, newFingerprint string)
}

// guiPrompts anchors all credential dialogs on the main window via
// fyne.io/fyne/v2/dialog. Standalone windows (a.NewWindow) used to host
// these prompts but caused subsequent dialogs anchored on the main window
// to misrender — Fyne's modal-owner state breaks once a non-master window
// is closed. dialog.NewX(..., window) keeps that invariant intact.
type guiPrompts struct {
	app    fyne.App
	window fyne.Window
}

func newGUIPrompts(a fyne.App, w fyne.Window) *guiPrompts {
	return &guiPrompts{app: a, window: w}
}

// surface brings the main window forward before showing a prompt. The user
// may have triggered the connect from the tray with the window hidden; a
// dialog parented to a hidden window has nothing to attach to.
func (g *guiPrompts) surface() {
	g.window.Show()
	g.window.RequestFocus()
}

func (g *guiPrompts) Passphrase(identityPath string) (string, bool) {
	g.surface()
	return g.askSecret(
		"Unlock SSH key",
		fmt.Sprintf("Enter passphrase for key %s", identityPath),
		"passphrase",
		"Unlock",
	)
}

func (g *guiPrompts) Password(user, host string) (string, bool) {
	g.surface()
	return g.askSecret(
		"SSH password",
		fmt.Sprintf("Enter password for %s@%s", user, host),
		"password",
		"Connect",
	)
}

func (g *guiPrompts) HostKeyMismatch(host, oldFp, newFp string) {
	g.surface()
	body := widget.NewLabel(fmt.Sprintf(
		"The host key for %s does not match the previously trusted key.\n\n"+
			"Stored:  %s\nOffered: %s\n\n"+
			"Connection aborted. If this change is expected, remove the host "+
			"from the tunnel-launcher known_hosts file and reconnect.",
		host, oldFp, newFp))
	body.Wrapping = fyne.TextWrapWord
	dialog.ShowCustom("Host key changed", "Close", body, g.window)
}

// askSecret opens a single-field password prompt anchored on the main
// window and blocks until the user submits or cancels. Returns ("", false)
// on cancel / dialog close.
func (g *guiPrompts) askSecret(title, prompt, placeholder, okLabel string) (string, bool) {
	label := widget.NewLabel(prompt)
	label.Wrapping = fyne.TextWrapWord

	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder(placeholder)

	resultCh := make(chan struct {
		s  string
		ok bool
	}, 1)
	sent := false
	send := func(s string, ok bool) {
		if sent {
			return
		}
		sent = true
		resultCh <- struct {
			s  string
			ok bool
		}{s, ok}
	}

	content := container.NewBorder(label, nil, nil, nil, entry)
	d := dialog.NewCustomConfirm(title, okLabel, "Cancel", content, func(ok bool) {
		if ok {
			send(entry.Text, true)
		} else {
			send("", false)
		}
	}, g.window)
	entry.OnSubmitted = func(string) { send(entry.Text, true); d.Hide() }
	d.Resize(fyne.NewSize(420, 160))
	d.Show()
	g.window.Canvas().Focus(entry)

	r := <-resultCh
	return r.s, r.ok
}
