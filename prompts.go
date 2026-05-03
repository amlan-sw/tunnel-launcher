package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// CredentialPrompts is what the SSH layer asks for when it needs the user's
// help. All methods block the calling goroutine until the user responds.
type CredentialPrompts interface {
	Passphrase(identityPath string) (pass string, ok bool)
	Password(user, host string) (pass string, ok bool)
	HostKeyMismatch(host, oldFingerprint, newFingerprint string)
}

// guiPrompts opens a small native window per request. Cross-goroutine UI is
// safe under Fyne 2.5 here for the same reason dialog.ShowError is — these
// calls already happen from connect goroutines elsewhere in the app.
type guiPrompts struct {
	app fyne.App
}

func newGUIPrompts(a fyne.App) *guiPrompts { return &guiPrompts{app: a} }

func (g *guiPrompts) Passphrase(identityPath string) (string, bool) {
	title := "Unlock SSH key"
	msg := fmt.Sprintf("Enter passphrase for key %s", identityPath)
	return askSecret(g.app, title, msg, "passphrase", "Unlock")
}

func (g *guiPrompts) Password(user, host string) (string, bool) {
	title := "SSH password"
	msg := fmt.Sprintf("Enter password for %s@%s", user, host)
	return askSecret(g.app, title, msg, "password", "Connect")
}

func (g *guiPrompts) HostKeyMismatch(host, oldFp, newFp string) {
	w := g.app.NewWindow("Host key changed")
	w.Resize(fyne.NewSize(560, 240))

	body := widget.NewLabel(fmt.Sprintf(
		"The host key for %s does not match the previously trusted key.\n\n"+
			"Stored:  %s\nOffered: %s\n\n"+
			"Connection aborted. If this change is expected, remove the host\n"+
			"from the tunnel-launcher known_hosts file and reconnect.",
		host, oldFp, newFp))
	body.Wrapping = fyne.TextWrapWord

	closeBtn := widget.NewButtonWithIcon("Close", theme.CancelIcon(), func() { w.Close() })
	w.SetContent(container.NewBorder(nil, container.NewHBox(closeBtn), nil, nil, body))
	w.Show()
}

// askSecret opens a single-field password prompt and blocks until the user
// submits or cancels. Returns ("", false) on cancel / window close.
func askSecret(a fyne.App, title, prompt, placeholder, okLabel string) (string, bool) {
	w := a.NewWindow(title)
	w.Resize(fyne.NewSize(420, 160))

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

	okBtn := widget.NewButtonWithIcon(okLabel, theme.ConfirmIcon(), func() {
		send(entry.Text, true)
		w.Close()
	})
	okBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
		send("", false)
		w.Close()
	})
	entry.OnSubmitted = func(string) { okBtn.OnTapped() }

	w.SetCloseIntercept(func() {
		send("", false)
		w.Close()
	})

	buttons := container.NewHBox(cancelBtn, okBtn)
	w.SetContent(container.NewBorder(label, buttons, nil, nil, entry))
	w.Show()
	w.Canvas().Focus(entry)

	r := <-resultCh
	return r.s, r.ok
}

// showConnectError surfaces a tunnel-open failure in a standalone window so
// it remains visible when the main window is hidden in the tray.
func showConnectError(a fyne.App, name string, err error) {
	w := a.NewWindow("Tunnel connect failed")
	w.Resize(fyne.NewSize(520, 200))

	header := widget.NewLabel(fmt.Sprintf("Could not open tunnel %q.", name))
	header.TextStyle = fyne.TextStyle{Bold: true}

	body := widget.NewMultiLineEntry()
	body.SetText(err.Error())
	body.Wrapping = fyne.TextWrapWord
	body.Disable()

	closeBtn := widget.NewButtonWithIcon("Close", theme.CancelIcon(), func() { w.Close() })
	w.SetContent(container.NewBorder(header, container.NewHBox(closeBtn), nil, nil, body))
	w.Show()
}
