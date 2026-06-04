// vpn-bot is the Telegram onboarding bot for govpn: a user redeems a one-time
// invite token and receives a ready-to-import .vpnio profile — and, with
// -installers, buttons to download the app installer for their OS.
//
// Generate a token (run where the CA lives):
//
//	vpn-bot token -name alice
//
// Run the bot (long-polls Telegram; needs the CA directory — including ca.key
// to sign client certs — and the server address clients connect to):
//
//	vpn-bot serve -telegram-token <BOT_TOKEN> -dir ca-data -server vpn.example.com:8443
//
// Because the bot signs certificates, it must run on a host that holds ca.key.
// See docs/BOT.md for deployment and the trust trade-off.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/invite"
	"github.com/govpn/internal/profile"
	"github.com/govpn/internal/revoke"
)

const (
	defaultDir   = "./ca-data"
	defaultStore = "./invite-tokens.json"
	// maxTokenLen bounds candidate-token text so a huge message never reaches
	// the store; a real token is ~22 chars.
	maxTokenLen = 128
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "token":
		err = cmdToken(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vpn-bot — Telegram onboarding bot for govpn.

Commands:
  token -name NAME [-store FILE]
        generate a one-time invite token for a client and print it

  serve -telegram-token TOKEN -dir CA_DIR -server HOST:PORT [-server-name S] [-store FILE] [-installers DIR] [-owner ID]
        run the bot: redeem invite tokens and deliver .vpnio profiles.
        With -installers DIR, also offer the app installer for the user's OS
        (*.exe / *.pkg / *.deb found in DIR) via inline buttons.
        With -owner ID, that Telegram user can manage clients in-chat instead
        of this CLI: /invite <name>, /revoke <name>, /unrevoke <name>, /revoked.
        Anyone can /whoami to learn their own ID.

Defaults: -dir ./ca-data, -store ./invite-tokens.json
`)
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	name := fs.String("name", "", "client name to issue when the token is redeemed (required)")
	storePath := fs.String("store", defaultStore, "invite token store file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateClientName(*name); err != nil {
		return fmt.Errorf("-name: %w", err)
	}
	tok, err := invite.New(*storePath).Generate(*name)
	if err != nil {
		return err
	}
	fmt.Printf("Invite token for %q:\n\n  %s\n\nSend it to the person; they message it to the bot to receive their profile.\n", *name, tok.Value)
	return nil
}

// validateClientName rejects names that aren't a plain, filesystem-safe client
// identifier. The CA writes <name>.crt/.key, so a path separator would escape
// the directory and an over-long name would break os.WriteFile (NAME_MAX 255).
// Because a redeemed token is spent before the cert is issued, a name that only
// fails at issue time would burn the token — so reject it up front. Shared by
// the `token` command and `/invite`.
func validateClientName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("name is required")
	case len(name) > 64:
		return fmt.Errorf("name too long (max 64 characters)")
	case strings.ContainsAny(name, `/\`) || name == "." || name == "..":
		return fmt.Errorf("name must be plain — no path separators")
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	tgToken := fs.String("telegram-token", "", "Telegram bot token from @BotFather (required)")
	dir := fs.String("dir", defaultDir, "CA directory (must contain ca.key to sign client certs)")
	server := fs.String("server", "", "server address clients connect to, host:port (required)")
	serverName := fs.String("server-name", "", "SNI / certificate verification host (optional)")
	storePath := fs.String("store", defaultStore, "invite token store file")
	installersDir := fs.String("installers", "", "directory with app installers (*.exe/*.pkg/*.deb) to offer after the profile; empty disables")
	ownerID := fs.Int64("owner", 0, "Telegram user ID allowed to mint tokens with /invite (0 disables; send /whoami to the bot to find yours)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Accept the bot token from the environment too, so a systemd unit can keep
	// it out of the command line (and out of `ps`).
	tgTokenVal := *tgToken
	if tgTokenVal == "" {
		tgTokenVal = os.Getenv("TELEGRAM_TOKEN")
	}
	if tgTokenVal == "" {
		return fmt.Errorf("-telegram-token (or TELEGRAM_TOKEN env) is required")
	}
	if *server == "" {
		return fmt.Errorf("-server is required")
	}
	// Fail fast on a misconfigured installers path rather than discovering it
	// only when the first user taps a button.
	if *installersDir != "" {
		if fi, err := os.Stat(*installersDir); err != nil || !fi.IsDir() {
			return fmt.Errorf("-installers %q is not a directory", *installersDir)
		}
	}
	// Load the CA once: it holds ca.key in memory for signing, so we don't
	// re-read the key on every onboarding (and we fail fast here if it's
	// missing, before going online).
	authority, err := ca.Load(*dir)
	if err != nil {
		return fmt.Errorf("load CA from %s: %w", *dir, err)
	}

	bot, err := tgbotapi.NewBotAPI(tgTokenVal)
	if err != nil {
		return fmt.Errorf("connect to Telegram: %w", err)
	}
	store := invite.New(*storePath)
	log.Printf("vpn-bot online as @%s", bot.Self.UserName)

	// Stop cleanly on SIGTERM / Interrupt (systemd stop). Messages are handled
	// inline (one at a time), so an in-flight onboarding finishes before we exit.
	// Installer uploads run in background goroutines tracked by wg, so shutdown
	// waits for them — cutting one off would hand the user a truncated file.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	// Cap concurrent installer uploads so repeated button taps can't spawn an
	// unbounded number of multi-MB transfers.
	sendSem := make(chan struct{}, 4)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)
	for {
		select {
		case <-ctx.Done():
			bot.StopReceivingUpdates()
			log.Print("vpn-bot shutting down")
			wg.Wait()
			return nil
		case update, ok := <-updates:
			if !ok {
				wg.Wait()
				return nil
			}
			if update.CallbackQuery != nil {
				// Uploading an installer (tens of MB) can take many seconds; run
				// it off the main loop so other users' updates and a SIGTERM
				// shutdown aren't blocked behind it. wg + sendSem bound and track
				// these uploads.
				cq := update.CallbackQuery
				wg.Add(1)
				go func() {
					defer wg.Done()
					// Acquire a slot off the main loop, but bail if we start
					// shutting down before we get one — a still-queued upload
					// shouldn't hold up wg.Wait().
					select {
					case sendSem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-sendSem }()
					handleCallback(bot, cq, *installersDir)
				}()
				continue
			}
			if update.Message == nil || update.Message.From == nil {
				continue
			}
			handleMessage(bot, store, authority, update.Message, *server, *serverName, *installersDir, *ownerID)
		}
	}
}

const helpText = "Send me your one-time invite token and I'll send back your vpn.io profile (.vpnio). " +
	"Ask the owner for a token if you don't have one."

func handleMessage(bot *tgbotapi.BotAPI, store *invite.Store, authority *ca.CA, msg *tgbotapi.Message, server, serverName, installersDir string, ownerID int64) {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}
	// Telegram commands — msg.Command() strips the leading slash and any
	// @BotName suffix (group chats), so parsing is robust there too.
	switch msg.Command() {
	case "start", "help":
		reply(bot, msg.Chat.ID, helpText)
		return
	case "whoami":
		// Not secret, and how the owner discovers the value to pass as -owner.
		reply(bot, msg.Chat.ID, fmt.Sprintf("Your Telegram ID is %d.", msg.From.ID))
		return
	case "invite":
		// A token is a credential: mint it only for the owner, and only in a
		// private chat. Every other case (non-owner, or even the owner in a
		// group) just gets the greeting — that neither prints a token nor
		// reveals to a group who the owner is.
		if ownerID != 0 && msg.From.ID == ownerID && msg.Chat.IsPrivate() {
			handleInvite(bot, store, msg)
		} else {
			reply(bot, msg.Chat.ID, helpText)
		}
		return
	case "revoke", "unrevoke", "revoked":
		// Same gate as /invite: owner only, private chat only.
		if ownerID != 0 && msg.From.ID == ownerID && msg.Chat.IsPrivate() {
			handleRevokeCommand(bot, authority, msg)
		} else {
			reply(bot, msg.Chat.ID, helpText)
		}
		return
	}
	if len(text) > maxTokenLen {
		reply(bot, msg.Chat.ID, "That doesn't look like an invite token. Send the token the owner gave you.")
		return
	}

	// Any other short text is treated as a candidate invite token.
	who := userLabel(msg.From)
	name, err := store.Redeem(text, who)
	if err != nil {
		if errors.Is(err, invite.ErrNotFound) {
			reply(bot, msg.Chat.ID, "That invite is invalid or already used. Ask the owner for a new one.")
		} else {
			// A real store failure (disk, permissions) — the user's token may
			// be fine, so don't call it invalid. Log it and apologise.
			log.Printf("redeem token from %s: %v", who, err)
			reply(bot, msg.Chat.ID, "Sorry — something went wrong on our side. The owner has been notified.")
		}
		return
	}

	bundle, err := issueBundle(authority, name, server, serverName)
	if err != nil {
		// Don't leak internals to the user; log for the operator.
		log.Printf("issue bundle for %q (%s): %v", name, who, err)
		reply(bot, msg.Chat.ID, "Sorry — couldn't create your profile. The owner has been notified.")
		return
	}

	doc := tgbotapi.NewDocument(msg.Chat.ID, tgbotapi.FileBytes{Name: name + ".vpnio", Bytes: bundle})
	doc.Caption = "Your vpn.io profile. In the app choose \"Import a profile file\" and pick this file."
	if _, err := bot.Send(doc); err != nil {
		// The token is already spent and the cert issued, so don't leave the
		// user with silence — tell them; the owner can re-issue if needed.
		log.Printf("send profile to %s: %v", who, err)
		reply(bot, msg.Chat.ID, "Your profile was created but I couldn't send the file — please contact the owner.")
		return
	}
	log.Printf("issued profile %q to %s", name, who)

	// Offer the app installer for the user's OS, if any are configured.
	if installersDir != "" {
		if kb, ok := installerKeyboard(installersDir); ok {
			m := tgbotapi.NewMessage(msg.Chat.ID, "Now grab the vpn.io app for your system:")
			m.ReplyMarkup = kb
			if _, err := bot.Send(m); err != nil {
				log.Printf("send installer menu to %s: %v", who, err)
			}
		}
	}
}

// handleInvite mints a one-time token from an owner's "/invite <name>" and
// replies with it. The caller has already verified the sender is the owner.
func handleInvite(bot *tgbotapi.BotAPI, store *invite.Store, msg *tgbotapi.Message) {
	name := strings.TrimSpace(msg.CommandArguments())
	if err := validateClientName(name); err != nil {
		reply(bot, msg.Chat.ID, "Can't use that name ("+err.Error()+"). Usage: /invite <client-name>")
		return
	}
	tok, err := store.Generate(name)
	if err != nil {
		log.Printf("/invite generate %q: %v", name, err)
		reply(bot, msg.Chat.ID, "Couldn't generate a token — check the logs.")
		return
	}
	// Audit: a minted token is a credential, like an issued profile.
	log.Printf("minted invite token for %q via /invite from %s", name, userLabel(msg.From))
	reply(bot, msg.Chat.ID, fmt.Sprintf("Invite token for %q (single-use):\n\n%s\n\nSend it to the person; they message it to me.", name, tok.Value))
}

// handleRevokeCommand serves the owner's /revoke, /unrevoke and /revoked against
// the same revoked.json the server enforces. The caller has verified the sender
// is the owner and the chat is private.
func handleRevokeCommand(bot *tgbotapi.BotAPI, authority *ca.CA, msg *tgbotapi.Message) {
	store := revoke.New(filepath.Join(authority.Dir, "revoked.json"))

	if msg.Command() == "revoked" {
		entries, err := store.List()
		if err != nil {
			log.Printf("/revoked list: %v", err)
			reply(bot, msg.Chat.ID, "Couldn't read the revocation list — check the logs.")
			return
		}
		if len(entries) == 0 {
			reply(bot, msg.Chat.ID, "No revoked clients.")
			return
		}
		var b strings.Builder
		b.WriteString("Revoked clients:\n")
		for _, e := range entries {
			fmt.Fprintf(&b, "• %s (%s)\n", e.Name, e.RevokedAt.Format("2006-01-02"))
		}
		reply(bot, msg.Chat.ID, b.String())
		return
	}

	// /revoke and /unrevoke both take a client name.
	name := strings.TrimSpace(msg.CommandArguments())
	if err := validateClientName(name); err != nil {
		reply(bot, msg.Chat.ID, "Can't use that name ("+err.Error()+"). Usage: /"+msg.Command()+" <client-name>")
		return
	}
	who := userLabel(msg.From)

	if msg.Command() == "unrevoke" {
		n, err := store.Remove(name)
		if err != nil {
			log.Printf("/unrevoke %q: %v", name, err)
			reply(bot, msg.Chat.ID, "Couldn't un-revoke — check the logs.")
			return
		}
		if n == 0 {
			reply(bot, msg.Chat.ID, fmt.Sprintf("%q had no revoked certificates.", name))
			return
		}
		log.Printf("un-revoked %q via /unrevoke from %s", name, who)
		reply(bot, msg.Chat.ID, fmt.Sprintf("Un-revoked %q.", name))
		return
	}

	// /revoke: look up the issued cert's serial and add it to the deny-list.
	serial, err := ca.ClientSerial(authority.Dir, name)
	if err != nil {
		log.Printf("/revoke %q: %v", name, err)
		reply(bot, msg.Chat.ID, fmt.Sprintf("No issued client named %q (or its certificate is unreadable).", name))
		return
	}
	added, err := store.Add(serial, name)
	if err != nil {
		log.Printf("/revoke add %q: %v", name, err)
		reply(bot, msg.Chat.ID, "Couldn't revoke — check the logs.")
		return
	}
	if !added {
		reply(bot, msg.Chat.ID, fmt.Sprintf("%q was already revoked.", name))
		return
	}
	log.Printf("revoked %q via /revoke from %s", name, who)
	reply(bot, msg.Chat.ID, fmt.Sprintf("Revoked %q. The server cuts it off on its next connection.", name))
}

// userLabel is a human-ish audit string for a Telegram user. UserName is
// optional, so fall back to the (always present) first name; the numeric ID is
// the reliable identifier either way.
func userLabel(u *tgbotapi.User) string {
	name := u.UserName
	if name == "" {
		name = u.FirstName
	}
	return fmt.Sprintf("%s (id %d)", name, u.ID)
}

func reply(bot *tgbotapi.BotAPI, chatID int64, text string) {
	if _, err := bot.Send(tgbotapi.NewMessage(chatID, text)); err != nil {
		log.Printf("send reply: %v", err)
	}
}

// issueBundle issues a fresh client certificate with the loaded CA and packs it
// into a .vpnio bundle.
func issueBundle(authority *ca.CA, name, server, serverName string) ([]byte, error) {
	if err := authority.IssueClient(name); err != nil {
		return nil, fmt.Errorf("issue client %q: %w", name, err)
	}
	caPEM, err := os.ReadFile(filepath.Join(authority.Dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(authority.Dir, "clients", name+".crt"))
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(authority.Dir, "clients", name+".key"))
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}
	return profile.MarshalBundle(caPEM, certPEM, keyPEM, server, serverName)
}

// installerOS describes one downloadable installer the bot can hand out.
type installerOS struct {
	key, label, pattern, hint string
}

// installerOSes is the fixed platform menu, matched to the installer files the
// owner drops into -installers by extension.
var installerOSes = []installerOS{
	{"windows", "Windows", "*.exe", "Run the installer. If Windows SmartScreen warns: \"More info\" → \"Run anyway\", then approve the admin prompt."},
	{"macos", "macOS", "*.pkg", "Right-click the .pkg → Open (it's unsigned), then follow the installer and enter your admin password."},
	{"linux", "Linux", "*.deb", "Install with: sudo apt install ./<file>.deb — then log out and back in once."},
}

// installerKeyboard builds an inline keyboard with a button per OS that has an
// installer file present in dir. ok is false when none are available.
func installerKeyboard(dir string) (tgbotapi.InlineKeyboardMarkup, bool) {
	var row []tgbotapi.InlineKeyboardButton
	for _, o := range installerOSes {
		if _, err := findInstaller(dir, o.pattern); err == nil {
			row = append(row, tgbotapi.NewInlineKeyboardButtonData(o.label, "install:"+o.key))
		}
	}
	if len(row) == 0 {
		return tgbotapi.InlineKeyboardMarkup{}, false
	}
	return tgbotapi.NewInlineKeyboardMarkup(row), true
}

// handleCallback answers an OS button tap by sending that platform's installer.
// Installers aren't secret (useless without a profile), so this needs no token —
// and the keyboard is only ever shown after a successful redemption.
func handleCallback(bot *tgbotapi.BotAPI, cq *tgbotapi.CallbackQuery, installersDir string) {
	// Always answer the callback so the user's button stops spinning.
	if _, err := bot.Request(tgbotapi.NewCallback(cq.ID, "")); err != nil {
		log.Printf("answer callback: %v", err)
	}
	if cq.Message == nil || installersDir == "" {
		return
	}
	if !strings.HasPrefix(cq.Data, "install:") {
		return
	}
	key := strings.TrimPrefix(cq.Data, "install:")
	var sel *installerOS
	for i := range installerOSes {
		if installerOSes[i].key == key {
			sel = &installerOSes[i]
			break
		}
	}
	if sel == nil {
		return
	}
	path, err := findInstaller(installersDir, sel.pattern)
	if err != nil {
		reply(bot, cq.Message.Chat.ID, "The "+sel.label+" installer isn't available right now — ask the owner.")
		return
	}
	doc := tgbotapi.NewDocument(cq.Message.Chat.ID, tgbotapi.FilePath(path))
	doc.Caption = sel.hint
	if _, err := bot.Send(doc); err != nil {
		log.Printf("send %s installer to chat %d: %v", sel.key, cq.Message.Chat.ID, err)
		reply(bot, cq.Message.Chat.ID, "Couldn't send the "+sel.label+" installer — please contact the owner.")
	}
}

// findInstaller returns the newest file in dir matching pattern (e.g. "*.exe"),
// so dropping in a new build without deleting the old still serves the latest.
func findInstaller(dir, pattern string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return "", err
	}
	var best string
	var bestT time.Time
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || fi.IsDir() {
			continue
		}
		if best == "" || fi.ModTime().After(bestT) {
			best, bestT = m, fi.ModTime()
		}
	}
	if best == "" {
		return "", fmt.Errorf("no installer matching %s in %s", pattern, dir)
	}
	return best, nil
}
