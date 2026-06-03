// vpn-bot is the Telegram onboarding bot for govpn: a user redeems a one-time
// invite token and receives a ready-to-import .vpnio profile.
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
	"syscall"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/invite"
	"github.com/govpn/internal/profile"
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

  serve -telegram-token TOKEN -dir CA_DIR -server HOST:PORT [-server-name S] [-store FILE]
        run the bot: redeem invite tokens and deliver .vpnio profiles

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
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	if strings.ContainsAny(*name, `/\`) || *name == "." || *name == ".." {
		return fmt.Errorf("-name must be a plain client name (no path separators)")
	}
	tok, err := invite.New(*storePath).Generate(*name)
	if err != nil {
		return err
	}
	fmt.Printf("Invite token for %q:\n\n  %s\n\nSend it to the person; they message it to the bot to receive their profile.\n", *name, tok.Value)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	tgToken := fs.String("telegram-token", "", "Telegram bot token from @BotFather (required)")
	dir := fs.String("dir", defaultDir, "CA directory (must contain ca.key to sign client certs)")
	server := fs.String("server", "", "server address clients connect to, host:port (required)")
	serverName := fs.String("server-name", "", "SNI / certificate verification host (optional)")
	storePath := fs.String("store", defaultStore, "invite token store file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tgToken == "" {
		return fmt.Errorf("-telegram-token is required")
	}
	if *server == "" {
		return fmt.Errorf("-server is required")
	}
	// Load the CA once: it holds ca.key in memory for signing, so we don't
	// re-read the key on every onboarding (and we fail fast here if it's
	// missing, before going online).
	authority, err := ca.Load(*dir)
	if err != nil {
		return fmt.Errorf("load CA from %s: %w", *dir, err)
	}

	bot, err := tgbotapi.NewBotAPI(*tgToken)
	if err != nil {
		return fmt.Errorf("connect to Telegram: %w", err)
	}
	store := invite.New(*storePath)
	log.Printf("vpn-bot online as @%s", bot.Self.UserName)

	// Stop cleanly on SIGTERM / Interrupt (systemd stop). Updates are processed
	// one at a time, so an in-flight onboarding finishes before we exit — no
	// half-issued client left behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)
	for {
		select {
		case <-ctx.Done():
			bot.StopReceivingUpdates()
			log.Print("vpn-bot shutting down")
			return nil
		case update, ok := <-updates:
			if !ok {
				return nil
			}
			if update.Message == nil || update.Message.From == nil {
				continue
			}
			handleMessage(bot, store, authority, update.Message, *server, *serverName)
		}
	}
}

const helpText = "Send me your one-time invite token and I'll send back your vpn.io profile (.vpnio). " +
	"Ask the owner for a token if you don't have one."

func handleMessage(bot *tgbotapi.BotAPI, store *invite.Store, authority *ca.CA, msg *tgbotapi.Message, server, serverName string) {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}
	if text == "/start" || text == "/help" {
		reply(bot, msg.Chat.ID, helpText)
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
