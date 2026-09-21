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
	"github.com/govpn/internal/vless"
	"github.com/govpn/internal/watchdog"
)

const (
	defaultDir   = "./ca-data"
	defaultStore = "./invite-tokens.json"
	// maxTokenLen bounds candidate-token text so a huge message never reaches
	// the store; a real token is ~22 chars.
	maxTokenLen = 128
	// maxPollFailures bounds consecutive update-poll failures before the bot
	// gives up and exits non-zero. A transient blip or Telegram 5xx clears well
	// under this; a permanent fault (a revoked or invalid token) fails every
	// poll, so exiting lets a supervisor restart or alert instead of leaving a
	// live-looking process that quietly fetches nothing.
	maxPollFailures = 10
	// pollBackoff is the pause after a failed update poll — the same 3s the
	// library's own GetUpdatesChan used, so a flapping network isn't hammered.
	pollBackoff = 3 * time.Second
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
	case "list":
		err = cmdList(os.Args[2:])
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
  token -name NAME [-grant profile|vless|both] [-store FILE]
        generate a one-time invite token for a client and print it.
        The grant decides what redeeming it hands over: a profile for the
        vpn.io app, a vless:// link for a third-party client, or both.

  list [-store FILE]
        list issued invites (name + status: PENDING/EXPIRED/used); no secrets

  serve -telegram-token TOKEN -dir CA_DIR -server HOST:PORT [-server-name S] [-store FILE] [-installers DIR] [-owner ID]
        run the bot: redeem invite tokens and deliver .vpnio profiles.
        With -installers DIR, also offer the app installer for the user's OS
        (*.exe / *.pkg / *.deb found in DIR) via inline buttons.
        With -owner ID, that Telegram user can manage clients in-chat instead
        of this CLI: /invite <name> [profile|vless|both], /invites,
        /revoke <name>, /unrevoke <name>, /revoked. Anyone can /whoami to
        learn their own ID.
        With -vless-dir DIR, invites can also hand out VLESS access on a node
        that runs the second service; without it only profiles are issued.
        With -watch URL (needs -owner), also poll the node's health endpoint
        and message the owner when it stops serving clients — and when it
        recovers. See docs/BOT.md.

Defaults: -dir ./ca-data, -store ./invite-tokens.json
`)
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	name := fs.String("name", "", "client name to issue when the token is redeemed (required)")
	storePath := fs.String("store", defaultStore, "invite token store file")
	grantRaw := fs.String("grant", string(invite.GrantProfile), "what redeeming this token hands over: profile, vless or both")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateClientName(*name); err != nil {
		return fmt.Errorf("-name: %w", err)
	}
	grant, err := invite.ParseGrant(*grantRaw)
	if err != nil {
		return fmt.Errorf("-grant: %w", err)
	}
	tok, err := invite.New(*storePath).Generate(*name, grant)
	if err != nil {
		return err
	}
	fmt.Printf("Invite token for %q:\n\n  %s\n\nSend it to the person; they message it to the bot to receive their profile.\n", *name, tok.Value)
	return nil
}

// cmdList prints issued invites (name + status) from the store — the CLI
// counterpart of the bot's /invites, for reading the list over SSH without
// grepping the JSON. Token secrets are never printed. Expiry labels use the
// default TTL; the bot's /invites uses the running serve's -invite-ttl.
func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	storePath := fs.String("store", defaultStore, "invite token store file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tokens, err := invite.New(*storePath).List()
	if err != nil {
		return err
	}
	fmt.Print(formatInviteList(tokens, invite.DefaultInviteTTL, time.Now()))
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
	inviteTTL := fs.Duration("invite-ttl", invite.DefaultInviteTTL, "how long an invite token stays redeemable after it's issued (0 = never expires)")
	vlessDir := fs.String("vless-dir", "", "state directory of the node's VLESS service, e.g. "+vless.DefaultDir+" (empty = this node runs no VLESS service)")
	vlessUnit := fs.String("vless-unit", vless.DefaultUnit, "systemd unit of the VLESS service, watched to confirm a change was applied")
	watchURL := fs.String("watch", "", "vpn-server health endpoint to watch, e.g. http://127.0.0.1:9443/readyz (empty disables; requires -owner)")
	watchEvery := fs.Duration("watch-interval", watchdog.DefaultInterval, "how often to poll -watch")
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
	// A watchdog with nobody to notify is just load on the node it watches.
	if *watchURL != "" && *ownerID == 0 {
		return fmt.Errorf("-watch needs -owner: there is nobody to send an alert to")
	}
	// Fail fast on a VLESS directory that is not set up, rather than at the
	// moment someone redeems an invite: the token is spent by then.
	var vlessStore *vless.Store
	if *vlessDir != "" {
		vlessStore = vless.New(*vlessDir)
		if _, err := vlessStore.LoadNode(); err != nil {
			return fmt.Errorf("-vless-dir %q: %w", *vlessDir, err)
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
	store.TTL = *inviteTTL
	// One revoke.Store (with one mutex) shared across handlers, like the invite
	// store — so its read-modify-write stays serialized even if message handling
	// is ever moved off the single main goroutine.
	revoked := revoke.New(filepath.Join(authority.Dir, "revoked.json"))
	e := &env{
		authority:     authority,
		invites:       store,
		revoked:       revoked,
		vless:         vlessStore,
		vlessUnit:     *vlessUnit,
		server:        *server,
		serverName:    *serverName,
		installersDir: *installersDir,
		ownerID:       *ownerID,
	}
	log.Printf("vpn-bot online as @%s", bot.Self.UserName)
	if vlessStore != nil {
		log.Printf("VLESS access enabled from %s (unit %s)", vlessStore.Dir, *vlessUnit)
	}

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

	shutdown := func() error {
		log.Print("vpn-bot shutting down")
		wg.Wait() // let in-flight installer uploads finish, not truncate
		return nil
	}

	// Long-poll in a dedicated goroutine and fan updates in over a channel, the
	// way the library's GetUpdatesChan does internally — but here pollUpdates can
	// see each poll error and turn a persistent one (e.g. a revoked token) into a
	// fatal on pollErr, instead of the library's silent forever-retry that leaves
	// a live-looking but useless process.
	updates := make(chan tgbotapi.Update)
	pollErr := make(chan error, 1)
	go pollUpdates(ctx, bot, updates, pollErr)

	// Watch the node, if asked to. The bot is where this belongs: it already
	// holds the operator's chat and runs on the same machine as the server, so
	// an alert needs no new service and no new credential. A failure to build
	// the watcher is fatal — an operator who asked to be watched must not be
	// left believing they are.
	if *watchURL != "" {
		w, err := watchdog.New(watchdog.Config{
			URL:      *watchURL,
			Interval: *watchEvery,
			Notify:   func(text string) { reply(bot, *ownerID, text) },
			Logf:     log.Printf,
		})
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Run(ctx)
		}()
		log.Printf("watching %s every %s", *watchURL, *watchEvery)
	}

	for {
		select {
		case <-ctx.Done():
			return shutdown()
		case err := <-pollErr:
			// The poller gave up after too many consecutive failures. Drain any
			// in-flight uploads, then exit non-zero so the supervisor notices.
			wg.Wait()
			return err
		case update := <-updates:
			if update.CallbackQuery != nil {
				// Uploading an installer (tens of MB) can take many seconds; run
				// it off the main loop so other users' updates and a SIGTERM
				// shutdown aren't blocked behind it. Acquire the upload slot here,
				// *before* spawning the worker, so a burst of button taps can't
				// pile up an unbounded number of goroutines all parked on the
				// semaphore; if we're shutting down, stop instead of blocking.
				cq := update.CallbackQuery
				select {
				case sendSem <- struct{}{}:
				case <-ctx.Done():
					return shutdown()
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sendSem }()
					handleCallback(bot, cq, *installersDir)
				}()
				continue
			}
			if update.Message == nil || update.Message.From == nil {
				continue
			}
			handleMessage(bot, e, update.Message)
		}
	}
}

// pollUpdates long-polls Telegram and forwards updates on out, mirroring what
// tgbotapi.GetUpdatesChan does internally — but it counts consecutive poll
// failures and, once they cross maxPollFailures, reports the last error on fatal
// and stops. That turns a permanent fault the library would retry forever in
// silence (a revoked or invalid token fails every poll) into a visible non-zero
// exit. It returns when ctx is cancelled or after signalling a fatal error; an
// in-flight long-poll is simply abandoned as the process exits.
func pollUpdates(ctx context.Context, bot *tgbotapi.BotAPI, out chan<- tgbotapi.Update, fatal chan<- error) {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	failures := 0
	for {
		if ctx.Err() != nil {
			return
		}
		batch, err := bot.GetUpdates(u)
		if err != nil {
			failures++
			log.Printf("get updates (failure %d/%d): %v", failures, maxPollFailures, err)
			if failures >= maxPollFailures {
				select {
				case fatal <- fmt.Errorf("giving up after %d consecutive update failures: %w", failures, err):
				case <-ctx.Done():
				}
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollBackoff):
			}
			continue
		}
		failures = 0
		for _, update := range batch {
			// Mirror GetUpdatesChan's offset handling: skip anything at or below
			// the current offset, and advance past each so Telegram drops it from
			// the next batch.
			if update.UpdateID < u.Offset {
				continue
			}
			u.Offset = update.UpdateID + 1
			select {
			case out <- update:
			case <-ctx.Done():
				return
			}
		}
	}
}

const helpText = "Send me your one-time invite token and I'll send back your vpn.io profile (.vpnio). " +
	"Ask the owner for a token if you don't have one."

// env is everything a message handler needs besides the message itself: the
// stores it reads and writes, and the deployment's configuration. It exists
// because the handlers grew a second service to hand out — passing nine
// positional arguments through three call sites was already at the edge of
// readable, and "which string was serverName again" is exactly the kind of
// mistake that issues someone a profile pointing at the wrong node.
type env struct {
	authority *ca.CA
	invites   *invite.Store
	revoked   *revoke.Store
	// vless is nil on a node that runs no VLESS service. Nil is the normal
	// state, not a degraded one: the second service is optional, and a node
	// without it must still onboard people to the first.
	vless     *vless.Store
	vlessUnit string

	server        string
	serverName    string
	installersDir string
	ownerID       int64
}

// vlessEnabled reports whether this node can hand out VLESS access.
func (e *env) vlessEnabled() bool { return e.vless != nil }

func handleMessage(bot *tgbotapi.BotAPI, e *env, msg *tgbotapi.Message) {
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
		if e.ownerID != 0 && msg.From.ID == e.ownerID && msg.Chat.IsPrivate() {
			handleInvite(bot, e, msg)
		} else {
			reply(bot, msg.Chat.ID, helpText)
		}
		return
	case "revoke", "unrevoke", "revoked":
		// Same gate as /invite: owner only, private chat only.
		if e.ownerID != 0 && msg.From.ID == e.ownerID && msg.Chat.IsPrivate() {
			handleRevokeCommand(bot, e, msg)
		} else {
			reply(bot, msg.Chat.ID, helpText)
		}
		return
	case "invites":
		// Same owner-only, private-chat gate: the list names clients and their
		// redemption status, so it stays out of groups — and never prints a token
		// secret (see formatInviteList).
		if e.ownerID != 0 && msg.From.ID == e.ownerID && msg.Chat.IsPrivate() {
			handleInvitesCommand(bot, e.invites, msg)
		} else {
			reply(bot, msg.Chat.ID, helpText)
		}
		return
	}
	// Everything below treats the text as a candidate invite token, and a
	// successful redemption replies with a .vpnio bundle that carries the
	// client's *private key*. That must never happen outside a private chat:
	// a user who pastes their token into a group would otherwise hand every
	// member a working profile. Staying silent (rather than explaining) also
	// keeps the bot from reacting to ordinary group chatter, and avoids
	// echoing the token's fate back into the group.
	if !redeemableChat(msg.Chat) {
		return
	}

	if len(text) > maxTokenLen {
		reply(bot, msg.Chat.ID, "That doesn't look like an invite token. Send the token the owner gave you.")
		return
	}

	// Any other short text is treated as a candidate invite token.
	who := userLabel(msg.From)
	tok, err := e.invites.Redeem(text, who)
	if err != nil {
		if errors.Is(err, invite.ErrNotFound) {
			reply(bot, msg.Chat.ID, "That invite is invalid or already used. Ask the owner for a new one.")
		} else {
			// A real store failure (disk, permissions) — the user's token may
			// be fine, so don't call it invalid. Log it, tell the owner, apologise.
			log.Printf("redeem token from %s: %v", who, err)
			notifyOwner(bot, e.ownerID, "couldn't redeem an invite token from %s: %v", who, err)
			reply(bot, msg.Chat.ID, ownerNotifiedText(e.ownerID, "Sorry — something went wrong on our side."))
		}
		return
	}

	name := tok.ClientName
	grant := tok.Grants()

	// A token that grants VLESS on a node that has none would spend the token
	// and hand back nothing. Say so plainly and tell the owner: the token is
	// already gone either way, and the person waiting deserves better than
	// silence.
	if grant.VLESS() && !e.vlessEnabled() {
		log.Printf("token for %q grants VLESS but this node runs no VLESS service", name)
		notifyOwner(bot, e.ownerID, "the invite for %q asked for VLESS access, but this node has no VLESS service configured", name)
		if !grant.Profile() {
			reply(bot, msg.Chat.ID, ownerNotifiedText(e.ownerID, "Sorry — that invite can't be completed here."))
			return
		}
	}

	if grant.Profile() {
		if !issueProfile(bot, e, msg, name, who) {
			return
		}
	}
	if grant.VLESS() && e.vlessEnabled() {
		if !issueVLESS(bot, e, msg, name, who) {
			return
		}
	}

	// Offer the app installer for the user's OS, if any are configured. Only
	// for a profile: someone who was handed a link uses a third-party client,
	// and our installer is not what they need.
	if grant.Profile() && e.installersDir != "" {
		if kb, ok := installerKeyboard(e.installersDir); ok {
			m := tgbotapi.NewMessage(msg.Chat.ID, "Now grab the vpn.io app for your system:")
			m.ReplyMarkup = kb
			if _, err := bot.Send(m); err != nil {
				log.Printf("send installer menu to %s: %v", who, err)
			}
		}
	}
}

// issueProfile issues a client certificate bundle and sends it. It reports
// whether the user was served; a false return means the failure has already
// been reported to both the user and the owner.
func issueProfile(bot *tgbotapi.BotAPI, e *env, msg *tgbotapi.Message, name, who string) bool {
	bundle, err := issueBundle(e.authority, name, e.server, e.serverName)
	if err != nil {
		// Don't leak internals to the user; log and tell the operator.
		log.Printf("issue bundle for %q (%s): %v", name, who, err)
		notifyOwner(bot, e.ownerID, "failed to issue a profile for %q (%s): %v", name, who, err)
		reply(bot, msg.Chat.ID, ownerNotifiedText(e.ownerID, "Sorry — couldn't create your profile."))
		return false
	}

	doc := tgbotapi.NewDocument(msg.Chat.ID, tgbotapi.FileBytes{Name: name + ".vpnio", Bytes: bundle})
	doc.Caption = "Your vpn.io profile. In the app choose \"Import a profile file\" and pick this file."
	if _, err := bot.Send(doc); err != nil {
		// The token is already spent and the cert issued, so don't leave the
		// user with silence — tell them; the owner can re-issue if needed.
		log.Printf("send profile to %s: %v", who, err)
		notifyOwner(bot, e.ownerID, "issued %q to %s but couldn't deliver the file: %v", name, who, err)
		reply(bot, msg.Chat.ID, "Your profile was created but I couldn't send the file — please contact the owner.")
		return false
	}
	log.Printf("issued profile %q to %s", name, who)
	return true
}

// issueVLESS adds the person to the node's VLESS client list and sends them
// their link. Like issueProfile it reports whether the user was served.
//
// The link is sent BEFORE the service finishes restarting, and the wait for the
// restart happens after. That order is deliberate: the credential is real the
// moment it is written, the restart only makes the node honour it, and a person
// staring at a chat for thirty seconds while systemd works is worse than one
// whose link needs a second attempt.
func issueVLESS(bot *tgbotapi.BotAPI, e *env, msg *tgbotapi.Message, name, who string) bool {
	client, err := e.vless.Add(name)
	if err != nil {
		log.Printf("add VLESS client %q (%s): %v", name, who, err)
		notifyOwner(bot, e.ownerID, "failed to add VLESS access for %q (%s): %v", name, who, err)
		reply(bot, msg.Chat.ID, ownerNotifiedText(e.ownerID, "Sorry — couldn't create your access."))
		return false
	}
	node, err := e.vless.LoadNode()
	if err != nil {
		log.Printf("load VLESS node for %q: %v", name, err)
		notifyOwner(bot, e.ownerID, "added VLESS access for %q but couldn't build the link: %v", name, err)
		reply(bot, msg.Chat.ID, ownerNotifiedText(e.ownerID, "Sorry — couldn't create your access."))
		return false
	}
	link, err := vless.Link(node, client)
	if err != nil {
		log.Printf("build VLESS link for %q: %v", name, err)
		notifyOwner(bot, e.ownerID, "added VLESS access for %q but couldn't build the link: %v", name, err)
		reply(bot, msg.Chat.ID, ownerNotifiedText(e.ownerID, "Sorry — couldn't create your access."))
		return false
	}

	// The link IS the access, so it goes out exactly like the .vpnio bundle:
	// this chat is already known to be private (see redeemableChat).
	reply(bot, msg.Chat.ID, vlessInstructions)
	reply(bot, msg.Chat.ID, link)
	log.Printf("issued VLESS access %q to %s", name, who)

	// Writing the client list is not the same as the node honouring it: the
	// restart happens out of our hands (see internal/vless.WaitApplied). If it
	// does not come back, the person is holding a link that silently does
	// nothing — and the only one who can fix that is the owner.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := vless.WaitApplied(ctx, e.vlessUnit); err != nil {
		log.Printf("VLESS service did not apply the change for %q: %v", name, err)
		notifyOwner(bot, e.ownerID, "added VLESS access for %q, but the service did not come back: %v", name, err)
		reply(bot, msg.Chat.ID, "Your access is created. If it doesn't connect within a minute, tell the owner — they've been notified.")
	}
	return true
}

// vlessInstructions is what a person needs to know before the link arrives.
const vlessInstructions = "Your VLESS access. Copy the link below, open Happ (or another VLESS client) " +
	"and add it — most clients pick the link up from the clipboard on their \"add server\" screen.\n\n" +
	"Keep it to yourself: this link is the access."

// redeemableChat reports whether a chat may redeem an invite token. Only a
// private (one-to-one) chat qualifies, because redemption hands back the
// client's private key — see the call site.
func redeemableChat(chat *tgbotapi.Chat) bool {
	return chat != nil && chat.IsPrivate()
}

// inviteUsage is shown whenever /invite is called with something unusable.
const inviteUsage = "Usage: /invite <client-name> [profile|vless|both]"

// handleInvite mints a one-time token from an owner's "/invite <name> [grant]"
// and replies with it. The caller has already verified the sender is the owner.
//
// The grant decides what the person gets when they redeem: a profile for our
// app, a VLESS link for a third-party client, or both. It is chosen here, when
// the owner knows who they are inviting and what device that person has —
// nobody wants to answer that question in a chat with the friend later.
func handleInvite(bot *tgbotapi.BotAPI, e *env, msg *tgbotapi.Message) {
	name, grantRaw, _ := strings.Cut(strings.TrimSpace(msg.CommandArguments()), " ")
	if err := validateClientName(strings.TrimSpace(name)); err != nil {
		reply(bot, msg.Chat.ID, "Can't use that name ("+err.Error()+"). "+inviteUsage)
		return
	}
	name = strings.TrimSpace(name)
	grant, err := invite.ParseGrant(grantRaw)
	if err != nil {
		reply(bot, msg.Chat.ID, err.Error()+". "+inviteUsage)
		return
	}
	// Minting a token for something this node cannot deliver only produces a
	// disappointed friend later, when the token is already spent.
	if grant.VLESS() && !e.vlessEnabled() {
		reply(bot, msg.Chat.ID, "This node has no VLESS service configured, so I can't issue that. See docs/VLESS.md.")
		return
	}
	tok, err := e.invites.Generate(name, grant)
	if err != nil {
		log.Printf("/invite generate %q: %v", name, err)
		reply(bot, msg.Chat.ID, "Couldn't generate a token — check the logs.")
		return
	}
	// Audit: a minted token is a credential, like an issued profile.
	log.Printf("minted invite token for %q (%s) via /invite from %s", name, grant, userLabel(msg.From))
	reply(bot, msg.Chat.ID, fmt.Sprintf("Invite token for %q — %s (single-use):\n\n%s\n\nSend it to the person; they message it to me.", name, grantText(grant), tok.Value))
}

// grantText says what a grant means in words the owner reads at a glance.
func grantText(g invite.Grant) string {
	switch g {
	case invite.GrantVLESS:
		return "VLESS link for third-party clients"
	case invite.GrantBoth:
		return "app profile + VLESS link"
	default:
		return "app profile"
	}
}

// handleInvitesCommand answers the owner's /invites with the list of issued
// tokens and their status. The caller has verified owner + private chat.
func handleInvitesCommand(bot *tgbotapi.BotAPI, store *invite.Store, msg *tgbotapi.Message) {
	tokens, err := store.List()
	if err != nil {
		log.Printf("/invites list: %v", err)
		reply(bot, msg.Chat.ID, "Couldn't read the invite list — check the logs.")
		return
	}
	reply(bot, msg.Chat.ID, formatInviteList(tokens, store.TTL, time.Now()))
}

// formatInviteList renders the issued-invite list for /invites and `vpn-bot
// list`: client name, status (PENDING / EXPIRED / used-by-whom) and dates. It
// deliberately OMITS Token.Value — possession of an unused value is a live
// credential, so it must never be echoed into a chat or a terminal scrollback.
func formatInviteList(tokens []invite.Token, ttl time.Duration, now time.Time) string {
	if len(tokens) == 0 {
		return "No invites have been issued yet."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Issued invites (%d):\n", len(tokens))
	for _, t := range tokens {
		switch {
		case t.Used:
			who := t.UsedBy
			if who == "" {
				who = "unknown"
			}
			fmt.Fprintf(&b, "• %s [%s] — used by %s on %s\n", t.ClientName, t.Grants(), who, t.UsedAt.Format("2006-01-02"))
		case invite.Expired(t, ttl, now):
			fmt.Fprintf(&b, "• %s [%s] — EXPIRED (issued %s)\n", t.ClientName, t.Grants(), t.Created.Format("2006-01-02"))
		default:
			fmt.Fprintf(&b, "• %s [%s] — PENDING (issued %s)\n", t.ClientName, t.Grants(), t.Created.Format("2006-01-02"))
		}
	}
	return b.String()
}

// handleRevokeCommand serves the owner's /revoke, /unrevoke and /revoked against
// the same revoked.json the server enforces. The caller has verified the sender
// is the owner and the chat is private.
func handleRevokeCommand(bot *tgbotapi.BotAPI, e *env, msg *tgbotapi.Message) {
	authority, store := e.authority, e.revoked
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
		// Only the current certificate. Certificates superseded by a re-issue
		// were retired on purpose — usually because that profile leaked — and
		// un-revoking by name would hand them their access back.
		serial, err := ca.ClientSerial(authority.Dir, name)
		if err != nil {
			log.Printf("/unrevoke %q: %v", name, err)
			reply(bot, msg.Chat.ID, fmt.Sprintf("No issued client named %q (or its certificate is unreadable).", name))
			return
		}
		removed, err := store.RemoveSerial(serial)
		if err != nil {
			log.Printf("/unrevoke %q: %v", name, err)
			reply(bot, msg.Chat.ID, "Couldn't un-revoke — check the logs.")
			return
		}
		if !removed {
			reply(bot, msg.Chat.ID, fmt.Sprintf("%q's current profile was not revoked.", name))
			return
		}
		log.Printf("un-revoked %q via /unrevoke from %s", name, who)
		reply(bot, msg.Chat.ID, fmt.Sprintf("Un-revoked %q.", name))
		return
	}

	// /revoke: deny every certificate ever issued to this name, not just the
	// current one — a re-issue supersedes the old cert but leaves it valid
	// against the CA, and its serial survives only in the issuance ledger.
	serials, err := ca.ClientSerials(authority.Dir, name)
	if err != nil {
		log.Printf("/revoke %q: %v", name, err)
		reply(bot, msg.Chat.ID, fmt.Sprintf("No issued client named %q (or its certificate is unreadable).", name))
		return
	}
	added := 0
	for _, serial := range serials {
		ok, err := store.Add(serial, name)
		if err != nil {
			log.Printf("/revoke add %q: %v", name, err)
			reply(bot, msg.Chat.ID, "Couldn't revoke — check the logs.")
			return
		}
		if ok {
			added++
		}
	}
	if added == 0 {
		reply(bot, msg.Chat.ID, fmt.Sprintf("%q was already revoked.", name))
		return
	}
	log.Printf("revoked %q via /revoke from %s (%d certificate(s), %d newly)", name, who, len(serials), added)
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

// notifyOwner forwards an operator-facing failure to the owner's chat when an
// owner is configured, so a user-facing "the owner has been notified" is a
// promise the bot actually keeps rather than only a log line. With no -owner set
// there is nobody to tell — ownerNotifiedText adjusts the wording for that case.
func notifyOwner(bot *tgbotapi.BotAPI, ownerID int64, format string, args ...any) {
	if ownerID == 0 {
		return
	}
	if _, err := bot.Send(tgbotapi.NewMessage(ownerID, "⚠️ vpn-bot: "+fmt.Sprintf(format, args...))); err != nil {
		log.Printf("notify owner: %v", err)
	}
}

// ownerNotifiedText finishes a user-facing apology, claiming the owner was
// notified only when an owner is actually configured to receive it; otherwise it
// points the user at the owner without asserting a notification that never went
// out.
func ownerNotifiedText(ownerID int64, prefix string) string {
	if ownerID != 0 {
		return prefix + " The owner has been notified."
	}
	return prefix + " Please try again later or contact the owner."
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
