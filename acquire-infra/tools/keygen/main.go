// keygen — Acquire LLC wallet provisioning CLI.
//
// Quick start (SoftHSM2 dev):
//
//	softhsm2-util --init-token --slot 0 --label "acquire-dev" --pin 1234 --so-pin 1234
//	export HSM_PIN=1234
//	keygen init --name default --gen-kek --chains eth,gnosis
//
// Production (Luna HSM):
//
//	export HSM_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so
//	export HSM_PIN=<luna-pin>
//	keygen init --name default --gen-kek --chains eth,gnosis
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	bip39 "github.com/tyler-smith/go-bip39"

	"acquire.io/infra/config"
	"acquire.io/infra/signer"
)

const usage = `keygen — Acquire LLC wallet provisioning CLI

Commands:
  init       Generate new wallet: BIP39 entropy -> BIP32 keys -> HSM wrap
  open       Show all accounts in a wallet (no HSM needed)
  list       List all wallets in the keys directory (no HSM needed)
  unlock     Verify wallet keys via HSM round-trip; optionally print private keys
  create     Add a new account to an existing wallet
  partition  Derive accounts at a range of BIP44 account indices

Common flags:
  --keys-dir   Directory for wallet JSON files  (default: /keys/wallets)
  --hsm-slot   PKCS#11 slot ID                 (default: 0)
  --hsm-pin    HSM user PIN                    (env: HSM_PIN)
  --kek        KEK label in HSM                (default: acquire-kek-v1)

Environment:
  HSM_PIN   HSM user PIN
  HSM_LIB   PKCS#11 library path (default: /usr/lib/softhsm/libsofthsm2.so)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "init":
		runInit(args)
	case "open":
		runOpen(args)
	case "list":
		runList(args)
	case "unlock":
		runUnlock(args)
	case "create":
		runCreate(args)
	case "partition":
		runPartition(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(1)
	}
}

// ── init ─────────────────────────────────────────────────────────────────────

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	keysDir    := fs.String("keys-dir",    "/keys/wallets",       "wallet storage directory")
	hsmSlot    := fs.Uint("hsm-slot",     0,                     "PKCS#11 slot ID")
	hsmPin     := fs.String("hsm-pin",    os.Getenv("HSM_PIN"), "HSM user PIN")
	kek        := fs.String("kek",        "acquire-kek-v1",      "KEK label")
	name       := fs.String("name",       "default",             "wallet name")
	mnemonic   := fs.String("mnemonic",   "",                    "import existing BIP39 mnemonic")
	passphrase := fs.String("passphrase", "",                    "BIP39 passphrase")
	chains     := fs.String("chains",     "eth,gnosis",          "chains to derive (comma-separated)")
	genKEK     := fs.Bool("gen-kek",     false,                 "generate new KEK in HSM before provisioning")
	fs.Parse(args)

	requirePin(*hsmPin)

	if err := os.MkdirAll(*keysDir, 0700); err != nil {
		fatalf("create keys dir: %v", err)
	}

	// Mnemonic: import or generate
	mnem := *mnemonic
	if mnem != "" {
		if !bip39.IsMnemonicValid(mnem) {
			fatalf("provided mnemonic is not valid BIP39")
		}
		fmt.Println("Using provided mnemonic.")
	} else {
		entropy, err := bip39.NewEntropy(256) // 24 words
		if err != nil {
			fatalf("generate entropy: %v", err)
		}
		mnem, err = bip39.NewMnemonic(entropy)
		if err != nil {
			fatalf("generate mnemonic: %v", err)
		}
		fmt.Println("=== GENERATED MNEMONIC — WRITE THIS DOWN AND STORE OFFLINE ===")
		fmt.Println(mnem)
		fmt.Println("================================================================")
		fmt.Println()
	}

	seed := bip39.NewSeed(mnem, *passphrase)
	defer config.Wipe(seed)

	// HSM
	h, err := signer.NewPKCS11HSM(uint(*hsmSlot), *hsmPin)
	if err != nil {
		fatalf("hsm connect: %v", err)
	}
	defer h.Close()

	if *genKEK {
		if err := h.GenerateKEK(*kek); err != nil {
			fatalf("generate KEK: %v", err)
		}
		fmt.Printf("KEK %q generated in HSM slot %d\n\n", *kek, *hsmSlot)
	}

	// Random DEK — wrapped under KEK, never stored in plaintext
	dek, err := generateDEK()
	if err != nil {
		fatalf("generate DEK: %v", err)
	}
	defer config.Wipe(dek)

	wrappedDEK, err := h.WrapDEK(*kek, dek)
	if err != nil {
		fatalf("wrap DEK: %v", err)
	}

	// Derive and wrap per-chain keys at account index 0
	defaultChains := config.DefaultChains()
	fmt.Println("Deriving accounts:")
	var accounts []Account
	for _, chainName := range splitTrim(*chains) {
		chainCfg, ok := defaultChains[chainName]
		if !ok {
			fatalf("unknown chain %q (known: eth, gnosis, zec)", chainName)
		}
		acct, err := deriveAndWrapAccount(seed, dek, chainName, chainCfg.DerivPath, 0)
		if err != nil {
			fatalf("derive [%s]: %v", chainName, err)
		}
		fmt.Printf("  %-8s  %s  (%s)\n", chainName, acct.Address, acct.DerivPath)
		accounts = append(accounts, *acct)
	}

	w := &Wallet{
		ID:         walletID(),
		Name:       *name,
		CreatedAt:  time.Now().UTC(),
		KEKLabel:   *kek,
		WrappedDEK: wrappedDEK,
		Accounts:   accounts,
	}

	if err := saveWallet(*keysDir, *name, w); err != nil {
		fatalf("save wallet: %v", err)
	}
	fmt.Printf("\nWallet %q saved -> %s/%s.json\n", *name, *keysDir, *name)
}

// ── open ─────────────────────────────────────────────────────────────────────

func runOpen(args []string) {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	keysDir := fs.String("keys-dir", "/keys/wallets", "wallet storage directory")
	name    := fs.String("wallet",   "default",       "wallet name")
	fs.Parse(args)

	w, err := loadWallet(*keysDir, *name)
	if err != nil {
		fatalf("load wallet %q: %v", *name, err)
	}

	fmt.Printf("Wallet  : %s\n", w.Name)
	fmt.Printf("ID      : %s\n", w.ID)
	fmt.Printf("Created : %s\n", w.CreatedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Printf("KEK     : %s\n", w.KEKLabel)
	fmt.Printf("Accounts: %d\n\n", len(w.Accounts))

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IDX\tCHAIN\tADDRESS\tPATH")
	for _, a := range w.Accounts {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", a.Index, a.Chain, a.Address, a.DerivPath)
	}
	tw.Flush()
}

// ── list ─────────────────────────────────────────────────────────────────────

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	keysDir := fs.String("keys-dir", "/keys/wallets", "wallet storage directory")
	fs.Parse(args)

	names, err := listWalletNames(*keysDir)
	if err != nil {
		fatalf("list wallets in %s: %v", *keysDir, err)
	}
	if len(names) == 0 {
		fmt.Printf("No wallets found in %s\n", *keysDir)
		return
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCREATED\tACCOUNTS\tKEK")
	for _, n := range names {
		w, err := loadWallet(*keysDir, n)
		if err != nil {
			fmt.Fprintf(tw, "%s\t(parse error: %v)\n", n, err)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n",
			w.Name, w.CreatedAt.Format("2006-01-02"), len(w.Accounts), w.KEKLabel)
	}
	tw.Flush()
}

// ── unlock ────────────────────────────────────────────────────────────────────

func runUnlock(args []string) {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	keysDir  := fs.String("keys-dir",  "/keys/wallets",      "wallet storage directory")
	hsmSlot  := fs.Uint("hsm-slot",   0,                    "PKCS#11 slot ID")
	hsmPin   := fs.String("hsm-pin",  os.Getenv("HSM_PIN"), "HSM user PIN")
	name     := fs.String("wallet",   "default",            "wallet name")
	showKeys := fs.Bool("show-keys", false,                 "print private keys (dev only — never use in prod)")
	fs.Parse(args)

	requirePin(*hsmPin)

	w, err := loadWallet(*keysDir, *name)
	if err != nil {
		fatalf("load wallet %q: %v", *name, err)
	}

	h, err := signer.NewPKCS11HSM(uint(*hsmSlot), *hsmPin)
	if err != nil {
		fatalf("hsm connect: %v", err)
	}
	defer h.Close()

	dek, err := h.UnwrapDEK(w.KEKLabel, w.WrappedDEK)
	if err != nil {
		fatalf("unwrap DEK (wrong PIN or KEK not found): %v", err)
	}
	defer config.Wipe(dek)

	if *showKeys {
		fmt.Println("WARNING: PRIVATE KEYS BELOW — DEV USE ONLY — DO NOT LOG OR SHARE")
		fmt.Println()
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	allOK := true
	if *showKeys {
		fmt.Fprintln(tw, "IDX\tCHAIN\tADDRESS\tPRIVATE KEY (hex)")
	} else {
		fmt.Fprintln(tw, "IDX\tCHAIN\tADDRESS\tSTATUS")
	}
	for _, acct := range w.Accounts {
		privKey, err := config.UnwrapKey(dek, acct.WrappedKey)
		if err != nil {
			fmt.Fprintf(tw, "%d\t%s\t%s\tFAIL: %v\n", acct.Index, acct.Chain, acct.Address, err)
			allOK = false
			continue
		}
		if *showKeys {
			fmt.Fprintf(tw, "%d\t%s\t%s\t0x%x\n", acct.Index, acct.Chain, acct.Address, privKey)
		} else {
			fmt.Fprintf(tw, "%d\t%s\t%s\tok\n", acct.Index, acct.Chain, acct.Address)
		}
		config.Wipe(privKey)
	}
	tw.Flush()

	if allOK && !*showKeys {
		fmt.Printf("\nAll %d keys verified via HSM round-trip.\n", len(w.Accounts))
	}
}

// ── create ────────────────────────────────────────────────────────────────────

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	keysDir    := fs.String("keys-dir",    "/keys/wallets",      "wallet storage directory")
	hsmSlot    := fs.Uint("hsm-slot",     0,                    "PKCS#11 slot ID")
	hsmPin     := fs.String("hsm-pin",    os.Getenv("HSM_PIN"), "HSM user PIN")
	kek        := fs.String("kek",        "acquire-kek-v1",     "KEK label")
	name       := fs.String("wallet",     "default",            "wallet name")
	chain      := fs.String("chain",      "eth",                "chain for new account")
	mnemonic   := fs.String("mnemonic",   "",                   "BIP39 mnemonic (or use --mnemonic-stdin)")
	mnemonicIn := fs.Bool("mnemonic-stdin", false,              "read mnemonic from stdin")
	passphrase := fs.String("passphrase", "",                   "BIP39 passphrase")
	fs.Parse(args)

	requirePin(*hsmPin)
	_ = kek // used implicitly via wallet.KEKLabel

	mnem := resolveMnemonic(*mnemonic, *mnemonicIn)

	w, err := loadWallet(*keysDir, *name)
	if err != nil {
		fatalf("load wallet %q: %v", *name, err)
	}

	// Next unused account index for this chain
	var nextIdx uint32
	for _, a := range w.Accounts {
		if a.Chain == *chain && a.Index >= nextIdx {
			nextIdx = a.Index + 1
		}
	}

	seed := bip39.NewSeed(mnem, *passphrase)
	defer config.Wipe(seed)

	h, err := signer.NewPKCS11HSM(uint(*hsmSlot), *hsmPin)
	if err != nil {
		fatalf("hsm connect: %v", err)
	}
	defer h.Close()

	dek, err := h.UnwrapDEK(w.KEKLabel, w.WrappedDEK)
	if err != nil {
		fatalf("unwrap DEK: %v", err)
	}
	defer config.Wipe(dek)

	chainCfg, ok := config.DefaultChains()[*chain]
	if !ok {
		fatalf("unknown chain %q", *chain)
	}

	path := bip44Path(chainCfg.CoinType, nextIdx)
	acct, err := deriveAndWrapAccount(seed, dek, *chain, path, nextIdx)
	if err != nil {
		fatalf("derive account: %v", err)
	}

	w.Accounts = append(w.Accounts, *acct)
	if err := saveWallet(*keysDir, *name, w); err != nil {
		fatalf("save wallet: %v", err)
	}
	fmt.Printf("Account added  index=%-3d  chain=%-8s  address=%s  path=%s\n",
		nextIdx, *chain, acct.Address, path)
}

// ── partition ─────────────────────────────────────────────────────────────────

func runPartition(args []string) {
	fs := flag.NewFlagSet("partition", flag.ExitOnError)
	keysDir    := fs.String("keys-dir",    "/keys/wallets",      "wallet storage directory")
	hsmSlot    := fs.Uint("hsm-slot",     0,                    "PKCS#11 slot ID")
	hsmPin     := fs.String("hsm-pin",    os.Getenv("HSM_PIN"), "HSM user PIN")
	name       := fs.String("wallet",     "default",            "wallet name")
	chain      := fs.String("chain",      "eth",                "chain to partition")
	mnemonic   := fs.String("mnemonic",   "",                   "BIP39 mnemonic")
	mnemonicIn := fs.Bool("mnemonic-stdin", false,              "read mnemonic from stdin")
	passphrase := fs.String("passphrase", "",                   "BIP39 passphrase")
	start      := fs.Uint("start",       0,                    "first BIP44 account index")
	end        := fs.Uint("end",         9,                    "last BIP44 account index (inclusive)")
	fs.Parse(args)

	requirePin(*hsmPin)
	if *end < *start {
		fatalf("--end must be >= --start")
	}

	mnem := resolveMnemonic(*mnemonic, *mnemonicIn)

	w, err := loadWallet(*keysDir, *name)
	if err != nil {
		fatalf("load wallet %q: %v", *name, err)
	}

	seed := bip39.NewSeed(mnem, *passphrase)
	defer config.Wipe(seed)

	h, err := signer.NewPKCS11HSM(uint(*hsmSlot), *hsmPin)
	if err != nil {
		fatalf("hsm connect: %v", err)
	}
	defer h.Close()

	dek, err := h.UnwrapDEK(w.KEKLabel, w.WrappedDEK)
	if err != nil {
		fatalf("unwrap DEK: %v", err)
	}
	defer config.Wipe(dek)

	chainCfg, ok := config.DefaultChains()[*chain]
	if !ok {
		fatalf("unknown chain %q", *chain)
	}

	// Index existing accounts to skip duplicates
	existing := map[uint32]bool{}
	for _, a := range w.Accounts {
		if a.Chain == *chain {
			existing[a.Index] = true
		}
	}

	fmt.Printf("Partitioning %s accounts [%d..%d] in wallet %q\n\n", *chain, *start, *end, *name)
	added := 0
	for idx := uint32(*start); idx <= uint32(*end); idx++ {
		if existing[idx] {
			fmt.Printf("  [%d] already exists — skipping\n", idx)
			continue
		}
		path := bip44Path(chainCfg.CoinType, idx)
		acct, err := deriveAndWrapAccount(seed, dek, *chain, path, idx)
		if err != nil {
			fatalf("derive index %d: %v", idx, err)
		}
		w.Accounts = append(w.Accounts, *acct)
		fmt.Printf("  [%d] %s  %s\n", idx, acct.Address, path)
		added++
	}

	if err := saveWallet(*keysDir, *name, w); err != nil {
		fatalf("save wallet: %v", err)
	}
	fmt.Printf("\n%d accounts added. Wallet now has %d total.\n", added, len(w.Accounts))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func requirePin(pin string) {
	if pin == "" {
		fatalf("HSM_PIN or --hsm-pin is required")
	}
}

// resolveMnemonic returns the mnemonic from flag, stdin prompt, or fatal.
func resolveMnemonic(flag string, fromStdin bool) string {
	if flag != "" {
		if !bip39.IsMnemonicValid(flag) {
			fatalf("invalid BIP39 mnemonic")
		}
		return flag
	}
	if fromStdin {
		fmt.Fprint(os.Stderr, "Enter mnemonic: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		mnem := strings.TrimSpace(scanner.Text())
		if !bip39.IsMnemonicValid(mnem) {
			fatalf("invalid BIP39 mnemonic")
		}
		return mnem
	}
	fatalf("--mnemonic or --mnemonic-stdin is required")
	return ""
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
