package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"acquire.io/infra/audit"
	"acquire.io/infra/config"
	"acquire.io/infra/signer"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	al, err := audit.New(cfg.AuditLogPath)
	if err != nil {
		log.Fatalf("audit logger: %v", err)
	}
	defer al.Close()

	hsm, err := signer.NewLunaHSM(cfg.HSMSlot, cfg.HSMPin)
	if err != nil {
		log.Fatalf("hsm init: %v", err)
	}
	defer hsm.Close()

	keys, err := config.LoadKeyHierarchy("/keys/key_hierarchy.json")
	if err != nil {
		log.Fatalf("key hierarchy: %v", err)
	}

	s := signer.New(hsm, keys, cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/sign/eth", makeSignHandler(s, al))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("signer listening on %s (TLS)", cfg.ListenAddr)
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("signer server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down signer")
}

type signRequest struct {
	Chain string `json:"chain"` // "eth", "gnosis", "zec"
	RLP   string `json:"rlp"`   // hex-encoded unsigned tx (EIP-2718 binary)
}

type signResponse struct {
	SignedRLP string `json:"signed_rlp"`
	TxHash    string `json:"tx_hash"`
}

func makeSignHandler(s *signer.Signer, al *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		rawRLP, err := hexutil.Decode(req.RLP)
		if err != nil {
			http.Error(w, "invalid hex rlp", http.StatusBadRequest)
			return
		}

		var tx types.Transaction
		if err := tx.UnmarshalBinary(rawRLP); err != nil {
			http.Error(w, "invalid tx encoding", http.StatusBadRequest)
			return
		}

		signed, err := s.SignEthTx(&tx, req.Chain)
		if err != nil {
			al.Log(audit.Entry{Event: "sign_failed", Chain: req.Chain, Error: err.Error()})
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}

		signedBytes, err := signed.MarshalBinary()
		if err != nil {
			http.Error(w, "marshal failed", http.StatusInternalServerError)
			return
		}

		al.Log(audit.Entry{
			Event:  "tx_signed",
			Chain:  req.Chain,
			TxHash: signed.Hash().Hex(),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signResponse{
			SignedRLP: hexutil.Encode(signedBytes),
			TxHash:    signed.Hash().Hex(),
		})
	}
}
