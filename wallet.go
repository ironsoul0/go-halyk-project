package main

import "time"

type Transfer struct {
	ToWalletID int64     `json:"to_wallet_id"`
	Amount     int64     `json:"amount"`
	CreatedAt  time.Time `json:"created_at"`
}

type Wallet struct {
	ID        int64       `json:"id"`
	Owner     int64       `json:"owner"`
	Code      string      `json:"code"`
	CreatedAt time.Time   `json:"created_at"`
	Balance   int64       `json:"balance"`
	Transfers []*Transfer `json:"transfers"`
}
