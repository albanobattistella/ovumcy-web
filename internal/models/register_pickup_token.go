package models

import "time"

// RegisterPickupToken is the server-side single-use record for a sealed
// `ovumcy_register_pickup` cookie. The nonce inside the cookie is opaque to
// the client; the server resolves it to a user_id atomically on consume so a
// captured cookie cannot be replayed to mint a second auth session.
type RegisterPickupToken struct {
	Nonce      string     `gorm:"column:nonce;primaryKey"`
	UserID     uint       `gorm:"column:user_id;not null"`
	ExpiresAt  time.Time  `gorm:"column:expires_at;not null"`
	ConsumedAt *time.Time `gorm:"column:consumed_at"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
}

func (RegisterPickupToken) TableName() string {
	return "register_pickup_tokens"
}
