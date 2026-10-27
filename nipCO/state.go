package nipCO

// OrderFacts are what a Hub knows of an order when it states it. Seen is any
// payment seen: a settled invoice, or an output in the mempool or on chain.
// Unminted and Minted count the payments seen and not yet minted, and minted.
type OrderFacts struct {
	Payment  string
	PayBy    int64
	Seen     bool
	Unminted int
	Minted   int
}

// OrderStateAt is the order's state at now (NIP-CO §Order State). Until pay_by:
// paid while a payment waits to be minted, minted once one is and none waits,
// else open. After pay_by: an on-chain order with a payment seen is closed, one
// without is expired; a Lightning order is paid while its payment waits (the Hub
// retries until it is minted), minted once it is, else expired.
func OrderStateAt(f OrderFacts, now int64) OrderState {
	if now <= f.PayBy {
		switch {
		case f.Unminted > 0:
			return OrderPaid
		case f.Minted > 0:
			return OrderMinted
		}
		return OrderOpen
	}
	if f.Payment == PaymentOnchain {
		if f.Seen || f.Unminted > 0 || f.Minted > 0 {
			return OrderClosed
		}
		return OrderExpired
	}
	switch {
	case f.Unminted > 0:
		return OrderPaid
	case f.Minted > 0:
		return OrderMinted
	}
	return OrderExpired
}
