// Package challenge holds challenge-domain constants. HTTP handlers live in
// httpapi/, verification orchestration lives in linkverify/.
package challenge

import "time"

const DefaultTTL = 5 * time.Minute
