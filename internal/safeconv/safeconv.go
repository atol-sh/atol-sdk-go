package safeconv

import (
	"fmt"
	"math"
)

// SafeInt32 converts an int to int32, returning an error if the value
// would overflow.
func SafeInt32(v int) (int32, error) {
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0, fmt.Errorf("integer overflow: %d exceeds int32 range [%d, %d]", v, math.MinInt32, math.MaxInt32)
	}
	return int32(v), nil
}

// SafeInt32From64 converts an int64 to int32 with overflow check.
func SafeInt32From64(v int64) (int32, error) {
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0, fmt.Errorf("integer overflow: %d exceeds int32 range [%d, %d]", v, math.MinInt32, math.MaxInt32)
	}
	return int32(v), nil
}
