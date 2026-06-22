package model

import "errors"

// ErrLastHolder is returned when deleting a tuple would drop the number of
// direct holders of a required relation to or below its declared floor,
// stranding the object with too few holders of a critical relation.
var ErrLastHolder = errors.New("cannot delete the last holder of a required relation")
