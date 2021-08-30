// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by "stringer -type=dropReason -trimprefix=dropReason"; DO NOT EDIT.

package derp

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[dropReasonUnknownDest-0]
	_ = x[dropReasonUnknownDestOnFwd-1]
	_ = x[dropReasonGone-2]
	_ = x[dropReasonQueueHead-3]
	_ = x[dropReasonQueueTail-4]
	_ = x[dropReasonWriteError-5]
	_ = x[dropReasonDupClient-6]
}

const _dropReason_name = "UnknownDestUnknownDestOnFwdGoneQueueHeadQueueTailWriteErrorDupClient"

var _dropReason_index = [...]uint8{0, 11, 27, 31, 40, 49, 59, 68}

func (i dropReason) String() string {
	if i < 0 || i >= dropReason(len(_dropReason_index)-1) {
		return "dropReason(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _dropReason_name[_dropReason_index[i]:_dropReason_index[i+1]]
}
