/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * go_types.h — Go runtime type representations for BPF.
 * Adapted from Pixie's go_types.h (Apache-2.0)
 */

#pragma once

/* Go string representation: {ptr, len}. */
struct gostring {
  const char *ptr;
  s64 len;
};

/* Go interface representation: {type_ptr, data_ptr}. */
struct go_interface {
  s64 type;
  void *ptr;
};
