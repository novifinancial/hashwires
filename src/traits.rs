// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use digest::{BlockInput, FixedOutput, Reset, Update};

/// A convenience trait for digest bounds used throughout the library
pub trait Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone {}

impl<T: Update + BlockInput + FixedOutput + Reset + Default + Clone> Hash for T {}
