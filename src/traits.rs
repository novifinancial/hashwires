use digest::{BlockInput, FixedOutput, Reset, Update};

/// A convenience trait for digest bounds used throughout the library
pub trait Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone {}

impl<T: Update + BlockInput + FixedOutput + Reset + Default + Clone> Hash for T {}
