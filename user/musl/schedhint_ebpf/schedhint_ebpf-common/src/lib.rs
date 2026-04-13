#![no_std]

pub const CLASS_OTHER: u32 = 0;
pub const CLASS_IO_WAIT: u32 = 1;
pub const CLASS_SLEEP_WAIT: u32 = 2;
pub const CLASS_SYNC_WAIT: u32 = 3;

pub fn class_name(class: u32) -> &'static str {
	match class {
		CLASS_IO_WAIT => "io_wait",
		CLASS_SLEEP_WAIT => "sleep_wait",
		CLASS_SYNC_WAIT => "sync_wait",
		_ => "other",
	}
}
