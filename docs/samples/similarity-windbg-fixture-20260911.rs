#![no_std]
#![no_main]
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
#[link(name="kernel32")]
unsafe extern "system" { fn ExitProcess(code: u32) -> !; }
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_step(value: u32) -> u32 {
    if value > 10 { value.wrapping_add(11) } else { value.wrapping_mul(3) }
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_finish(value: u32) -> u32 { value ^ 0x55 }
#[unsafe(no_mangle)]
pub extern "system" fn handoff_entry() -> ! {
    let value = probe_finish(probe_step(20));
    unsafe { ExitProcess(value & 0xff) }
}
