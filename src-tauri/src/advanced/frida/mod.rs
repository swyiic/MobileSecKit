mod android_dump;
mod ios_dump;
mod runtime;
mod server;

pub(super) use android_dump::{
    run_dex_dump as run_dex_dump_internal, run_so_dump as run_so_dump_internal,
};
pub(super) use ios_dump::run_ios_dump as run_ios_dump_internal;
#[cfg(test)]
pub(super) use runtime::{
    adapt_frida_17_script, apply_ios_compatibility_profile, frida_script_args,
    normalize_ios_compatibility_profile, read_script_path, IOS_DUMP_AGENT, IOS_DUMP_RUNNER,
};
pub(super) use runtime::{
    list_frida_processes as list_processes, list_frida_scripts as list_scripts,
    run_frida_script as run_script,
};
pub(super) use server::{
    download_frida_server as download_server, install_frida_tools as install_host_tools,
    manage_frida_server as manage_server,
};
