/*
 * SPDX-FileCopyrightText: 2025 yonasBSD
 *
 * SPDX-License-Identifier: MIT
 */

use vergen::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::all_build()?;
    let cargo = CargoBuilder::all_cargo()?;
    let rustc = RustcBuilder::all_rustc()?;

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&rustc)?
        .emit()?;

    build_data::set_GIT_BRANCH().unwrap();
    build_data::set_GIT_COMMIT().unwrap();
    build_data::set_GIT_DIRTY().unwrap();
    build_data::set_SOURCE_TIMESTAMP().unwrap();
    build_data::no_debug_rebuilds().unwrap();

    Ok(())
}
