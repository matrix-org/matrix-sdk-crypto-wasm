use std::error::Error;

use vergen_gitcl::{Emitter, Gitcl};

fn main() -> Result<(), Box<dyn Error>> {
    let gitcl = Gitcl::builder().sha(true).describe(true, false, None).build();
    Emitter::default().add_instructions(&gitcl)?.emit()?;

    Ok(())
}
