//! The crate reads its shared data from mirrors under `testdata/` so it stays
//! self-contained when it travels without the rest of the repository. These
//! tests prove the mirrors are byte-identical to the repository's sources of
//! truth, in both directions, so neither a new source file nor a stale
//! mirror slips through. Without the repository around the crate there is
//! nothing to compare, and the mirror is authoritative.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn assert_mirror(source: &Path, mirror: &Path) {
    if !source.is_dir() {
        eprintln!("{} absent: the mirror is authoritative", source.display());
        return;
    }
    let sources = json_files(source);
    let mirrored = json_files(mirror);
    let mut wrong = Vec::new();
    for name in sources.difference(&mirrored) {
        wrong.push(format!(
            "{name} is in {} but not mirrored in {}",
            source.display(),
            mirror.display()
        ));
    }
    for name in mirrored.difference(&sources) {
        wrong.push(format!(
            "{name} is mirrored in {} but gone from {}",
            mirror.display(),
            source.display()
        ));
    }
    for name in sources.intersection(&mirrored) {
        if std::fs::read(source.join(name)).unwrap() != std::fs::read(mirror.join(name)).unwrap() {
            wrong.push(format!(
                "{} drifted from {}: copy it again",
                mirror.join(name).display(),
                source.join(name).display()
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

fn json_files(directory: &Path) -> BTreeSet<String> {
    let names: BTreeSet<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| {
            Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    assert!(!names.is_empty(), "no JSON under {}", directory.display());
    names
}

#[test]
fn the_conformance_mirror_matches_the_corpus() {
    assert_mirror(
        &crate_dir().join("../conformance"),
        &crate_dir().join("testdata/conformance"),
    );
}

#[test]
fn the_iana_mirror_matches_the_snapshots() {
    assert_mirror(
        &crate_dir().join("../script/iana"),
        &crate_dir().join("testdata/iana"),
    );
}
