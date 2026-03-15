use crate::find_utils::{filter_excludes, FindLineADB, FindLineMinimal, FindLineTrait};
use crate::utils::{FileKind, HashAlg};
use anyhow::bail;
use anyhow::Error as AnyHowError;
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub async fn adb_quick_scanner(
    base_path: &Path,
    excludes: Option<HashSet<PathBuf>>,
    tx: mpsc::Sender<FindLineMinimal>,
) -> Result<(), AnyHowError> {
    match excludes {
        Some(excludes) => {
            adb_scanner_advanced::<FindLineMinimal>(base_path, None, excludes, &tx).await
        }
        None => adb_scanner_core::<FindLineMinimal>(base_path, None, None, &tx).await,
    }
}

pub async fn adb_full_scanner(
    base_path: &Path,
    excludes: Option<HashSet<PathBuf>>,
    hash_alg: Option<HashAlg>,
    tx: mpsc::Sender<FindLineADB>,
) -> Result<(), AnyHowError> {
    match excludes {
        Some(excludes) => {
            adb_scanner_advanced::<FindLineADB>(base_path, hash_alg, excludes, &tx).await
        }
        None => adb_scanner_core::<FindLineADB>(base_path, None, None, &tx).await,
    }
}

pub async fn adb_scanner_core<FindLineT: FindLineTrait + 'static>(
    base_path: &Path,
    hash_alg: Option<HashAlg>,
    max_depth: Option<i32>,
    tx: &mpsc::Sender<FindLineT>,
) -> Result<(), AnyHowError> {
    let find_printf = FindLineT::find_printf(hash_alg.is_some());
    let max_depth_str: String;

    let mut cmd_parts = Vec::from(["shell", "find", "-H", base_path.to_str().unwrap()]);

    if let Some(max_depth) = max_depth {
        cmd_parts.push("-maxdepth");
        max_depth_str = format!("{}", max_depth);
        cmd_parts.push(&max_depth_str);
    }

    cmd_parts.push("-printf");
    cmd_parts.push(&find_printf);

    if let Some(hash_alg) = hash_alg {
        cmd_parts.push("-exec");
        cmd_parts.push(hash_alg.shell_command());
        cmd_parts.push("{}");
        cmd_parts.push("\\;");
    }
    debug!("cmd_parts = {:?}", cmd_parts);

    let mut child = Command::new("adb")
        .args(cmd_parts)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stderr = child.stderr.take().expect("Failed to open stderr");
    tokio::spawn(async move {
        let stderr_reader = BufReader::new(stderr);
        let mut stderr_lines = stderr_reader.lines();
        loop {
            match stderr_lines.next_line().await {
                Ok(Some(line)) => error!("{}", line),
                Ok(None) => break,
                Err(err) => error!("{}", err),
            };
        }
    });

    let hash_alg_prefix = match hash_alg {
        Some(hash_alg) => hash_alg.prefix(),
        None => "",
    };
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let adb_line = FindLineT::parse(&line, hash_alg_prefix);
        if let Ok(adb_line) = adb_line {
            tx.send(adb_line).await?;
        } else {
            error!(
                "adb_line error: {:?} (line = {:?})",
                adb_line.unwrap_err(),
                line
            )
        }
    }
    Ok(())
}

pub async fn adb_scanner_advanced<'a, FindLineT: FindLineTrait + 'a + 'static>(
    base_path: &'a Path,
    hash_alg: Option<HashAlg>,
    excludes: HashSet<PathBuf>,
    tx: &mpsc::Sender<FindLineT>,
) -> Result<(), AnyHowError> {
    let excludes = filter_excludes(base_path, &excludes);
    for exclude_path in &excludes {
        if exclude_path == base_path {
            return Ok(());
        }
    }
    // println!("adb_scanner2: base_path={:?} excludes={:?}", base_path, excludes);
    if excludes.len() == 0 {
        // println!("calling adb_scanner({:?}, None)", base_path);
        return adb_scanner_core(base_path, hash_alg, None, tx).await;
    }
    let (tx_local, mut rx_local) = mpsc::channel::<FindLineT>(32);
    let base_path2 = base_path.to_path_buf();
    let handle = tokio::spawn(async move {
        // println!("calling adb_scanner({:?}, 1)", base_path2);
        adb_scanner_core::<FindLineT>(&base_path2, hash_alg, Some(1), &tx_local).await
    });
    while let Some(find_line) = rx_local.recv().await {
        tx.send(find_line.clone()).await?;
        let new_base_path = find_line.get_full_path();
        if find_line.get_kind() == FileKind::DIRECTORY && new_base_path != base_path {
            let mut flag = true;
            for exclude_path in &excludes {
                if new_base_path.starts_with(exclude_path) || new_base_path == exclude_path {
                    flag = false;
                    break;
                }
            }
            if flag {
                let new_excludes = filter_excludes(new_base_path, &excludes);
                // println!("calling adb_scanner2({:?}, {:?})", new_base_path, new_excludes);
                Box::pin(adb_scanner_advanced(
                    new_base_path,
                    hash_alg,
                    new_excludes,
                    tx,
                ))
                .await?;
            }
        }
    }
    handle.await?;
    Ok(())
}

pub async fn adb_copy_file(source_path: &Path, target_path: &Path) -> Result<(), AnyHowError> {
    match fs::remove_file(target_path) {
        Ok(()) => {}
        Err(e) => {
            if e.kind() != ErrorKind::NotFound {
                error!("Failed to remove file: {:?}: {:?}", target_path, e);
                return Err(e.into());
            }
        }
    };

    let cmd_parts = Vec::from([
        "pull",
        source_path.to_str().unwrap(),
        target_path.to_str().unwrap(),
    ]);

    debug!("cmd_parts = {:?}", cmd_parts);

    let output = Command::new("adb")
        .args(cmd_parts)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        error!(
            "failed to adb pull: {:?}",
            String::from_utf8_lossy(&output.stderr).to_string()
        );
        bail!("failed to adb pull");
    }

    Ok(())
}
