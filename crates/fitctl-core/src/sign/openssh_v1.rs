// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::artifacts::envelope_v1::SignatureEnvelopeV1;
use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::artifacts::validation_v1::{
    validate_config_bundle, validate_decision_bundle, validate_host_contract, validate_host_state,
    validate_host_survey, validate_service_profile, validate_validation_report,
};
use crate::sign::{SignError, SignErrorCode};

pub const SIGNATURE_FORMAT_V1: &str = "openssh_sshsig_v1";
pub const SIGNATURE_NAMESPACE_V1: &str = "fitctl-artifact-v1";
pub const PAYLOAD_ENCODING_V1: &str = "fitctl.semantic_cbor.v1";

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureRequestV1 {
    pub artifact: ArtifactRecordV1,
    pub private_key_path: PathBuf,
    pub signed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignatureRequestV1 {
    pub payload_bytes: Vec<u8>,
    pub payload_semantic_hash: String,
    pub private_key_path: PathBuf,
    pub signature_namespace: String,
    pub payload_encoding: String,
    pub signed_at: String,
}

pub fn load_artifact_record_for_signing(path: &Path) -> Result<ArtifactRecordV1, SignError> {
    load_artifact_record_from_path(path).map_err(|error| {
        SignError::new(
            SignErrorCode::ArtifactInputInvalid,
            "artifact_load",
            error.message,
        )
    })
}

/// Sign the artifact's semantic payload rather than its full JSON envelope.
///
/// That keeps signatures stable across envelope-only changes such as timestamps or redaction
/// metadata while still binding the signature to the artifact's canonical semantic content.
pub fn sign_artifact_v1(request: SignatureRequestV1) -> Result<ArtifactRecordV1, SignError> {
    if request.signed_at.trim().is_empty() {
        return Err(SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            "signing timestamp must be populated",
        ));
    }

    let semantic_bytes = request.artifact.semantic_bytes().map_err(|error| {
        SignError::new(
            SignErrorCode::ArtifactInputInvalid,
            "signing_preflight",
            error.message,
        )
    })?;
    let semantic_hash = request.artifact.semantic_hash_hex().map_err(|error| {
        SignError::new(
            SignErrorCode::ArtifactInputInvalid,
            "signing_preflight",
            error.message,
        )
    })?;
    let detached_signature = sign_detached_semantic_payload_v1(DetachedSignatureRequestV1 {
        payload_bytes: semantic_bytes,
        payload_semantic_hash: semantic_hash.clone(),
        private_key_path: request.private_key_path,
        signature_namespace: SIGNATURE_NAMESPACE_V1.to_string(),
        payload_encoding: PAYLOAD_ENCODING_V1.to_string(),
        signed_at: request.signed_at,
    })?;

    preflight_duplicate_signature(
        &request.artifact,
        &detached_signature.key_id,
        &semantic_hash,
    )?;
    let mut artifact = request.artifact;
    let envelope = artifact_envelope_mut(&mut artifact);
    envelope.signatures.push(detached_signature);

    validate_artifact_record(&artifact).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureOutputInvalid,
            "signature_output_validate",
            error,
        )
    })?;
    verify_artifact_signatures_v1(&artifact)?;

    Ok(artifact)
}

/// Emit a detached OpenSSH signature envelope for already-selected semantic payload bytes.
///
/// The caller chooses the exact payload and semantic hash; this function focuses on binding that
/// payload to a signer, namespace, and encoding tuple.
pub fn sign_detached_semantic_payload_v1(
    request: DetachedSignatureRequestV1,
) -> Result<SignatureEnvelopeV1, SignError> {
    if request.signed_at.trim().is_empty() {
        return Err(SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            "signing timestamp must be populated",
        ));
    }
    if request.payload_semantic_hash.trim().is_empty() {
        return Err(SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            "payload semantic hash must be populated",
        ));
    }
    if request.signature_namespace.trim().is_empty() {
        return Err(SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            "signature namespace must be populated",
        ));
    }
    if request.payload_encoding.trim().is_empty() {
        return Err(SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            "payload encoding must be populated",
        ));
    }

    let public_key = derive_public_key(&request.private_key_path)?;
    let key_id = derive_key_fingerprint(&public_key)?;
    let signature_b64 = emit_signature_base64(
        &request.private_key_path,
        &request.payload_bytes,
        &request.signature_namespace,
    )?;

    Ok(SignatureEnvelopeV1 {
        key_id: key_id.clone(),
        signer_identity: Some(key_id),
        public_key: Some(public_key),
        signature_format: Some(SIGNATURE_FORMAT_V1.to_string()),
        signature_namespace: Some(request.signature_namespace),
        payload_encoding: Some(request.payload_encoding),
        payload_semantic_hash: Some(request.payload_semantic_hash),
        signed_at: Some(request.signed_at),
        signature: signature_b64,
    })
}

/// Verify both the envelope binding fields and the OpenSSH signature bytes.
///
/// Metadata mismatches fail before the cryptographic check so callers get a precise reason when a
/// signature envelope no longer matches the current semantic payload.
pub fn verify_detached_semantic_payload_signature_v1(
    signature: &SignatureEnvelopeV1,
    payload_bytes: &[u8],
    payload_semantic_hash: &str,
) -> Result<(), SignError> {
    if signature.payload_semantic_hash.as_deref() != Some(payload_semantic_hash) {
        return Err(SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature payload semantic hash does not match the current payload",
        ));
    }

    if signature.signature_format.as_deref() != Some(SIGNATURE_FORMAT_V1) {
        return Err(SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature format must be populated and supported",
        ));
    }

    let signer_identity = signature.signer_identity.as_deref().ok_or_else(|| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature signer identity must be populated",
        )
    })?;
    let public_key = signature.public_key.as_deref().ok_or_else(|| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature public key must be populated",
        )
    })?;
    let derived_key_id = derive_key_fingerprint(public_key).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            error.message,
        )
    })?;
    if derived_key_id != signature.key_id {
        return Err(SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature key id must match the embedded public key fingerprint",
        ));
    }
    let signature_namespace = signature.signature_namespace.as_deref().ok_or_else(|| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature namespace must be populated",
        )
    })?;
    let signature_bytes = STANDARD.decode(&signature.signature).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            format!("failed to decode base64 signature bytes: {error}"),
        )
    })?;

    verify_signature_bytes(
        signer_identity,
        public_key,
        signature_namespace,
        &signature_bytes,
        payload_bytes,
    )
}

/// Re-derive the current semantic payload and require every attached signature to match it.
pub fn verify_artifact_signatures_v1(artifact: &ArtifactRecordV1) -> Result<(), SignError> {
    validate_artifact_record(artifact).map_err(|error| {
        SignError::new(
            SignErrorCode::ArtifactInputInvalid,
            "signature_verify",
            error,
        )
    })?;

    let semantic_bytes = artifact.semantic_bytes().map_err(|error| {
        SignError::new(
            SignErrorCode::ArtifactInputInvalid,
            "signature_verify",
            error.message,
        )
    })?;
    let semantic_hash = artifact.semantic_hash_hex().map_err(|error| {
        SignError::new(
            SignErrorCode::ArtifactInputInvalid,
            "signature_verify",
            error.message,
        )
    })?;

    for signature in artifact_envelope(artifact).signatures.iter() {
        verify_detached_semantic_payload_signature_v1(signature, &semantic_bytes, &semantic_hash)?;
    }

    Ok(())
}

fn preflight_duplicate_signature(
    artifact: &ArtifactRecordV1,
    key_id: &str,
    semantic_hash: &str,
) -> Result<(), SignError> {
    // Prevent signing the same semantic payload twice with the same signer/namespace tuple.
    let duplicate = artifact_envelope(artifact)
        .signatures
        .iter()
        .any(|signature| {
            signature.key_id == key_id
                && signature.payload_semantic_hash.as_deref() == Some(semantic_hash)
                && signature.signature_namespace.as_deref() == Some(SIGNATURE_NAMESPACE_V1)
        });

    if duplicate {
        return Err(SignError::new(
            SignErrorCode::SignatureDuplicate,
            "signing_preflight",
            "artifact already carries the same signing tuple for this key, payload, and namespace",
        ));
    }

    Ok(())
}

fn emit_signature_base64(
    private_key_path: &Path,
    payload_bytes: &[u8],
    signature_namespace: &str,
) -> Result<String, SignError> {
    // The OpenSSH signing path operates on files, so stage the canonical payload in a private
    // temp directory and convert the emitted signature blob back into the envelope base64 field.
    let temp_dir = unique_temp_dir("sign-emit");
    let payload_path = temp_dir.join("payload.bin");
    fs::write(&payload_path, payload_bytes).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            format!("failed to write signing payload: {error}"),
        )
    })?;
    let signature_path = signature_path_for(&payload_path);

    let output = run_ssh_keygen(
        Command::new("ssh-keygen").args([
            "-Y",
            "sign",
            "-f",
            private_key_path.to_str().ok_or_else(|| {
                SignError::new(
                    SignErrorCode::SigningKeyInvalid,
                    "signing_key_load",
                    "private key path must be valid UTF-8 for ssh-keygen",
                )
            })?,
            "-n",
            signature_namespace,
            payload_path.to_str().ok_or_else(|| {
                SignError::new(
                    SignErrorCode::SignatureEmitFailed,
                    "signature_emit",
                    "payload path must be valid UTF-8 for ssh-keygen",
                )
            })?,
        ]),
        SignErrorCode::SignatureEmitFailed,
        "signature_emit",
    )?;

    if !output.status.success() {
        return Err(SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            ssh_stderr_message("ssh-keygen sign", &output),
        ));
    }

    let signature_bytes = fs::read(&signature_path).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureEmitFailed,
            "signature_emit",
            format!("failed to read emitted signature file: {error}"),
        )
    })?;

    Ok(STANDARD.encode(signature_bytes))
}

fn derive_public_key(private_key_path: &Path) -> Result<String, SignError> {
    let output = run_ssh_keygen(
        Command::new("ssh-keygen").args([
            "-y",
            "-f",
            private_key_path.to_str().ok_or_else(|| {
                SignError::new(
                    SignErrorCode::SigningKeyInvalid,
                    "signing_key_load",
                    "private key path must be valid UTF-8 for ssh-keygen",
                )
            })?,
        ]),
        SignErrorCode::SigningKeyInvalid,
        "signing_key_load",
    )?;

    if !output.status.success() {
        return Err(SignError::new(
            SignErrorCode::SigningKeyInvalid,
            "signing_key_load",
            ssh_stderr_message("ssh-keygen -y", &output),
        ));
    }

    let public_key = String::from_utf8(output.stdout).map_err(|error| {
        SignError::new(
            SignErrorCode::SigningKeyInvalid,
            "signing_key_load",
            format!("derived public key was not valid UTF-8: {error}"),
        )
    })?;
    let public_key = public_key.trim().to_string();
    if public_key.is_empty() {
        return Err(SignError::new(
            SignErrorCode::SigningKeyInvalid,
            "signing_key_load",
            "derived public key must not be empty",
        ));
    }

    Ok(public_key)
}

fn derive_key_fingerprint(public_key: &str) -> Result<String, SignError> {
    let temp_dir = unique_temp_dir("sign-fingerprint");
    let public_key_path = temp_dir.join("signer.pub");
    fs::write(&public_key_path, format!("{public_key}\n")).map_err(|error| {
        SignError::new(
            SignErrorCode::SigningKeyInvalid,
            "signing_key_load",
            format!("failed to write temporary public key: {error}"),
        )
    })?;

    let output = run_ssh_keygen(
        Command::new("ssh-keygen").args([
            "-lf",
            public_key_path.to_str().ok_or_else(|| {
                SignError::new(
                    SignErrorCode::SigningKeyInvalid,
                    "signing_key_load",
                    "public key path must be valid UTF-8 for ssh-keygen",
                )
            })?,
        ]),
        SignErrorCode::SigningKeyInvalid,
        "signing_key_load",
    )?;

    if !output.status.success() {
        return Err(SignError::new(
            SignErrorCode::SigningKeyInvalid,
            "signing_key_load",
            ssh_stderr_message("ssh-keygen -lf", &output),
        ));
    }

    let text = String::from_utf8(output.stdout).map_err(|error| {
        SignError::new(
            SignErrorCode::SigningKeyInvalid,
            "signing_key_load",
            format!("fingerprint output was not valid UTF-8: {error}"),
        )
    })?;
    let fingerprint = text
        .split_whitespace()
        .nth(1)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SignError::new(
                SignErrorCode::SigningKeyInvalid,
                "signing_key_load",
                "failed to parse OpenSSH key fingerprint",
            )
        })?;

    Ok(fingerprint)
}

fn verify_signature_bytes(
    signer_identity: &str,
    public_key: &str,
    signature_namespace: &str,
    signature_bytes: &[u8],
    payload_bytes: &[u8],
) -> Result<(), SignError> {
    let temp_dir = unique_temp_dir("sign-verify");
    let allowed_signers_path = temp_dir.join("allowed_signers");
    fs::write(
        &allowed_signers_path,
        format!("{signer_identity} {public_key}\n"),
    )
    .map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            format!("failed to write allowed signers file: {error}"),
        )
    })?;
    let signature_path = temp_dir.join("payload.sig");
    fs::write(&signature_path, signature_bytes).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            format!("failed to write signature file: {error}"),
        )
    })?;

    let allowed_signers_arg = allowed_signers_path.to_str().ok_or_else(|| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "allowed signers path must be valid UTF-8 for ssh-keygen",
        )
    })?;
    let signature_arg = signature_path.to_str().ok_or_else(|| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "signature path must be valid UTF-8 for ssh-keygen",
        )
    })?;

    let mut command = Command::new("ssh-keygen");
    command.args([
        "-Y",
        "verify",
        "-f",
        allowed_signers_arg,
        "-I",
        signer_identity,
        "-n",
        signature_namespace,
        "-s",
        signature_arg,
    ]);
    prepare_non_interactive_ssh_keygen(&mut command);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| map_spawn_error(error, "signature_verify"))?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            "failed to open ssh-keygen verify stdin",
        )
    })?;
    stdin.write_all(payload_bytes).map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            format!("failed to write payload bytes into ssh-keygen verify stdin: {error}"),
        )
    })?;
    drop(stdin);

    let output = child.wait_with_output().map_err(|error| {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            format!("failed to wait for ssh-keygen verify: {error}"),
        )
    })?;

    if !output.status.success() {
        return Err(SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            "signature_verify",
            ssh_stderr_message("ssh-keygen verify", &output),
        ));
    }

    Ok(())
}

fn validate_artifact_record(artifact: &ArtifactRecordV1) -> Result<(), String> {
    match artifact {
        ArtifactRecordV1::Survey(artifact) => validate_host_survey(artifact),
        ArtifactRecordV1::Contract(artifact) => validate_host_contract(artifact),
        ArtifactRecordV1::ServiceProfile(artifact) => validate_service_profile(artifact),
        ArtifactRecordV1::State(artifact) => validate_host_state(artifact),
        ArtifactRecordV1::ValidationReport(artifact) => validate_validation_report(artifact),
        ArtifactRecordV1::ConfigBundle(artifact) => validate_config_bundle(artifact),
        ArtifactRecordV1::DecisionBundle(artifact) => validate_decision_bundle(artifact),
    }
    .map_err(|error| error.message)
}

fn artifact_envelope(
    artifact: &ArtifactRecordV1,
) -> &crate::artifacts::envelope_v1::ArtifactEnvelopeV1 {
    match artifact {
        ArtifactRecordV1::Survey(artifact) => &artifact.envelope,
        ArtifactRecordV1::Contract(artifact) => &artifact.envelope,
        ArtifactRecordV1::ServiceProfile(artifact) => &artifact.envelope,
        ArtifactRecordV1::State(artifact) => &artifact.envelope,
        ArtifactRecordV1::ValidationReport(artifact) => &artifact.envelope,
        ArtifactRecordV1::ConfigBundle(artifact) => &artifact.envelope,
        ArtifactRecordV1::DecisionBundle(artifact) => &artifact.envelope,
    }
}

fn artifact_envelope_mut(
    artifact: &mut ArtifactRecordV1,
) -> &mut crate::artifacts::envelope_v1::ArtifactEnvelopeV1 {
    match artifact {
        ArtifactRecordV1::Survey(artifact) => &mut artifact.envelope,
        ArtifactRecordV1::Contract(artifact) => &mut artifact.envelope,
        ArtifactRecordV1::ServiceProfile(artifact) => &mut artifact.envelope,
        ArtifactRecordV1::State(artifact) => &mut artifact.envelope,
        ArtifactRecordV1::ValidationReport(artifact) => &mut artifact.envelope,
        ArtifactRecordV1::ConfigBundle(artifact) => &mut artifact.envelope,
        ArtifactRecordV1::DecisionBundle(artifact) => &mut artifact.envelope,
    }
}

fn run_ssh_keygen(
    command: &mut Command,
    failure_code: SignErrorCode,
    checkpoint_id: &'static str,
) -> Result<Output, SignError> {
    prepare_non_interactive_ssh_keygen(command);
    command.output().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SignError::new(
                SignErrorCode::SigningToolUnavailable,
                checkpoint_id,
                "ssh-keygen is not available in PATH",
            )
        } else {
            SignError::new(
                failure_code,
                checkpoint_id,
                format!("failed to launch ssh-keygen: {error}"),
            )
        }
    })
}

fn map_spawn_error(error: std::io::Error, checkpoint_id: &'static str) -> SignError {
    if error.kind() == std::io::ErrorKind::NotFound {
        SignError::new(
            SignErrorCode::SigningToolUnavailable,
            checkpoint_id,
            "ssh-keygen is not available in PATH",
        )
    } else {
        SignError::new(
            SignErrorCode::SignatureVerifyFailed,
            checkpoint_id,
            format!("failed to launch ssh-keygen: {error}"),
        )
    }
}

fn prepare_non_interactive_ssh_keygen(command: &mut Command) {
    command.env("SSH_ASKPASS_REQUIRE", "never");
    command.env_remove("SSH_ASKPASS");
    command.env_remove("DISPLAY");
}

fn ssh_stderr_message(command_name: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        format!("{command_name} failed without stderr output")
    } else {
        format!("{command_name} failed: {stderr}")
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("fitctl-{prefix}-{}-{nanos}", std::process::id()));
    let _ = fs::create_dir_all(&path);
    path
}

fn signature_path_for(payload_path: &Path) -> PathBuf {
    let mut raw = payload_path.as_os_str().to_os_string();
    raw.push(".sig");
    PathBuf::from(raw)
}
