import pytest
from pathlib import Path
from chronotrace.core.case import Case
from chronotrace.core.bundle import CaseBundleManager


def test_bundle_export_and_verify(tmp_path: Path):
    case_dir = tmp_path / "case_test"
    case = Case.create(
        case_id="CASE-BUNDLE-01",
        out_dir=case_dir,
        examiner="Auditor Smith",
    )

    # Put a dummy evidence file
    dummy_ev = case.evidence_dir / "sample.bin"
    dummy_ev.write_bytes(b"FORENSIC_EVIDENCE_DATA_12345")

    # Export bundle with passphrase signature
    bundle_path = tmp_path / "CASE-BUNDLE-01.wasp"
    passphrase = "SecretCourtroomKey2026!"
    exported = CaseBundleManager.export_bundle(
        case_dir=case_dir,
        output_file=bundle_path,
        passphrase=passphrase,
    )

    assert exported.exists()
    assert exported.suffix == ".wasp"

    # Verify bundle with correct passphrase
    res_valid = CaseBundleManager.verify_bundle(bundle_path, passphrase=passphrase)
    assert res_valid.is_valid is True
    assert res_valid.signature_present is True
    assert res_valid.signature_valid is True
    assert res_valid.files_checked > 0

    # Verify bundle with wrong passphrase fails signature check
    res_bad_key = CaseBundleManager.verify_bundle(bundle_path, passphrase="WrongPassword!")
    assert res_bad_key.is_valid is False
    assert res_bad_key.signature_valid is False

    # Extract bundle into a new clean directory
    extracted_dir = tmp_path / "extracted_case"
    CaseBundleManager.extract_bundle(
        bundle_path=bundle_path,
        target_dir=extracted_dir,
        passphrase=passphrase,
    )
    assert (extracted_dir / "case.json").exists()
    assert (extracted_dir / "evidence" / "sample.bin").read_bytes() == b"FORENSIC_EVIDENCE_DATA_12345"
