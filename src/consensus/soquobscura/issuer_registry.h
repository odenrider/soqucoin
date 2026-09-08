// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// SoquObscura — per-asset issuer key registry (WI-2)
//
// =============================================================================
// STATUS: SCAFFOLDING. Not in Makefile.am, not included by any consensus path.
// Plan:   doc/design/DL-SOQUOBSCURA-VE-CONSENSUS-PLAN.md section 3a
// Review: doc/design/DL-SOQUOBSCURA-ISSUER-KEY-REVIEW.md
// Bead:   soqucoin-build-soquobscura-ve-wi1-wi2-4xiq
// =============================================================================
//
// ⛔ MODEL STATUS: PROPOSED, NOT RATIFIED. This is decision gate D2 and it is
// OPEN. An earlier revision of this header claimed a ratification dated 2026-08-16;
// no such ratification is recorded in any design document, and the companion
// review (DL-SOQUOBSCURA-ISSUER-KEY-REVIEW.md) states on its own first page
// that it reviews a *proposal* and is "an analytical device, not a record of
// real people's review". The claim has been withdrawn. This is the same defect
// class as the witness-v6 collision: an artifact asserting a fact that no
// source supports, which a later reader then builds on. Do not restore an
// authority claim here without a dated ratification you can cite.
//
// PROPOSED MODEL (gate D2): per-asset key registry, epoch-addressed, rotation
// authority split from the decryption key, storing a typed key DESCRIPTOR
// rather than a raw public key.
//
// WHY A DESCRIPTOR RATHER THAN A KEY
//
// The ratified post-launch enhancement is a threshold (t-of-n) issuer key so
// that no single party can decrypt the ledger. That upgrade is cheap here, and
// the reason is worth recording because the whole design leans on it:
//
//   the verifiable-encryption public key is t_v = A_v * s_v + e_v
//
// A threshold scheme shares the PRIVATE s_v across n parties. It does not
// change t_v, does not change the ciphertext shape, and does not change the
// relation. Consensus verifies the VE proof and never performs a decryption,
// so single-key -> threshold is a change in who holds s_v plus a new descriptor
// type. It is NOT a consensus change and NOT a wire-format break.
// (Confirmed against VE-V2-CARD.md line 41 and the phase-2 verifier signature.)
//
// SECURITY PROPERTY THIS MODEL DOES *NOT* PROVIDE, stated so nobody banks it:
// epoch rotation limits FUTURE exposure only. A decryption key that leaks
// exposes every amount ever encrypted to it, retroactively and permanently.
// Rotation does not mitigate exfiltration; only threshold access and
// distributed custody do. See the review, finding A2.

#ifndef SOQUCOIN_CONSENSUS_SOQUOBSCURA_ISSUER_REGISTRY_H
#define SOQUCOIN_CONSENSUS_SOQUOBSCURA_ISSUER_REGISTRY_H

#include <array>
#include <cstdint>
#include <vector>

namespace soquobscura {

//! Ring-element counts for the verifiable-encryption public key, matching the
//! phase-2 verifier entry point soq_lbpp_verify_ve().
static constexpr size_t VE_SEED_BYTES = 32;    //!< seeds the public matrix A_v
static constexpr size_t VE_TV_COEFFS  = 1536;  //!< t_v, 24 ring elements

//! Descriptor type. New types are ADDED; existing ones are never redefined,
//! because an epoch already referenced by on-chain outputs must keep resolving
//! to the same key forever.
enum class KeyDescriptorType : uint8_t {
    //! Single-key verifiable encryption. One holder of s_v.
    VE_SINGLE_V1 = 0x01,

    //! Threshold verifiable encryption, t-of-n over s_v. RESERVED, not yet
    //! defined. Public key material is identical in shape to VE_SINGLE_V1
    //! because t_v does not change under sharing; only off-chain custody
    //! differs. Ratified post-launch enhancement.
    VE_THRESHOLD_V1 = 0x02,
};

// -----------------------------------------------------------------------------
// One issuer key epoch.
// -----------------------------------------------------------------------------
struct IssuerKeyEpoch
{
    uint8_t nType{0};                              //!< KeyDescriptorType
    uint32_t nKeyId{0};                            //!< epoch id, referenced by Disclosure::nKeyId
    std::array<uint8_t, VE_SEED_BYTES> vkSeed{};   //!< seeds A_v
    std::vector<int64_t> tv;                       //!< t_v, VE_TV_COEFFS centered coefficients

    //! Height at which this epoch became usable for NEW outputs.
    int32_t nActiveFromHeight{0};

    //! Height after which this epoch may no longer be used for NEW outputs.
    //! Zero means open-ended. ⚠️ A retired epoch must still RESOLVE, because
    //! outputs created under it remain spendable and auditable forever.
    //! Retirement restricts creation, never resolution.
    int32_t nRetiredAtHeight{0};

    bool IsNull() const { return nType == 0; }
};

// -----------------------------------------------------------------------------
// The registry: asset -> epoch -> key.
// -----------------------------------------------------------------------------
//
// ⛔ FAIL-CLOSED CONTRACT (review finding A13). Every lookup failure is a
// REJECT, never a skip and never a fallback to a default key:
//
//   - unknown asset               -> reject
//   - unknown nKeyId              -> reject
//   - epoch not yet active        -> reject
//   - epoch retired for creation  -> reject NEW outputs, still resolve old ones
//   - malformed descriptor        -> reject
//
// A lookup miss that returned "no disclosure required" would convert a typo
// into a bypass of the entire compliance rule.
class IssuerRegistry
{
public:
    //! Resolve the key for (asset, keyId) at a height. Returns false on ANY
    //! failure; callers must treat false as "reject this output", never as
    //! "no requirement".
    bool Resolve(uint32_t nAssetType, uint32_t nKeyId, int32_t nHeight,
                 IssuerKeyEpoch& epochOut) const;

    //! Does this asset require a mandatory issuer disclosure?
    //!
    //! ⛔ REVIEW FINDING A1, THE MOST IMPORTANT CONSTRAINT IN THIS FILE.
    //! The rule is asset-typed: Tier A (USDSOQ) is mandatory, Tier B (SOQ) is
    //! exempt because individuals hold their own keys. That exemption is a
    //! bypass surface. This predicate and the asset-type determination it reads
    //! MUST be the same evaluation, on the same input, at the same point in
    //! validation as the disclosure requirement itself. Two checks that agree
    //! today are a divergence waiting to happen — the same shape as the
    //! mempool-versus-consensus divergence already documented in this system.
    //!
    //! Unknown or malformed asset type MUST return true (mandatory), never
    //! false. Failing closed means a parse error rejects a transaction; failing
    //! open means a malformed byte silently buys exemption from the compliance
    //! rule.
    bool RequiresIssuerDisclosure(uint32_t nAssetType) const;
};

} // namespace soquobscura

#endif // SOQUCOIN_CONSENSUS_SOQUOBSCURA_ISSUER_REGISTRY_H
