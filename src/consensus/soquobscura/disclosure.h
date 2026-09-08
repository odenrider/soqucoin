// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// SoquObscura — mandatory issuer disclosure for confidential outputs
//
// =============================================================================
// STATUS: SCAFFOLDING. Deliberately NOT in Makefile.am and NOT included by any
// consensus path. Nothing here affects validation until WI-2 and WI-3 land.
// Plan: doc/design/DL-SOQUOBSCURA-VE-CONSENSUS-PLAN.md
// Bead: soqucoin-build-soquobscura-ve-wi1-wi2-4xiq
// =============================================================================
//
// WHAT THIS IS, AND WHY IT IS NOT ViewKeyData
//
// The ratified Tier A compliance rule (DL-LATTICEBP-STATE-ANALYSIS-2026-07-18
// section II.3, ratified 2026-07-19) requires that every confidential
// USDSOQ output carry the amount and blinding encrypted to the issuer's view
// key, together with an in-band proof, verified by consensus, that the
// ciphertext encrypts exactly the committed value. Consensus rejects a
// confidential USDSOQ output without one. That rule is what makes issuer audit,
// the proof-of-reserves turnstile, regulator disclosure, the Travel Rule and
// GENIUS Act 4(a)(2) freeze compatibility true statements rather than
// intentions.
//
// The pre-existing consensus/privacy.h ViewKeyData is NOT that mechanism and is
// scheduled for deletion (WI-4):
//
//   - it is documented as OPTIONAL, so it has no compliance force;
//   - it is referenced by nothing in the validation path;
//   - it carries no proof of correct encryption, only a 32-byte commitment
//     hint an auditor can check AFTER decrypting, which consensus cannot use
//     because consensus never decrypts;
//   - it encrypts under ChaCha20-Poly1305 with a key from HKDF over a
//     Diffie-Hellman shared secret. The symmetric part is fine; the key
//     agreement is classically breakable, which makes it a
//     harvest-now-decrypt-later hole inside a post-quantum chain.
//
// This structure replaces it wholesale, as the scope document directs, with the
// Module-LWE verifiable encryption already built and measured in phase 3
// (22,426 B wire, prove 104.0 ms, verify 56.9 ms, MLWE 2^164.2 at k_dim = 12).
//
// DISAMBIGUATION, because both have been confused before:
//   - the ViewKey in crypto/latticebp/stealth_address.h is the Monero-style
//     RECIPIENT SCANNING key, from the superseded design;
//   - the issuer view key here is the mandatory Tier A COMPLIANCE key.
// Different objects. Do not conflate them.

#ifndef SOQUCOIN_CONSENSUS_SOQUOBSCURA_DISCLOSURE_H
#define SOQUCOIN_CONSENSUS_SOQUOBSCURA_DISCLOSURE_H

#include <serialize.h>

#include <cstdint>
#include <vector>

namespace soquobscura {

//! Which key a disclosure is encrypted to.
//! Dual-target at launch is ratified: the issuer target is mandatory for Tier A,
//! a counterparty/auditor target is optional. A threshold (t-of-n) issuer key is
//! a ratified POST-LAUNCH enhancement and is deliberately not modelled here.
enum class DisclosureTarget : uint8_t {
    ISSUER      = 0x01,  //!< mandatory for confidential USDSOQ (Tier A)
    COUNTERPARTY = 0x02, //!< optional second target
};

//! Wire version. Bump only with a KAT and an ingest rule, never silently:
//! canonical bytes are part of consensus under the ratified Option (b)
//! transcript rule, so a representation change is a consensus change.
static constexpr uint8_t DISCLOSURE_VERSION_V1 = 0x01;

// -----------------------------------------------------------------------------
// One encrypted-and-proved disclosure of (value, blinding) to one target key.
// -----------------------------------------------------------------------------
class Disclosure
{
public:
    uint8_t nVersion{0};

    //! Which key this is encrypted to.
    uint8_t nTarget{0};

    //! Identifies WHICH issuer/counterparty key was used, so the verifier can
    //! select the right public key and so keys can rotate.
    //! NOTE: how issuer keys are published and rotated is an OPEN DESIGN
    //! DECISION (WI-3, bead soquobscura-ve-wi3-8r6e). This field exists so that
    //! whichever answer is chosen, rotation does not require a hard fork.
    uint32_t nKeyId{0};

    //! Module-LWE ciphertext over the commitment ring, encrypting (v, r).
    std::vector<uint8_t> vchCiphertext;

    //! Verifiable-encryption proof: the ciphertext encrypts exactly the value
    //! committed in the output's commitment, and its noise is bounded so that
    //! decryption is unambiguous.
    std::vector<uint8_t> vchProof;

    Disclosure() = default;

    bool IsNull() const { return nVersion == 0; }

    bool IsIssuerTarget() const
    {
        return nTarget == static_cast<uint8_t>(DisclosureTarget::ISSUER);
    }

    //! Serialized size in bytes. Used for fee and weight accounting; must match
    //! what SerializationOp writes, and a KAT pins the two together.
    size_t SerializedSize() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(nTarget);
        READWRITE(nKeyId);
        READWRITE(vchCiphertext);
        READWRITE(vchProof);
    }
};

// -----------------------------------------------------------------------------
// The set of disclosures attached to one confidential output.
// -----------------------------------------------------------------------------
class DisclosureSet
{
public:
    std::vector<Disclosure> vDisclosures;

    bool IsNull() const { return vDisclosures.empty(); }

    //! True iff at least one well-formed ISSUER-targeted disclosure is present.
    //! ⚠️ Presence only. This says NOTHING about whether the proof verifies, and
    //! must never be used as the consensus check on its own. The consensus rule
    //! (WI-3) is presence AND verification; a presence-only gate would be
    //! exactly the kind of hollow check the scope document warns about.
    bool HasIssuerTarget() const;

    size_t SerializedSize() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(vDisclosures);
    }
};

} // namespace soquobscura

#endif // SOQUCOIN_CONSENSUS_SOQUOBSCURA_DISCLOSURE_H
