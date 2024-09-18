////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2023 Crypto Lab Inc.                                    //
//                                                                            //
// - This file is part of HEaaN homomorphic encryption library.               //
// - HEaaN cannot be copied and/or distributed without the express permission //
//  of Crypto Lab Inc.                                                        //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <memory>
#include <optional>
#include <string>

#include "Context.hpp"
#include "HEaaNExport.hpp"
#include "KeyPack.hpp"

namespace HEaaN {

class SecretKey;
class KeyGeneratorImpl;

///
///@brief A class generating public (encryption/evaluation) keys from a
/// secret key
///
class HEAAN_API KeyGenerator {
public:
    ///@brief Create a KeyGenerator object
    ///@details This generator internally creates a KeyPack object, which the
    /// user can later extract by `getKeyPack()` function. The SecretKey sk_
    /// should have the same context as the input context context_. Otherwise,
    /// throws 'RuntimeException'.
    explicit KeyGenerator(const Context &context, const SecretKey &sk);

    ///@brief Create a KeyGenerator object from an existing KeyPack
    /// object.
    ///@details The SecretKey sk should have the same context as the input
    /// context context. Otherwise, throws 'RuntimeException'.
    explicit KeyGenerator(const Context &context, const SecretKey &sk,
                          const KeyPack &pack);

    ///@brief Create a KeyGenerator object which can generate key that can
    /// perform sparse secret encapsulation, with the same parameter which @p
    /// context is constructed
    /// for.
    ///@throws RuntimeException if @p context_sparse is not a context
    /// constructed with the corresponding sparse parameter of which constructed
    /// context.
    /// Please refer to SparseParameterPresetFor() on ParameterPreset.hpp
    /// for the sparse parameters.
    explicit KeyGenerator(const Context &context, const Context &context_sparse,
                          const SecretKey &sk);

    ///@brief Create a KeyGenerator object from an existing @p pack object which
    /// can generate key that can which can perform sparse secret encapsulation,
    /// with the same parameter which context is constructed for.
    ///@throws RuntimeException if @p context_sparse is not a context
    /// constructed
    /// with the corresponding sparse parameter of @p context.
    /// Please refer to SparseParameterPresetFor() on ParameterPreset.hpp
    /// for the sparse parameters.
    explicit KeyGenerator(const Context &context, const Context &context_sparse,
                          const SecretKey &sk, const KeyPack &pack);

    //////////////////////////////////
    // Functions for key generation //
    //////////////////////////////////

    ///@brief Generate an encryption key into the internal `KeyPack` object
    void genEncryptionKey(void) const;

    ///@brief Generate a multiplication key into the internal `KeyPack` object
    void genMultiplicationKey(void) const;

    ///@brief Generate a conjugation key into the internal `KeyPack` object
    void genConjugationKey(void) const;

    ///@brief Generate a rotation key for the left rotation with `rot` steps,
    /// into the internal KeyPack object.
    void genLeftRotationKey(u64 rot) const;

    ///@brief Generate a rotation key for the right rotation with `rot` steps,
    /// into the internal KeyPack object.
    void genRightRotationKey(u64 rot) const;

    ///@brief Generate a bundle of rotation keys
    ///@details This function creates rotations keys for the left and right
    /// rotations with all power-of-two steps, so that any arbitrary rotation
    /// can be decomposed as a composition of these base rotations.
    void genRotationKeyBundle(void) const;

    ///@brief Generate a pair of keys for sparse secret encapsulation
    ///@details This function creates switching keys between the dense secret
    /// key and the sparse secret key so the sparse secret encapsulation can be
    /// performed during bootstrapping.
    ///@throws RuntimeException
    void genSparseSecretEncapsulationKey(void) const;

    ///@brief Generate commonly used keys
    ///@details Be cautious that for bigger parameter sets, this function
    /// creates a lot of public keys in the internal KeyPack object, causing a
    /// high memory usage.  In order to prevent this, the user might want to not
    /// use this function directly, and do use other key generation functions in
    /// the class separately, and use `save()` and `flush()` between the key
    /// generation.
    inline void genCommonKeys(void) const {
        genEncryptionKey();
        genMultiplicationKey();
        genConjugationKey();
        genRotationKeyBundle();
    }

    ///@brief Generate rotation keys used for accelerating the bootstrapping
    /// process.
    ///@param[in] log_slots
    ///@details This function generates only rotation keys. Bootstrapping
    /// process requires multiplication key and conjugation key, which are not
    /// generated in this function.
    void genRotKeysForBootstrap(const u64 log_slots) const;

    ///////////////////////
    // Utility functions //
    ///////////////////////

    ///@brief Save the generated keys in the internal KeyPack object into files.
    ///@param[in] dir_path must indicate a valid directory.
    ///@details This function creates a subdirectory `PK/` inside `dirPath`
    /// directory, and save all the keys in the cache of the KeyPack object into
    /// this subdirectory.
    void save(const std::string &dir_path) const;

    ///@brief Discard current internal KeyPack object
    void flush(void);

    ///@brief Extract the internal KeyPack object
    ///@details Keys might be generated again into the keypack after this getter
    /// function is called.
    KeyPack getKeyPack() const { return pack_; }

private:
    const Context context_;
    const std::optional<Context> context_sparse_;

    ///@brief The internal keypack object.
    KeyPack pack_;

    std::shared_ptr<KeyGeneratorImpl> impl_;
};
} // namespace HEaaN
