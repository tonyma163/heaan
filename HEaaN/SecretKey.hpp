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

#include "Context.hpp"
#include "HEaaNExport.hpp"
#include "Pointer.hpp"
#include "device/Device.hpp"

namespace HEaaN {
class SecretKeyImpl;
class Polynomial;

///
///@brief Secret key class
///

class HEAAN_API SecretKey {
public:
    using Coefficients = int *;
    ///@brief Generate random secret key
    explicit SecretKey(const Context &context);
    ///@brief Load secret key from stream
    ///@details The key can be loaded regardless of whether the stream is saving
    /// the full key or its seed only.
    explicit SecretKey(const Context &context, std::istream &stream);
    ///@brief Load secret key from file
    ///@details The key can be loaded regardless of whether the stream is saving
    /// the full key or its seed only.
    explicit SecretKey(const Context &context, const std::string &key_dir_path);

    ///@brief Generate a secret key whose coefficients are
    /// copied from @p coefficients and fits @p context.
    ///@details The key cannot be save or loaded by its seed.
    /// Instead of using a uniform random bit generator, it fills the secret
    /// key's coefficients with integers from coefficients[0] to
    /// coefficients[context->getDimension() - 1].
    explicit SecretKey(const Context &context,
                       const Coefficients &coefficients);

    ///@brief Save a secret key to file
    void save(const std::string &path) const;
    ///@brief Save a secret key to stream
    void save(std::ostream &stream) const;

    ///@brief Save the seed of a secret key to file
    ///@details The seed can reproduce the key under different parameter
    ///(Context) too.
    void saveSeedOnly(const std::string &path) const;
    ///@brief Save the seed of a secret key to stream
    ///@details The seed can reproduce the key under different parameter
    ///(Context) too.
    void saveSeedOnly(std::ostream &stream) const;

    ///@brief Get Context context
    const Context &getContext() const;

    ///@brief Get sx part of secret key.
    Polynomial &getSx();
    ///@brief Get const sx part of secret key.
    const Polynomial &getSx() const;

    ///@brief Get integer representation of coefficients.
    Coefficients getCoefficients() const;

    ///@brief Get device a secret key reside in.
    ///@returns The device in which the secret key resides
    const Device &getDevice() const;

    ///@brief Send a secret key to given device.
    ///@param[in] device
    void to(const Device &device);

private:
    Pointer<SecretKeyImpl> impl_;
};

} // namespace HEaaN
