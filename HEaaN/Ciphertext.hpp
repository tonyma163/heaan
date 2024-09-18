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
#include "Real.hpp"
#include "device/Device.hpp"

namespace HEaaN {
class CiphertextImpl;
class Polynomial;

///
///@brief A class of ciphertexts each of which contains a vector of polynomials
/// of length > 1.
///
class HEAAN_API Ciphertext {
    friend class BootstrapperImpl;

public:
    explicit Ciphertext(const Context &context, bool is_extended = false);

    ParameterPreset getParameterPreset() const;

    ///@brief Get the size of a ciphertext
    u64 getSize() const;

    ///@brief Set the size of a ciphertext
    ///@throws if the size is less than 2.
    void setSize(u64 size);

    ///@brief Set log(number of slots) of a ciphertext
    ///@param[in] log_slots
    void setLogSlots(u64 log_slots);

    ///@brief Get log(number of slots) of a ciphertext
    ///@returns log(number of slots)
    u64 getLogSlots() const;
    u64 getNumberOfSlots() const;

    ///@brief Get prime of current level
    u64 getCurrentPrime() const;

    ///@brief Get scale factor of current level
    Real getCurrentScaleFactor() const;

    ///@brief Get the i-th part of ciphertext.
    Polynomial &getPoly(u64 i);
    ///@brief Get the i-th part of ciphertext.
    const Polynomial &getPoly(u64 i) const;
    ///@brief Get the \p level -th data of the i-th part.
    ///@details the \p level -th data is a modulo q_{level} information of the
    /// polynomial
    u64 *getPolyData(u64 i, u64 level) const;

    ///@brief True if it is a mod-up ciphertext, False otherwise
    bool isModUp() const;

    ///@brief Save a ciphertext to a file
    void save(const std::string &path) const;

    ///@brief Save a ciphertext
    void save(std::ostream &stream) const;

    ///@brief Load a ciphertext from a file
    void load(const std::string &path);

    ///@brief Load a ciphertext
    void load(std::istream &stream);

    ///@brief Rescaling flag
    ///@returns The amount of extra deltas multiplied.
    int getRescaleCounter() const;

    ///@brief set rescale counter
    void setRescaleCounter(int r_counter);

    ///@brief Get level of a cipherext.
    ///@returns The current level of the ciphertext.
    u64 getLevel() const;

    ///@brief Set level of a ciphertext.
    ///@param[in] level
    void setLevel(u64 level);

    ///@brief Get device which a ciphertext reside in.
    ///@returns The device in which the ciphertext resides
    const Device &getDevice() const;

    ///@brief Send a ciphertext to given device.
    ///@param[in] device
    void to(const Device &device);

    ///@brief Allocate memory for a ciphertext at given device.
    ///@param[in] device
    void allocate(const Device &device);

private:
    Pointer<CiphertextImpl> impl_;

    ///@brief Construct a Ciphertext containing polynomial of same value
    /// only valid when the input ciphertext constructed for context
    /// sharing primes
    explicit Ciphertext(const Context &context, const Ciphertext &ctxt);
};

} // namespace HEaaN
