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

namespace HEaaN {

class Message;
class Plaintext;

///
///@brief Class containing functions dealing with message/plaintext encoding and
/// decoding.
///
class HEAAN_API EnDecoder {
public:
    explicit EnDecoder(const Context &context);

    ///@brief Encode a message into a plaintext at a certain level at a certain
    /// rescale counter.
    ///@param[in] msg Input message
    ///@param[in] level Target level to which \p msg is to be encoded
    ///@param[in] r_counter Target rescale counter to which \p msg is to be
    /// encoded
    ///@returns Encoded plaintext.
    ///@details All the real and imaginary parts of the slot values in \p msg
    /// should not exceed 2^(64). The output plaintext is in NTT form, which can
    /// be directly used in polynomial multiplication. The size of \p msg should
    /// be a power of two, being less than or equal to half of the dimension of
    /// the current context.
    ///@throws RuntimeException if neither the size of the input message is
    /// a power of two, nor it exceeds one half of the ciphertext dimension of
    /// the current homomorphic encryption context.
    ///@throws RuntimeException if the target \p level exceeds the maximal
    /// level decided in the homomorphic encryption context.
    ///@throws RuntimeException if the target rescale counter exceeds the
    /// target \p level.
    Plaintext encode(const Message &msg, u64 level, int r_counter = 0) const;

    ///@brief Encode a message into a plaintext with the maximal supported level
    /// of the current context.
    ///@param[in] msg Input message
    ///@returns Encoded plaintext.
    ///@details Encode to the default encryption level.
    ///@throws RuntimeException if neither the size of the input message is
    /// a power of two, nor it exceeds one half of the ciphertext dimension of
    /// the current homomorphic encryption context.
    Plaintext encode(const Message &msg) const;

    ///@brief Encode a message into a plaintext at a certain level at a certain
    /// rescale counter, without performing NTT.
    ///@param[in] msg Input message.
    ///@param[in] level Target level to which the input \p msg is to be encoded.
    ///@param[in] r_counter Target rescale counter to which \p msg is to be
    /// encoded
    ///@returns Encoded plaintext.
    ///@throws RuntimeException if neither the size of the input message is
    /// a power of two, nor it exceeds one half of the ciphertext dimension of
    /// the current homomorphic encryption context.
    ///@throws RuntimeException if the target \p level exceeds the maximal
    /// level decided in the homomorphic encryption context.
    ///@throws RuntimeException if the target rescale counter exceeds the
    /// target \p level
    Plaintext encodeWithoutNTT(const Message &msg, u64 level,
                               int r_counter = 0) const;

    ///@brief Encode a message into a plaintext with the maximal supported level
    /// of the current context, without performing NTT.
    ///@param[in] msg Input message.
    ///@returns Encoded plaintext.
    ///@throws RuntimeException if neither the size of the input message is
    /// a power of two, nor it exceeds one half of the ciphertext dimension of
    /// the current homomorphic encryption context.
    Plaintext encodeWithoutNTT(const Message &msg) const;

    ///@brief Decode a plaintext into a message.
    ///@param[in] ptxt Input plaintext.
    ///@returns Decoded message.
    Message decode(const Plaintext &ptxt) const;

private:
    ///@brief A context with which the scheme is associated.
    const Context context_;
};
} // namespace HEaaN
