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

#include <vector>

#include "HEaaNExport.hpp"
#include "KeyPack.hpp"
#include "Real.hpp"

namespace HEaaN {

class Message;
class Plaintext;
class Ciphertext;
class HomEvaluatorImpl;

///
///@brief A class consisting of basic operation of Ciphertext and Message
///
class HEAAN_API HomEvaluator {
    friend class BootstrapperImpl;

public:
    explicit HomEvaluator(const Context &context,
                          const std::string &key_dir_path);
    explicit HomEvaluator(const Context &context, const KeyPack &pack);

    ///@brief Negate a Message
    ///@param[in] msg
    ///@param[out] msg_out
    void negate(const Message &msg, Message &msg_out) const;
    ///@brief Negate a Plaintext
    ///@param[in] ptxt
    ///@param[out] ptxt_out
    void negate(const Plaintext &ptxt, Plaintext &ptxt_out) const;
    ///@brief Negate a Ciphertext
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    void negate(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;

    ///@brief Message + Complex Constant
    ///@param[in] msg1
    ///@param[in] cnst_complex
    ///@param[out] msg_out
    ///@details Add cnst_complex to each component of Message
    void add(const Message &msg1, const Complex &cnst_complex,
             Message &msg_out) const;
    ///@brief Message + Message
    ///@param[in] msg1
    ///@param[in] msg2
    ///@param[out] msg_out
    ///@details Add two Message component-wise
    ///@throws RuntimeException if msg1 and msg2 have the different size
    void add(const Message &msg1, const Message &msg2, Message &msg_out) const;
    ///@brief Plaintext + Complex Constant
    ///@param[in] ptxt1
    ///@param[in] cnst_complex
    ///@param[out] ptxt_out
    ///@details Add cnst_complex to each component of the message
    /// which Plaintext encodes
    ///@throws RuntimeException if ptxt1 has nonzero rescale counter.
    void add(const Plaintext &ptxt1, const Complex &cnst_complex,
             Plaintext &ptxt_out) const;
    ///@brief Plaintext + Plaintext
    ///@param[in] ptxt1
    ///@param[in] ptxt2
    ///@param[out] ptxt_out
    ///@throws RuntimeException if ptxt1 and ptxt2 have the different level
    /// or the different rescale counter
    void add(const Plaintext &ptxt1, const Plaintext &ptxt2,
             Plaintext &ptxt_out) const;
    ///@brief Ciphertext + Complex Constant
    ///@param[in] ctxt1
    ///@param[in] cnst_complex
    ///@param[out] ctxt_out
    ///@details Add cnst_complex to each component of the message
    /// which Ciphertext encrypts
    ///@throws RuntimeException if ctxt1 has nonzero rescale counter.
    void add(const Ciphertext &ctxt1, const Complex &cnst_complex,
             Ciphertext &ctxt_out) const;
    ///@brief Ciphertext + Message
    ///@param[in] ctxt1
    ///@param[in] msg2
    ///@param[out] ctxt_out
    ///@details Add msg2 to the message which ctxt1 encrypts. The result
    /// is a Ciphertext which encrypts the sum of those two messages.
    void add(const Ciphertext &ctxt1, const Message &msg2,
             Ciphertext &ctxt_out) const;
    ///@brief Ciphertext + Plaintext
    ///@param[in] ctxt1
    ///@param[in] ptxt2
    ///@param[out] ctxt_out
    ///@details Add Ciphertext and Plaintext.
    /// If the levels of ctxt1 and ptxt2 are different, we adjust the
    /// level.
    void add(const Ciphertext &ctxt1, const Plaintext &ptxt2,
             Ciphertext &ctxt_out) const;
    ///@brief Ciphertext + Ciphertext
    ///@param[in] ctxt1
    ///@param[in] ctxt2
    ///@param[out] ctxt_out
    ///@details Add two Ciphertext.
    /// If the levels of ctxt1 and ctxt2 are different, we adjust the
    /// level.
    ///@throws RuntimeException if ctxt1 and ctxt2 have the different
    /// rescale counter
    void add(const Ciphertext &ctxt1, const Ciphertext &ctxt2,
             Ciphertext &ctxt_out) const;

    ///@brief Message - Complex Constant
    ///@param[in] msg1
    ///@param[in] cnst_complex
    ///@param[out] msg_out
    ///@details Subtract cnst_complex from each component of Message
    void sub(const Message &msg1, const Complex &cnst_complex,
             Message &msg_out) const;
    ///@brief Message - Message
    ///@param[in] msg1
    ///@param[in] msg2
    ///@param[out] msg_out
    ///@details Subtract two Message component-wise
    ///@throws RuntimeException if msg1 and msg2 have the different size
    void sub(const Message &msg1, const Message &msg2, Message &msg_out) const;
    ///@brief Plaintext - Complex Constant
    ///@param[in] ptxt1
    ///@param[in] cnst_complex
    ///@param[out] ptxt_out
    ///@details Sub cnst_complex to each component of the message
    /// which Plaintext encodes
    ///@throws RuntimeException if ptxt1 has nonzero rescale counter.
    void sub(const Plaintext &ptxt1, const Complex &cnst_complex,
             Plaintext &ptxt_out) const;
    ///@brief Plaintext - Plaintext
    ///@param[in] ptxt1
    ///@param[in] ptxt2
    ///@param[out] ptxt_out
    ///@throws RuntimeException if ptxt1 and ptxt2 have the different level
    /// or the different rescale counter
    void sub(const Plaintext &ptxt1, const Plaintext &ptxt2,
             Plaintext &ptxt_out) const;
    ///@brief Ciphertext - Complex Constant
    ///@param[in] ctxt1
    ///@param[in] cnst_complex
    ///@param[out] ctxt_out
    ///@details Subtract cnst_complex from each slot of the message
    /// which Ciphertext encrypts
    ///@throws RuntimeException if ctxt1 has nonzero rescale counter.
    void sub(const Ciphertext &ctxt1, const Complex &cnst_complex,
             Ciphertext &ctxt_out) const;
    ///@brief Ciphertext - Message
    ///@param[in] ctxt1
    ///@param[in] msg2
    ///@param[out] ctxt_out
    ///@details Subtract msg2 from the message which ctxt1 encrypts
    /// The result is a Ciphertext which encrypts the difference of
    /// those two messages.
    void sub(const Ciphertext &ctxt1, const Message &msg2,
             Ciphertext &ctxt_out) const;
    ///@brief Ciphertext - Plaintext
    ///@param[in] ctxt1
    ///@param[in] ptxt2
    ///@param[out] ctxt_out
    ///@details Subtract ptxt2 from ctxt1.
    /// If the levels of ctxt1 and ptxt2 are different, we adjust the
    /// level.
    void sub(const Ciphertext &ctxt1, const Plaintext &ptxt2,
             Ciphertext &ctxt_out) const;
    ///@brief Ciphertext - Ciphertext
    ///@param[in] ctxt1
    ///@param[in] ctxt2
    ///@param[out] ctxt_out
    ///@details Subtract two Ciphertext.
    /// If the levels of ctxt1 and ctxt2 are different, we adjust the
    /// level.
    ///@throws RuntimeException if ctxt1 and ctxt2 have the different
    /// rescale counter
    void sub(const Ciphertext &ctxt1, const Ciphertext &ctxt2,
             Ciphertext &ctxt_out) const;

    ///@brief Message * Complex Constant
    ///@param[in] msg1
    ///@param[in] cnst_complex
    ///@param[out] msg_out
    ///@details Multiply cnst_complex to each component of Message
    void mult(const Message &msg1, const Complex &cnst_complex,
              Message &msg_out) const;
    ///@brief Message * Message
    ///@param[in] msg1
    ///@param[in] msg2
    ///@param[out] msg_out
    ///@details Multiply two Message component-wise
    ///@throws RuntimeException if msg1 and msg2 have the different size
    void mult(const Message &msg1, const Message &msg2, Message &msg_out) const;
    ///@brief Plaintext * Plaintext
    ///@param[in] ptxt1
    ///@param[in] ptxt2
    ///@param[out] ptxt_out
    ///@details Multiply two Plaintext.
    ///@throws RuntimeException if any of the input operands has nonzero rescale
    /// counter.
    void mult(const Plaintext &ptxt1, const Plaintext &ptxt2,
              Plaintext &ptxt_out) const;
    ///@brief Plaintext * Complex Constant
    ///@param[in] ptxt1
    ///@param[in] cnst_complex
    ///@param[out] ptxt_out
    ///@details Multiply cnst_complex to each component of the message
    /// which Plaintext encodes
    ///@throws RuntimeException if ptxt1 has nonzero rescale counter.
    void mult(const Plaintext &ptxt1, const Complex &cnst_complex,
              Plaintext &ptxt_out) const;
    ///@brief Ciphertext * Complex Constant
    ///@param[in] ctxt1
    ///@param[in] cnst_complex
    ///@param[out] ctxt_out
    ///@details Multiply cnst_complex to each component of the message
    /// which Ciphertext encrypts. Note that if the input `cnst_complex` is
    /// sufficiently close to a Gaussian integer (i.e. a complex number with
    /// integer real and imaginary parts), then the multiplication will take
    /// place via `multInteger`, i.e. without any depth consumption. More
    /// precisely, "sufficiently close" here means that the absolute value of
    /// the difference of the real (resp. imaginary) part with its closest
    /// integer is less than or equal to 1e-8.
    ///@throws RuntimeException if ctxt1 has nonzero rescale counter.
    void mult(const Ciphertext &ctxt1, const Complex &cnst_complex,
              Ciphertext &ctxt_out) const;
    ///@brief Ciphertext * Message
    ///@param[in] ctxt1
    ///@param[in] msg2
    ///@param[out] ctxt_out
    ///@details Multiply msg2 to the message which ctxt1 encrypts
    /// The result is a Ciphertext which encrypts the product of those
    /// two messages.
    ///@throws RuntimeException if ctxt1 has nonzero rescale counter.
    void mult(const Ciphertext &ctxt1, const Message &msg2,
              Ciphertext &ctxt_out) const;
    ///@brief Ciphertext * Plaintext
    ///@param[in] ctxt1
    ///@param[in] ptxt2
    ///@param[out] ctxt_out
    ///@details Multiply Ciphertext and Plaintext.
    /// If the levels of ctxt1 and ptxt2 are different, we adjust the
    /// level.
    ///@throws RuntimeException if any of the input operands has nonzero rescale
    /// counter.
    void mult(const Ciphertext &ctxt1, const Plaintext &ptxt2,
              Ciphertext &ctxt_out) const;
    ///@brief Ciphertext * Ciphertext
    ///@param[in] ctxt1
    ///@param[in] ctxt2
    ///@param[out] ctxt_out
    ///@details Multiply two Ciphertext.
    /// If the levels of ctxt1 and ctxt2 are different, we adjust the
    /// level.
    ///@throws RuntimeException if any of the input operands has nonzero rescale
    /// counter.
    void mult(const Ciphertext &ctxt1, const Ciphertext &ctxt2,
              Ciphertext &ctxt_out) const;

    ///@brief multiply a Message by the imaginary unit √(-1)
    ///@param[in] msg
    ///@param[out] msg_out
    void multImagUnit(const Message &msg, Message &msg_out) const;
    ///@brief multiply a Plaintext by the imaginary unit √(-1)
    ///@param[in] ptxt
    ///@param[out] ptxt_out
    void multImagUnit(const Plaintext &ptxt, Plaintext &ptxt_out) const;
    ///@brief multiply a Ciphertext by the imaginary unit √(-1)
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    void multImagUnit(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;

    ///@brief Plaintext * Positive Integer
    ///@param[in] ptxt
    ///@param[in] cnst_integer
    ///@param[out] ptxt_out
    void multInteger(const Plaintext &ptxt, u64 cnst_integer,
                     Plaintext &ptxt_out) const;

    ///@brief Ciphertext * Positive Integer
    ///@param[in] ctxt
    ///@param[in] cnst_integer
    ///@param[out] ctxt_out
    void multInteger(const Ciphertext &ctxt, u64 cnst_integer,
                     Ciphertext &ctxt_out) const;

    ///@brief Compute the square of a Message
    ///@param[in] msg
    ///@param[out] msg_out
    void square(const Message &msg, Message &msg_out) const;

    ///@brief Compute the square of a Plaintext
    ///@param[in] ptxt
    ///@param[out] ptxt_out
    void square(const Plaintext &ptxt, Plaintext &ptxt_out) const;

    ///@brief Compute the square of a Ciphertext
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    void square(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;

    ///@brief Rotate components of Message by rot
    ///@param[in] msg
    ///@param[in] rot
    ///@param[out] msg_out
    ///@details (m_0, m_1, ...) -> (m_r, m_r+1, ...)
    void leftRotate(const Message &msg, u64 rot, Message &msg_out) const;
    ///@brief Rotate components of the message which Plaintext encodes by rot
    ///@param[in] ptxt
    ///@param[in] rot
    ///@param[out] ptxt_out
    ///@details (m_0, m_1, ...) -> (m_r, m_r+1, ...)
    void leftRotate(const Plaintext &ptxt, u64 rot, Plaintext &ptxt_out) const;

    ///@brief Rotate components of the message which Ciphertext encrypts by rot
    ///@param[in] ctxt
    ///@param[in] rot
    ///@param[out] ctxt_out
    ///@details (m_0, m_1, ...) -> (m_r, m_r+1, ...)
    void leftRotate(const Ciphertext &ctxt, u64 rot,
                    Ciphertext &ctxt_out) const;

    ///@brief Rotate components of Message by rot
    ///@param[in] msg
    ///@param[in] rot
    ///@param[out] msg_out
    ///@details (m_0, m_1, ...) -> (..., m_0, m_1, ...)
    void rightRotate(const Message &msg, u64 rot, Message &msg_out) const;
    ///@brief Rotate components of the message which Ciphertext encrypts by rot
    ///@param[in] ptxt
    ///@param[in] rot
    ///@param[out] ptxt_out
    ///@details (m_0, m_1, ...) -> (..., m_0, m_1, ...)
    void rightRotate(const Plaintext &ptxt, u64 rot, Plaintext &ptxt_out) const;
    ///@brief Rotate components of the message which Ciphertext encrypts by rot
    ///@param[in] ctxt
    ///@param[in] rot
    ///@param[out] ctxt_out
    ///@details (m_0, m_1, ...) -> (..., m_0, m_1, ...)
    void rightRotate(const Ciphertext &ctxt, u64 rot,
                     Ciphertext &ctxt_out) const;

    ///@brief Compute Σ rot_i (ctxt_i)
    ///@param[in] ctxt
    ///@param[in] rot_idx
    ///@param[out] ctxt_out
    ///@details We suppose that all Ciphertext have the same level
    void rotSum(const std::vector<Ciphertext> &ctxt,
                const std::vector<u64> &rot_idx, Ciphertext &ctxt_out) const;

    ///@brief Compute left Rotate Reduce of Message
    ///@param[in] msg
    ///@param[in] idx_interval
    ///@param[in] num_summation
    ///@param[out] msg_out
    ///@details \f$ \sum_{idx} leftRotate(msg, idx) \f$
    /// where \f$ {idx} \f$ = {0, i, ..., (n-1) * i},
    /// i = idx_interval and n = num_summation
    void leftRotateReduce(const Message &msg, const u64 &idx_interval,
                          const u64 &num_summation, Message &msg_out) const;
    ///@brief Compute right Rotate Reduce of Message
    ///@param[in] msg
    ///@param[in] idx_interval
    ///@param[in] num_summation
    ///@param[out] msg_out
    ///@details \f$ \sum_{idx} rightRotate(msg, idx) \f$
    /// where \f$ {idx} \f$ = {0, i, ..., (n-1) * i},
    /// i = idx_interval and n = num_summation.
    void rightRotateReduce(const Message &msg, const u64 &idx_interval,
                           const u64 &num_summation, Message &msg_out) const;
    ///@brief Compute left Rotate Reduce of Ciphertext
    ///@param[in] ctxt
    ///@param[in] idx_interval
    ///@param[in] num_summation
    ///@param[out] ctxt_out
    ///@details \f$ \sum_{idx} leftRotate(ctxt, idx) \f$
    /// where \f$ {idx} \f$ = {0, i, ..., (n-1) * i},
    /// i = idx_interval and n = num_summation.
    void leftRotateReduce(const Ciphertext &ctxt, const u64 &idx_interval,
                          const u64 &num_summation, Ciphertext &ctxt_out) const;
    ///@brief Compute right Rotate Reduce of Ciphertext
    ///@param[in] ctxt
    ///@param[in] idx_interval
    ///@param[in] num_summation
    ///@param[out] ctxt_out
    ///@details \f$ \sum_{idx} rightRotate(ctxt, idx) \f$
    /// where \f$ {idx} \f$ = {0, i, ..., (n-1) * i},
    /// i = idx_interval and n = num_summation.
    void rightRotateReduce(const Ciphertext &ctxt, const u64 &idx_interval,
                           const u64 &num_summation,
                           Ciphertext &ctxt_out) const;
    ///@brief Compute complex conjugate a Message component-wise
    ///@param[in] msg
    ///@param[out] msg_out
    void conjugate(const Message &msg, Message &msg_out) const;
    ///@brief Compute complex conjugate the message ptxt encodes
    ///@param[in] ptxt
    ///@param[out] ptxt_out
    void conjugate(const Plaintext &ptxt, Plaintext &ptxt_out) const;
    ///@brief Compute complex conjugate the message ctxt encrypts
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    void conjugate(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;
    ///@brief Get the real part of the message which ctxt encrypts
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    void killImag(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;

    ///@brief Multiply Ciphertext by a complex constant
    ///@param[in] ctxt1
    ///@param[in] cnst_complex
    ///@param[out] ctxt_out
    ///@details There are no memory check.
    void multWithoutRescale(const Ciphertext &ctxt1,
                            const Complex &cnst_complex,
                            Ciphertext &ctxt_out) const;
    ///@brief Multiply Ciphertext and Plaintext
    ///@param[in] ctxt1
    ///@param[in] ptxt2
    ///@param[out] ctxt_out
    ///@details There are no memory check.
    /// You should perform the rescale function.
    ///@throws RuntimeException if ctxt1 and ptxt2 must have the different level
    ///@throws RuntimeException if any of the input operands has nonzero rescale
    /// counter.
    void multWithoutRescale(const Ciphertext &ctxt1, const Plaintext &ptxt2,
                            Ciphertext &ctxt_out) const;
    ///@brief Multiply two Ciphertext
    ///@param[in] ctxt1
    ///@param[in] ctxt2
    ///@param[out] ctxt_out
    ///@details There are no memory check.
    /// You should perform the rescale function.
    ///@throws RuntimeException if ctxt1 and ctxt2 have the different level
    ///@throws RuntimeException if any of the input operands has nonzero rescale
    /// counter.
    void multWithoutRescale(const Ciphertext &ctxt1, const Ciphertext &ctxt2,
                            Ciphertext &ctxt_out) const;

    ///@brief Compute (a1b2 + a2b1, b1b2, a1a2)
    ///@param[in] ctxt1
    ///@param[in] ctxt2
    ///@param[out] ctxt_out
    ///@details ctxt_out.getPoly(1) = ctxt1.getPoly(1) * ctxt2.getPoly(0) +
    /// ctxt2.getPoly(1) *
    /// ctxt1.getPoly(0),
    ///  ctxt_out.getPoly(0) = ctxt1.getPoly(0) * ctxt2.getPoly(0),
    ///  ctxt_out.getPoly(2) = ctxt1.getPoly(1) * ctxt2.getPoly(1)
    ///@throws RuntimeException if ctxt1 and ctxt2 have the different level
    ///@throws RuntimeException if any of the input operands has nonzero rescale
    /// counter.
    void tensor(const Ciphertext &ctxt1, const Ciphertext &ctxt2,
                Ciphertext &ctxt_out) const;
    ///@brief Mult relinearization key
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    ///@details This is the latter part of multWithoutRescale function.
    void relinearize(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;

    ///@brief Divide a Plaintext by the scale factor
    ///@param[in, out] ptxt
    ///@details It transforms a plaintext of a level ℓ encoding a message m
    /// into a plaintext of level ℓ-1 encoding the message {q_ℓ}^{-1} m.
    ///@throws RuntimeException if ptxt has nonzero rescale counter.
    void rescale(Plaintext &ptxt) const;

    ///@brief Divide a Ciphertext by the scale factor
    ///@param[in, out] ctxt
    ///@details It transforms a ciphertext of a level ℓ encrypting a message m
    /// into a ciphertext of level ℓ-1 encrypting the message {q_ℓ}^{-1} m.
    ///@throws RuntimeException if ctxt has nonzero rescale counter.
    void rescale(Ciphertext &ctxt) const;

    ///@brief Increase one level and multiply the prime at current level + 1.
    ///@param[in, out] ptxt
    ///@details It transforms a plaintext of a level ℓ encoding a message m
    /// into a plaintext of level ℓ+1 encoding the message {q_{ℓ+1}} m. The
    /// rescale counter is increased by 1 after this operation. When you
    /// encrypt, you can put inverseRescale before encryption to reduce the
    /// encryption error. Also, inverseRescale can be used to match the rescale
    /// counter and level of two plaintexts.
    ///@throws RuntimeException if the level of a plaintext is greater than or
    /// equal to the maximum level.
    void inverseRescale(Plaintext &ptxt) const;

    ///@brief Increase one level and multiply the prime at current level + 1.
    ///@param[in, out] ctxt
    ///@details It transforms a ciphetext of a level ℓ encrypting a message m
    /// into a ciphertext of level ℓ+1 encrypting the message {q_{ℓ+1}} m. The
    /// rescale counter is increased by 1 after this operation. When you
    /// rotate/conjugate, you can put inverseRescale and rescale before
    /// and after such operation to reduce the error of the operation. Also,
    /// inverseRescale can be used to match the rescale counter and level of two
    /// ciphertexts.
    ///@throws RuntimeException if the level of a ciphertext is greater than or
    /// equal to the maximum level.
    void inverseRescale(Ciphertext &ctxt) const;

    ///@brief Decrease the level of Ciphertext
    ///@param[in] ctxt
    ///@param[in] target_level
    ///@param[out] ctxt_out
    ///@throws RuntimeException if target_level is greater than level of ctxt
    ///@throws RuntimeException if ctxt has nonzero rescale counter.
    void levelDown(const Ciphertext &ctxt, u64 target_level,
                   Ciphertext &ctxt_out) const;
    ///@brief Decrease the level of Ciphertext by one
    ///@param[in] ctxt
    ///@param[out] ctxt_out
    ///@throws RuntimeException if level of ctxt is zero
    ///@throws RuntimeException if ctxt has nonzero rescale counter.
    void levelDownOne(const Ciphertext &ctxt, Ciphertext &ctxt_out) const;

    ///@brief Adjust the level of plaintext
    ///@param[in] ptxt Input plaintext
    ///@param[in] target_level Target level
    ///@param[out] ptxt_out
    ///@throws RuntimeException if target_level exceeds `context->getMaxLevel()`
    void relevel(const Plaintext &ptxt, const u64 target_level,
                 Plaintext &ptxt_out) const;

    ///@brief Get the internal Context object.
    ///@returns The context object required.
    const Context &getContext() const { return context_; }

private:
    ///@brief A context with which HomEvaluator is associated
    const Context context_;
    ///@brief Internal implementation object
    std::shared_ptr<HomEvaluatorImpl> impl_;
};
} // namespace HEaaN
