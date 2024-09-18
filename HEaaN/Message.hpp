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

#include <iterator>
#include <vector>

#include "HEaaNExport.hpp"
#include "Integers.hpp"
#include "Pointer.hpp"
#include "Real.hpp"
#include "device/Device.hpp"

namespace HEaaN {
///
///@brief A class consists of complex messages which correspond to plaintexts.
///@details Each slot value, which is a complex number, should have a real and
/// imaginary number whose absolute values are less than 2^64. Otherwise, it is
/// undefined behavior.
///
class MessageImpl;
class HEAAN_API Message {
public:
    using MessageIterator = Complex *;
    using ConstMessageIterator = const Complex *;

    Message();

    ///@brief Create an uninitialized message.
    ///@param[in] log_slots The number of log(slots).
    ///@details A message which has two to \p log_slots slots is constructed.
    /// Because each slot, which is a complex number, is not initialized, you
    /// have to fill them by yourself.
    explicit Message(u64 log_slots);

    ///@brief Create a message filled with a given value.
    ///@param[in] log_slots The number of log(slots).
    ///@param[in] initial The value of each slot.
    ///@details A message which has two to \p log_slots slots whose values are
    /// \p initial is constructed..
    explicit Message(u64 log_slots, Complex initial);

    Complex &operator[](u64 idx);

    const Complex &operator[](u64 idx) const;

    ///@brief Determine whether the message is empty or not.
    ///@returns true if the message is empty, false otherwise
    bool isEmpty() const;

    ///@brief Get log(number of slots) of a message
    ///@returns log(number of slots)
    u64 getLogSlots() const;

    u64 getSize() const;

    void resize(u64 size);

    MessageIterator begin() noexcept;

    ConstMessageIterator begin() const noexcept;

    MessageIterator end() noexcept;

    ConstMessageIterator end() const noexcept;

    auto rbegin() { return std::reverse_iterator(end()); }

    auto rbegin() const { return std::reverse_iterator(end()); }

    auto rend() { return std::reverse_iterator(begin()); }

    auto rend() const { return std::reverse_iterator(begin()); }

    template <class Archive> void serialize(Archive &ar);

    void to(const Device &device);

    void allocate(const Device &device);

    const Device &getDevice() const;

    void save(const std::string &path) const;

    void save(std::ostream &stream) const;

    void load(const std::string &path);

    void load(std::istream &stream);

private:
    Pointer<MessageImpl> impl_;
};
} // namespace HEaaN
