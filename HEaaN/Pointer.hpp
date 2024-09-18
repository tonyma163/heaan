////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2023 Crypto Lab Inc. //
//                                                                            //
// - This file is part of HEaaN homomorphic encryption library.               //
// - HEaaN cannot be copied and/or distributed without the express permission //
//  of Crypto Lab Inc.                                                        //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "HEaaNExport.hpp"
#include <memory>

namespace HEaaN {
///
///@brief A class holding unique_ptr but is copied with deepcopy.
///@details This class helps implementing PIMPL idiom. Include `Pointer.tpp` in
/// implementation files and instantiate the forward decl-ed class at there like
/// `template class Pointer<Impl>;`.
///
template <class T> class HEAAN_API Pointer {

private:
    std::unique_ptr<T> ptr_;

public:
    template <class... U> Pointer(U &&...args);

    ~Pointer();

    Pointer(Pointer const &other);
    Pointer(Pointer &&other) noexcept;

    Pointer &operator=(const Pointer &other);
    Pointer &operator=(Pointer &&other) noexcept;

    T &operator*();
    T *operator->();

    T const &operator*() const;
    T const *operator->() const;
};

class PlaintextImpl;
extern template class HEAAN_API Pointer<PlaintextImpl>;

class CiphertextImpl;
extern template class HEAAN_API Pointer<CiphertextImpl>;

class MessageImpl;
extern template class HEAAN_API Pointer<MessageImpl>;

class SecretKeyImpl;
extern template class HEAAN_API Pointer<SecretKeyImpl>;

class CollectiveKeyGenDataImpl;
extern template class HEAAN_API Pointer<CollectiveKeyGenDataImpl>;

} // namespace HEaaN
