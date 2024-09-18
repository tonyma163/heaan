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

#include "../Context.hpp"
#include "../HEaaNExport.hpp"
#include "../Pointer.hpp"
#include "../multiparty/CollectiveKeyGenConfig.hpp"

namespace HEaaN {
class CollectiveKeyGenDataImpl;
class Polynomial;

///
///@brief A class to describe data being transfered between parties
/// on the process of generating public keys from secret keys provided
/// by multiple parties
///
class HEAAN_API CollectiveKeyGenData {
public:
    /// @brief Create a container for data to be transacted during the process
    /// of collective key generation
    /// @param[in] config CollectiveKeyGenConfig object describing which key to
    /// generate
    CollectiveKeyGenData(const CollectiveKeyGenConfig &config);

    /// @brief Get configuration describing which key to generate
    const CollectiveKeyGenConfig &getConfig() const;

    /// @brief Save the data into a stream
    void save(std::ostream &stream) const;

    /// @brief Load the data from a stream
    void load(std::istream &stream);

    /// @brief Allocate polynomials at the back of the data
    /// @details This API is for manipulation of its content inside
    /// CollectiveKeyGenerator.
    void emplacePoly(const Context &context, bool is_extended,
                     u64 num_poly = 1);

    /// @brief Get number of polynomials
    /// @details This API is for manipulation of its content inside
    /// CollectiveKeyGenerator.
    u64 getSize() const;

    /// @brief Get the iterator to iterate through polynomials in
    /// CollectiveKeyGenData
    /// @details This API is for manipulation of its content inside
    /// CollectiveKeyGenerator.
    std::vector<Polynomial>::const_iterator getPolyIter() const;
    std::vector<Polynomial>::iterator getPolyIter();

private:
    Pointer<CollectiveKeyGenDataImpl> impl_;
};

} // namespace HEaaN
