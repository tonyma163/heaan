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

#include "../multiparty/CollectiveKeyGenConfig.hpp"
#include "../multiparty/CollectiveKeyGenData.hpp"

#include <memory>

namespace HEaaN {

class CollectiveKeyGeneratorImpl;
class SecretKey;
class KeyPack;
class EncryptionKey;
class EvaluationKey;
class SparseSecretEncapsulationKey;

///
///@brief A class generating public keys from secret keys provided
/// by multiple parties
///@details Generate collectively known public key for encryption /
/// multiplication / conjugation / rotation / sparse secret encapsulation. The
/// class member functions should be performed in sequential order.
///
class HEAAN_API CollectiveKeyGenerator {
public:
    /// @brief Construct a `CollectiveKeyGenerator` object with a given context
    explicit CollectiveKeyGenerator(const Context &context);

    /// @brief Construct a module for generating collective key including keys
    /// for sparse secret encapsulation for the given context
    /// @throws RuntimeException if context_sparse is not a context constructed
    /// with the corresponding sparse parameter of which constructed context.
    /// Please refer to getSparseParameterPresetFor() on ParameterPreset.hpp
    /// for the sparse parameters.
    explicit CollectiveKeyGenerator(const Context &context,
                                    const Context &context_sparse);

    /// @brief Generate a random data to be shared among parties for
    /// collective key generation
    /// @param[in] config Configuration representing the key type for which
    /// collective key generated.
    /// @returns Returns a random data which can be used to generate key share
    /// in genKeyShare().
    CollectiveKeyGenData
    genCommonRandomData(const CollectiveKeyGenConfig &config) const;

    /// @brief Generate key share, the data which can be aggregated to
    /// generate collective key for encryption / conjugation / rotation / sparse
    /// secret encapsulation
    /// @param[in] sk Secret key
    /// @param[in] crd Common random data obtained from @ref
    /// genCommonRandomData().
    /// @returns Returns key share for the same key for which @p crd was
    /// generated. key shares are aggregated by aggregateKeyShare().
    CollectiveKeyGenData genKeyShare(const SecretKey &sk,
                                     const CollectiveKeyGenData &crd) const;

    /// @brief Aggregate key share from each party
    /// @param[in] parts a vector of key shares obtained from genKeyShare().
    /// @throws RuntimeException if all the parts is not created to generate the
    /// same key.
    /// @returns Returns aggregated key share for the same key for which @p
    /// parts were generated. aggregated key share is used to generate
    /// collective key in genAndSaveCollectiveKey().
    /// @details As computation which is performed on this function is addition,
    /// user may eagerly evaluate aggregation when only a subset of required
    /// CollectiveKeyGenData are prepared, as below :
    /// auto aggregated_part_AB = aggregateKeyShare({&part_A, &part_B});
    /// auto aggregated_part_ABC = aggregateKeyShare({&aggregated_part_AB,
    /// &part_C});
    CollectiveKeyGenData aggregateKeyShare(
        const std::vector<const CollectiveKeyGenData *> &parts) const;

    /// @brief Perform round one for collective mult(relinearization) key
    /// generation
    /// @param[in] sk Secret key
    /// @param[in] tmp_sk
    /// @param[in] crd Common random data obtained from
    /// genCommonRandomData().
    /// @throws RuntimeException if @p crd is not generated for multiplication
    /// key
    /// @returns Returned data is used in genMultKeyShareRoundTwo().
    CollectiveKeyGenData
    genMultKeyShareRoundOne(const SecretKey &sk, const SecretKey &tmp_sk,
                            const CollectiveKeyGenData &crd) const;

    /// @brief Perform round two for collective mult(relinearization) key
    /// generation
    /// @param[in] sk Secret key
    /// @param[in] tmp_sk
    /// @param[in] data_round_one Returned data from genMultKeyShareRoundOne().
    /// @throws RuntimeException if @p data_round_one is not generated for
    /// multiplication key
    /// @returns Returned data is used to generate collective key in
    /// genAndSaveCollectiveMultKey().
    CollectiveKeyGenData
    genMultKeyShareRoundTwo(const SecretKey &sk, const SecretKey &tmp_sk,
                            const CollectiveKeyGenData &data_round_one) const;

    /// @brief Collectively generate key for encryption
    /// @param[in] crd Common random data obtained from
    /// genCommonRandomData().
    /// @param[in] agg aggregated key share obtained from aggregateKeyShare().
    /// @throws RuntimeException if @p crd or @p agg are not created to
    /// generate encryption key
    std::shared_ptr<EncryptionKey>
    genEncKey(const CollectiveKeyGenData &crd,
              const CollectiveKeyGenData &agg) const;

    /// @brief Collectively generate key for conjugation
    /// @param[in] crd Common random data obtained from
    /// genCommonRandomData().
    /// @param[in] agg aggregated key share obtained from aggregateKeyShare().
    /// @throws RuntimeException if @p crd or @p agg are not created to generate
    /// conjugation key
    std::shared_ptr<EvaluationKey>
    genConjKey(const CollectiveKeyGenData &crd,
               const CollectiveKeyGenData &agg) const;

    /// @brief Collectively generate key for rotation
    /// @param[in] crd Common random data obtained from
    /// genCommonRandomData().
    /// @param[in] agg aggregated key share obtained from aggregateKeyShare().
    /// @throws RuntimeException if @p crd or @p agg are not created to generate
    /// rotation key
    std::shared_ptr<EvaluationKey>
    genRotKey(const CollectiveKeyGenData &crd,
              const CollectiveKeyGenData &agg) const;

    /// @brief Collectively generate key for multiplication
    /// @param[in] data_round_one Returned data from genMultKeyShareRoundOne().
    /// @param[in] data_round_two Returned data from genMultKeyShareRoundTwo().
    /// @throws RuntimeException if @p data_round_one or @p data_round_two are
    /// not created to generate multiplication key
    std::shared_ptr<EvaluationKey>
    genMultKey(const CollectiveKeyGenData &data_round_one,
               const CollectiveKeyGenData &data_round_two) const;

    /// @brief Collectively generate key for sparse secret encapsulation
    /// @param[in] crd Common random data obtained from
    /// genCommonRandomData().
    /// @param[in] agg aggregated key share obtained from aggregateKeyShare().
    /// @throws RuntimeException if @p crd or @p agg are not created to generate
    /// sparse secret encapsulation key
    std::shared_ptr<SparseSecretEncapsulationKey>
    genSparseSecretEncapsulationKey(const CollectiveKeyGenData &crd,
                                    const CollectiveKeyGenData &agg) const;

private:
    std::shared_ptr<CollectiveKeyGeneratorImpl> impl_;
};
} // namespace HEaaN
