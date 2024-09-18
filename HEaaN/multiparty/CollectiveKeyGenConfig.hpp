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

#include "../HEaaNExport.hpp"
#include "../Integers.hpp"

namespace HEaaN {

/// @brief Configuration for collective key generation on which key to generate
struct HEAAN_API CollectiveKeyGenConfig {
    enum Type : uint32_t { Enc, Mult, Rot, Conj, SparseSecretEncapsulation };

    Type type;
    i64 rot_idx = 0;

    explicit CollectiveKeyGenConfig(CollectiveKeyGenConfig::Type type_input,
                                    i64 rot_idx_input = 0)
        : type(type_input), rot_idx(rot_idx_input) {}

    bool operator==(const CollectiveKeyGenConfig &other) const {
        if (type == Type::Rot)
            return type == other.type && rot_idx == other.rot_idx;
        return type == other.type;
    }
    bool operator!=(const CollectiveKeyGenConfig &other) const {
        return !(*this == other);
    }

    template <class Archive> void serialize(Archive &ar) { ar(type, rot_idx); }
};

} // namespace HEaaN
