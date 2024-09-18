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

#include "HEaaNExport.hpp"
#include <stdexcept>

namespace HEaaN {

class HEAAN_API RuntimeException : public std::runtime_error {
    using Base = std::runtime_error;

public:
    using Base::Base;
};

} // namespace HEaaN
