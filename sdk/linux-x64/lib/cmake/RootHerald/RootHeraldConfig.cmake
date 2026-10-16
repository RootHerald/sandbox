# The archive links tpm2-tss and libcrypto from the system; resolve them
# through pkg-config, as the build did, and name the apt line when they are absent.
set(_rootherald_missing "")

find_package(PkgConfig QUIET)
if(NOT PKG_CONFIG_FOUND)
    list(APPEND _rootherald_missing pkg-config)
else()
    foreach(_rootherald_pair TSS2_ESYS:tss2-esys TSS2_TCTILDR:tss2-tctildr TSS2_MU:tss2-mu OPENSSL:libcrypto)
        string(REPLACE ":" ";" _rootherald_pair "${_rootherald_pair}")
        list(GET _rootherald_pair 0 _rootherald_name)
        list(GET _rootherald_pair 1 _rootherald_module)
        if(NOT TARGET PkgConfig::RootHerald_${_rootherald_name})
            pkg_check_modules(RootHerald_${_rootherald_name} QUIET IMPORTED_TARGET ${_rootherald_module})
        endif()
        if(NOT TARGET PkgConfig::RootHerald_${_rootherald_name})
            list(APPEND _rootherald_missing ${_rootherald_module})
        endif()
    endforeach()
endif()

if(_rootherald_missing)
    list(JOIN _rootherald_missing ", " _rootherald_missing)
    set(RootHerald_FOUND FALSE)
    set(RootHerald_NOT_FOUND_MESSAGE
        "missing ${_rootherald_missing}: apt install libtss2-dev libssl-dev pkg-config")
    unset(_rootherald_missing)
    return()
endif()
unset(_rootherald_missing)

include("${CMAKE_CURRENT_LIST_DIR}/RootHeraldTargets.cmake")
