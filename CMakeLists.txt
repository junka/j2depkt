cmake_minimum_required(VERSION 3.7.2)
project(j2depkt)

add_custom_command (
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser.c
    COMMAND peg -P ${CMAKE_CURRENT_SOURCE_DIR}/parser.peg -o ${CMAKE_CURRENT_SOURCE_DIR}/parser.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.peg
    COMMENT "generating parser.c..."
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_custom_target(parser DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.c)


add_library(depkt depktcap.c utils.c)
add_dependencies(depkt parser)

add_subdirectory(example/pcapfilter)
add_subdirectory(example/tcpdump)

enable_testing ()
add_subdirectory(tests)

install(FILES depktcap.h DESTINATION include)
install(TARGETS depkt DESTINATION lib)



if (HAS_DPDK)
    include(ExternalProject)
    ExternalProject_Add(
        DPDKSubproject
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dpdk
        BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/dpdk
        CONFIGURE_COMMAND meson setup ${CMAKE_CURRENT_SOURCE_DIR}/dpdk ${CMAKE_CURRENT_BINARY_DIR}/dpdk --default-library static --libdir lib -Dtests=false -Ddisable_drivers=dma/\*,baseband/\*,bus/dpaa,bus/ifpga,baseband/\*,common/cpt,common/qat,common/dpaax,common/iavf,common/octeontx,common/octeontx2,common/sfc_efx,compress/isal,compress/octeontx,compress/zlib,crypto/\*,raw/\*,regex/\*,event/\*,mempool/dpaa,net/failsafe,net/idpf,net/cpfl,net/gve,net/enetfec,net/octeon_ep,net/ngbe,net/ionic,net/af_packet,net/bnx2x,net/kni,net/fm10k,net/hns3,net/octeontx,net/cxgbe,net/octeontx2,net/atlantic,net/ark,net/null,net/ipn3ke,net/liquidio,net/pfe,net/sfc,net/softnic,net/thunderx,raw/ifpga,net/af_xdp,net/avp,net/txgbe,net/ring,net/dpaa,net/dpaa2,net/enic,net/nfp,net/i40e,net/igc,net/axgbe,net/e1000,net/ena,net/hinic,net/memif,net/netvsc,net/vdev_netvsc,net/vmxnet3,net/qede,vdpa/\*,net/mlx4 -Ddisable_libs=acl,bbdev,bitratestats,bpf,cfgfile,distributor,efd,fib,flow_classify,graph,gro,gso,jobstats,kni,latencystats,lpm,member,node,pipeline,port,power,rawdev,rib,table,eventdev,security,compressdev,cryptodev,dmadev,gpudev,mldev,regexdev,cmdline -Doptimization=3 -Ddebug=true -Dmachine=default --prefix=${CMAKE_CURRENT_BINARY_DIR}/install/
        BUILD_COMMAND meson compile -C ${CMAKE_CURRENT_BINARY_DIR}/dpdk
        INSTALL_COMMAND meson install
    )

    include_directories(CMAKE_CURRENT_BINARY_DIR}/install/include)
    add_library(depkt_dpdk dpdkrflow.c utils.c)
    add_dependencies(depkt_dpdk parser)
    add_dependencies(depkt_dpdk DPDKSubproject)
    add_subdirectory(example/dpdkflow)
    install(FILES dpdkrflow.h DESTINATION include)
    install(TARGETS depkt_dpdk DESTINATION lib)
endif(HAS_DPDK)
