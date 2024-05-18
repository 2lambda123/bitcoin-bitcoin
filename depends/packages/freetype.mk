package=freetype
$(package)_version=2.13.2
$(package)_download_path=https://download.savannah.gnu.org/releases/$(package)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=12991c4e55c506dd7f9b765933e62fd2be2e06d421505d7950a132e4f1bb484d
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts := -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=true
  $(package)_config_opts += -DFT_DISABLE_ZLIB=ON -DFT_DISABLE_PNG=ON
  $(package)_config_opts += -DFT_DISABLE_HARFBUZZ=ON -DFT_DISABLE_BZIP2=ON
  $(package)_config_opts += -DFT_DISABLE_BROTLI=ON
  $(package)_config_opts_debug := -DCMAKE_BUILD_TYPE=Debug
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share/man
endef
