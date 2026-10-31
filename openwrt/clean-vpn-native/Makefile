include $(TOPDIR)/rules.mk

PKG_NAME:=clean-vpn-native
PKG_VERSION:=0.0.0
PKG_RELEASE:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

# Local source-only SDK build. Dependencies are already pinned, patched public
# source caches; compile has no network and never downloads a replacement.
CMAKE_SOURCE_SUBDIR:=native/clean_vpn
CMAKE_BINARY_SUBDIR:=build
PKG_INSTALL:=
# Keep SDK fortify enabled, but classify its GNU include_next wrappers as
# system headers. Our own -Wpedantic/-Werror stays unchanged.
TARGET_CPPFLAGS += -isystem $(TOOLCHAIN_DIR)/include/fortify
CMAKE_OPTIONS += \
	-DCVPN_LOW_MEMORY_BUILD=ON \
	-DCMAKE_EXE_LINKER_FLAGS="$(TARGET_LDFLAGS) -static" \
	-DCMAKE_CXX_STANDARD_LIBRARIES="-lstdc++ -lgcc_eh" \
	-DFETCHCONTENT_FULLY_DISCONNECTED=ON \
	-DFETCHCONTENT_UPDATES_DISCONNECTED=ON \
	-DCVPN_BORINGSSL_SOURCE=$(CVPN_TLS_DEPS)/boringssl-src \
	-DCVPN_JSON_SOURCE=$(CVPN_TLS_DEPS)/json-src \
	-DFETCHCONTENT_SOURCE_DIR_BROTLI=$(CVPN_HTTP_DEPS)/brotli-src \
	-DFETCHCONTENT_SOURCE_DIR_NGHTTP2=$(CVPN_HTTP_DEPS)/nghttp2-src

define Package/clean-vpn-native
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Clean VPN native engine (local experimental package)
endef

define Package/clean-vpn-native/description
 Native engine and bounded cold TLS profiles. External provisioning and network
 ownership are required. Installation starts no service and changes no network,
 DNS or firewall settings. This package does not provide LuCI or a netifd/fw4
 adapter; kmod-tun is required for actual TUN operation.
endef

define Build/Prepare
	test -f "$(CVPN_NATIVE_SOURCE)/native/clean_vpn/engine.cc"
	test -d "$(CVPN_TLS_DEPS)/boringssl-src/.git"
	test -d "$(CVPN_HTTP_DEPS)/nghttp2-src/.git"
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(CVPN_NATIVE_SOURCE)/native $(PKG_BUILD_DIR)/
	$(CP) $(CVPN_NATIVE_SOURCE)/fixtures $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call Build/Compile/Default,clean-vpn-engine)
endef

define Package/clean-vpn-native/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/share/clean-vpn/profiles
	$(INSTALL_BIN) $(CMAKE_BINARY_DIR)/clean-vpn-engine $(1)/usr/sbin/clean-vpn-engine
	$(INSTALL_DATA) $(CVPN_NATIVE_SOURCE)/fixtures/native-tls-profiles/*.json $(1)/usr/share/clean-vpn/profiles/
	$(INSTALL_DIR) $(1)/usr/share/doc/clean-vpn-native
	$(INSTALL_DATA) $(CVPN_TLS_DEPS)/boringssl-src/LICENSE $(1)/usr/share/doc/clean-vpn-native/BoringSSL-LICENSE
	$(INSTALL_DATA) $(CVPN_HTTP_DEPS)/nghttp2-src/COPYING $(1)/usr/share/doc/clean-vpn-native/nghttp2-COPYING
	$(INSTALL_DATA) $(CVPN_HTTP_DEPS)/brotli-src/LICENSE $(1)/usr/share/doc/clean-vpn-native/Brotli-LICENSE
	$(INSTALL_DATA) $(CVPN_TLS_DEPS)/json-src/LICENSE.MIT $(1)/usr/share/doc/clean-vpn-native/json-LICENSE.MIT
endef

$(eval $(call BuildPackage,clean-vpn-native))
