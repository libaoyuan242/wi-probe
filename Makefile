include $(TOPDIR)/rules.mk

PKG_NAME:=wi-probe
PKG_RELEASE:=1
PKG_VERSION:=0.2
PKG_MAINTAINER:=Kyle F. Davies

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

define Package/wi-probe
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=wi-probe, generates and sends probe requests over a Wi-Fi interface
  MENU:=1
endef

define Package/wi-probe/description
  Allows probe requests to be broadcast using a wireless interface. It is
  is possible to specify the number of probes, the channels on which to
  transmit, and the transmit power.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
	$(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/wi-probe/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wi-probe $(1)/bin/
endef

$(eval $(call BuildPackage,wi-probe))
