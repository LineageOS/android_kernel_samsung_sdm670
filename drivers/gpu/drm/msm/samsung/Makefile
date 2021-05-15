ccflags-y := -Iinclude/drm -Idrivers/gpu/drm/msm -Idrivers/gpu/drm/msm/dsi-staging
ccflags-y += -Idrivers/gpu/drm/msm/sde
ccflags-y += -Idrivers/gpu/drm/msm/samsung

obj-y += ss_dsi_panel_sysfs.o
obj-y += ss_dsi_panel_debug.o
obj-y += ss_dsi_panel_common.o
obj-y += ss_dsi_mdnie_lite_common.o
obj-y += ss_dsi_smart_dimming_common.o
obj-y += ss_interpolation_common.o
obj-y += ss_flash_table_data_common.o
obj-y += ss_dpui_common.o

# obj-$(CONFIG_SAMSUNG_DEBUG_DISPLAY) += dlog.o
obj-$(CONFIG_SUPPORT_POC_FLASH) += ss_ddi_poc_common.o

# TO SUPPORT SPI INTERFACE
obj-y  += ss_ddi_spi_common.o

# COPR
obj-y += ss_copr_common.o

# Self Display
obj-y += SELF_DISPLAY/

#
# panel directory make file
#

# TO SUPPORT PBA BOOINT
obj-y += PBA_BOOTING/ss_dsi_panel_PBA_BOOTING_fhd.o
obj-y += PBA_BOOTING_DSI1/ss_dsi_panel_PBA_BOOTING_fhd_dsi1.o

# TAB S4 LV Panel
obj-$(CONFIG_PANEL_ANA38401_AMSA05RB01_WQXGA) += ANA38401_AMSA05RB01/
