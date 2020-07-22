/*
 * Copyright (c) 2017-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt)	"[drm-dp] %s: " fmt, __func__

#include <drm/drm_atomic_helper.h>
#include <drm/drm_atomic.h>
#include <drm/drm_crtc.h>

#include "msm_drv.h"
#include "msm_kms.h"
#include "sde_connector.h"
#include "dp_drm.h"
#include "dp_debug.h"
#ifdef CONFIG_SEC_DISPLAYPORT
#include "secdp.h"
#endif

#define to_dp_bridge(x)     container_of((x), struct dp_bridge, base)

static void convert_to_dp_mode(const struct drm_display_mode *drm_mode,
			struct dp_display_mode *dp_mode, struct dp_display *dp)
{
	memset(dp_mode, 0, sizeof(*dp_mode));

	dp_mode->timing.h_active = drm_mode->hdisplay;
	dp_mode->timing.h_back_porch = drm_mode->htotal - drm_mode->hsync_end;
	dp_mode->timing.h_sync_width = drm_mode->htotal -
			(drm_mode->hsync_start + dp_mode->timing.h_back_porch);
	dp_mode->timing.h_front_porch = drm_mode->hsync_start -
					 drm_mode->hdisplay;
	dp_mode->timing.h_skew = drm_mode->hskew;

	dp_mode->timing.v_active = drm_mode->vdisplay;
	dp_mode->timing.v_back_porch = drm_mode->vtotal - drm_mode->vsync_end;
	dp_mode->timing.v_sync_width = drm_mode->vtotal -
		(drm_mode->vsync_start + dp_mode->timing.v_back_porch);

	dp_mode->timing.v_front_porch = drm_mode->vsync_start -
					 drm_mode->vdisplay;

	dp_mode->timing.refresh_rate = drm_mode->vrefresh;

	dp_mode->timing.pixel_clk_khz = drm_mode->clock;

	dp_mode->timing.v_active_low =
		!!(drm_mode->flags & DRM_MODE_FLAG_NVSYNC);

	dp_mode->timing.h_active_low =
		!!(drm_mode->flags & DRM_MODE_FLAG_NHSYNC);
}

static void convert_to_drm_mode(const struct dp_display_mode *dp_mode,
				struct drm_display_mode *drm_mode)
{
	u32 flags = 0;

	memset(drm_mode, 0, sizeof(*drm_mode));

	drm_mode->hdisplay = dp_mode->timing.h_active;
	drm_mode->hsync_start = drm_mode->hdisplay +
				dp_mode->timing.h_front_porch;
	drm_mode->hsync_end = drm_mode->hsync_start +
			      dp_mode->timing.h_sync_width;
	drm_mode->htotal = drm_mode->hsync_end + dp_mode->timing.h_back_porch;
	drm_mode->hskew = dp_mode->timing.h_skew;

	drm_mode->vdisplay = dp_mode->timing.v_active;
	drm_mode->vsync_start = drm_mode->vdisplay +
				dp_mode->timing.v_front_porch;
	drm_mode->vsync_end = drm_mode->vsync_start +
			      dp_mode->timing.v_sync_width;
	drm_mode->vtotal = drm_mode->vsync_end + dp_mode->timing.v_back_porch;

	drm_mode->vrefresh = dp_mode->timing.refresh_rate;
	drm_mode->clock = dp_mode->timing.pixel_clk_khz;

	if (dp_mode->timing.h_active_low)
		flags |= DRM_MODE_FLAG_NHSYNC;
	else
		flags |= DRM_MODE_FLAG_PHSYNC;

	if (dp_mode->timing.v_active_low)
		flags |= DRM_MODE_FLAG_NVSYNC;
	else
		flags |= DRM_MODE_FLAG_PVSYNC;

	drm_mode->flags = flags;

	drm_mode->type = 0x48;
	drm_mode_set_name(drm_mode);
}

static int dp_bridge_attach(struct drm_bridge *dp_bridge)
{
	struct dp_bridge *bridge = to_dp_bridge(dp_bridge);

	if (!dp_bridge) {
		pr_err("Invalid params\n");
		return -EINVAL;
	}

	pr_debug("[%d] attached\n", bridge->id);

	return 0;
}

static void dp_bridge_pre_enable(struct drm_bridge *drm_bridge)
{
	int rc = 0;
	struct dp_bridge *bridge;
	struct dp_display *dp;

	if (!drm_bridge) {
		pr_err("Invalid params\n");
		return;
	}

	pr_debug("+++\n");

	bridge = to_dp_bridge(drm_bridge);
	dp = bridge->display;

	/* By this point mode should have been validated through mode_fixup */
	rc = dp->set_mode(dp, &bridge->dp_mode);
	if (rc) {
		pr_err("[%d] failed to perform a mode set, rc=%d\n",
		       bridge->id, rc);
		return;
	}

	rc = dp->prepare(dp);
	if (rc) {
		pr_err("[%d] DP display prepare failed, rc=%d\n",
		       bridge->id, rc);
		return;
	}

	rc = dp->enable(dp);
	if (rc) {
		pr_err("[%d] DP display enable failed, rc=%d\n",
		       bridge->id, rc);
		dp->unprepare(dp);
	}
}

static void dp_bridge_enable(struct drm_bridge *drm_bridge)
{
	int rc = 0;
	struct dp_bridge *bridge;
	struct dp_display *dp;

	if (!drm_bridge) {
		pr_err("Invalid params\n");
		return;
	}

	pr_debug("+++\n");

	bridge = to_dp_bridge(drm_bridge);
	dp = bridge->display;

	rc = dp->post_enable(dp);
	if (rc)
		pr_err("[%d] DP display post enable failed, rc=%d\n",
		       bridge->id, rc);
}

static void dp_bridge_disable(struct drm_bridge *drm_bridge)
{
	int rc = 0;
	struct dp_bridge *bridge;
	struct dp_display *dp;

	if (!drm_bridge) {
		pr_err("Invalid params\n");
		return;
	}

	pr_debug("+++\n");

	bridge = to_dp_bridge(drm_bridge);
	dp = bridge->display;

	if (!dp) {
		pr_err("dp is null\n");
		return;
	}

	if (dp->connector)
		sde_connector_helper_bridge_disable(dp->connector);

	rc = dp->pre_disable(dp);
	if (rc) {
		pr_err("[%d] DP display pre disable failed, rc=%d\n",
		       bridge->id, rc);
	}
}

static void dp_bridge_post_disable(struct drm_bridge *drm_bridge)
{
	int rc = 0;
	struct dp_bridge *bridge;
	struct dp_display *dp;

	if (!drm_bridge) {
		pr_err("Invalid params\n");
		return;
	}

	pr_debug("+++\n");

	bridge = to_dp_bridge(drm_bridge);
	dp = bridge->display;

	rc = dp->disable(dp);
	if (rc) {
		pr_err("[%d] DP display disable failed, rc=%d\n",
		       bridge->id, rc);
		return;
	}

	rc = dp->unprepare(dp);
	if (rc) {
		pr_err("[%d] DP display unprepare failed, rc=%d\n",
		       bridge->id, rc);
		return;
	}
}

static void dp_bridge_mode_set(struct drm_bridge *drm_bridge,
				struct drm_display_mode *mode,
				struct drm_display_mode *adjusted_mode)
{
	struct dp_bridge *bridge;
	struct dp_display *dp;

	if (!drm_bridge || !mode || !adjusted_mode) {
		pr_err("Invalid params\n");
		return;
	}

	bridge = to_dp_bridge(drm_bridge);
	dp = bridge->display;

	memset(&bridge->dp_mode, 0x0, sizeof(struct dp_display_mode));
	convert_to_dp_mode(adjusted_mode, &bridge->dp_mode, dp);
}

static bool dp_bridge_mode_fixup(struct drm_bridge *drm_bridge,
				  const struct drm_display_mode *mode,
				  struct drm_display_mode *adjusted_mode)
{
	bool ret = true;
	struct dp_display_mode dp_mode;
	struct dp_bridge *bridge;
	struct dp_display *dp;

	if (!drm_bridge || !mode || !adjusted_mode) {
		pr_err("Invalid params\n");
		ret = false;
		goto end;
	}

	bridge = to_dp_bridge(drm_bridge);
	dp = bridge->display;

	convert_to_dp_mode(mode, &dp_mode, dp);
	convert_to_drm_mode(&dp_mode, adjusted_mode);
end:
	return ret;
}

static const struct drm_bridge_funcs dp_bridge_ops = {
	.attach       = dp_bridge_attach,
	.mode_fixup   = dp_bridge_mode_fixup,
	.pre_enable   = dp_bridge_pre_enable,
	.enable       = dp_bridge_enable,
	.disable      = dp_bridge_disable,
	.post_disable = dp_bridge_post_disable,
	.mode_set     = dp_bridge_mode_set,
};

int dp_connector_config_hdr(void *display,
	struct sde_connector_state *c_state)
{
	struct dp_display *dp = display;

	if (!display || !c_state) {
		pr_err("invalid params\n");
		return -EINVAL;
	}

	return dp->config_hdr(dp, &c_state->hdr_meta);
}

int dp_connector_post_init(struct drm_connector *connector, void *display)
{
	struct dp_display *dp_display = display;

	if (!dp_display)
		return -EINVAL;

	dp_display->connector = connector;

	if (dp_display->post_init)
		dp_display->post_init(dp_display);

	return 0;
}

int dp_connector_get_mode_info(const struct drm_display_mode *drm_mode,
	struct msm_mode_info *mode_info, u32 max_mixer_width, void *display)
{
	const u32 dual_lm = 2;
	const u32 single_lm = 1;
	const u32 single_intf = 1;
	const u32 no_enc = 0;
	struct msm_display_topology *topology;

	if (!drm_mode || !mode_info || !max_mixer_width) {
		pr_err("invalid params\n");
		return -EINVAL;
	}

	topology = &mode_info->topology;
	topology->num_lm = (max_mixer_width <= drm_mode->hdisplay) ?
							dual_lm : single_lm;
	topology->num_enc = no_enc;
	topology->num_intf = single_intf;

	mode_info->frame_rate = drm_mode->vrefresh;
	mode_info->vtotal = drm_mode->vtotal;
	mode_info->comp_info.comp_type = MSM_DISPLAY_COMPRESSION_NONE;

	return 0;
}

int dp_connector_get_info(struct msm_display_info *info, void *data)
{
	struct dp_display *display = data;

	if (!info || !display) {
		pr_err("invalid params\n");
		return -EINVAL;
	}

#ifdef CONFIG_SEC_DISPLAYPORT
	memset(info, 0, sizeof(struct msm_display_info));
#endif
	info->intf_type = DRM_MODE_CONNECTOR_DisplayPort;

	info->num_of_h_tiles = 1;
	info->h_tile_instance[0] = 0;
	info->is_connected = display->is_connected;
	info->capabilities = MSM_DISPLAY_CAP_VID_MODE | MSM_DISPLAY_CAP_EDID |
		MSM_DISPLAY_CAP_HOT_PLUG;

	return 0;
}

enum drm_connector_status dp_connector_detect(struct drm_connector *conn,
		bool force,
		void *display)
{
	enum drm_connector_status status = connector_status_unknown;
	struct msm_display_info info;
	int rc;

	if (!conn || !display)
		return status;

	/* get display dp_info */
	memset(&info, 0x0, sizeof(info));
	rc = dp_connector_get_info(&info, display);
	if (rc) {
		pr_err("failed to get display info, rc=%d\n", rc);
		return connector_status_disconnected;
	}

	if (info.capabilities & MSM_DISPLAY_CAP_HOT_PLUG)
		status = (info.is_connected ? connector_status_connected :
					      connector_status_disconnected);
	else
		status = connector_status_connected;

	conn->display_info.width_mm = info.width_mm;
	conn->display_info.height_mm = info.height_mm;

	return status;
}

void dp_connector_post_open(void *display)
{
	struct dp_display *dp;

	if (!display) {
		pr_err("invalid input\n");
		return;
	}

	dp = display;

	if (dp->post_open)
		dp->post_open(dp);
}

int dp_connector_get_modes(struct drm_connector *connector,
		void *display)
{
	int rc = 0;
	struct dp_display *dp;
	struct dp_display_mode *dp_mode = NULL;
	struct drm_display_mode *m, drm_mode;

	if (!connector || !display)
		return 0;

	dp = display;

	dp_mode = kzalloc(sizeof(*dp_mode),  GFP_KERNEL);
	if (!dp_mode)
		return 0;

	/* pluggable case assumes EDID is read when HPD */
	if (dp->is_connected) {
		rc = dp->get_modes(dp, dp_mode);
		if (!rc)
			pr_err("failed to get DP sink modes, rc=%d\n", rc);

		if (dp_mode->timing.pixel_clk_khz) { /* valid DP mode */
			memset(&drm_mode, 0x0, sizeof(drm_mode));
			convert_to_drm_mode(dp_mode, &drm_mode);
			m = drm_mode_duplicate(connector->dev, &drm_mode);
			if (!m) {
				pr_err("failed to add mode %ux%u\n",
				       drm_mode.hdisplay,
				       drm_mode.vdisplay);
				kfree(dp_mode);
				return 0;
			}
			m->width_mm = connector->display_info.width_mm;
			m->height_mm = connector->display_info.height_mm;
			drm_mode_probed_add(connector, m);
		}
	} else {
		pr_err("No sink connected\n");
	}
	kfree(dp_mode);

	return rc;
}

int dp_drm_bridge_init(void *data, struct drm_encoder *encoder)
{
	int rc = 0;
	struct dp_bridge *bridge;
	struct drm_device *dev;
	struct dp_display *display = data;
	struct msm_drm_private *priv = NULL;

	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge) {
		rc = -ENOMEM;
		goto error;
	}

	dev = display->drm_dev;
	bridge->display = display;
	bridge->base.funcs = &dp_bridge_ops;
	bridge->base.encoder = encoder;

	priv = dev->dev_private;

	rc = drm_bridge_attach(dev, &bridge->base);
	if (rc) {
		pr_err("failed to attach bridge, rc=%d\n", rc);
		goto error_free_bridge;
	}

	rc = display->request_irq(display);
	if (rc) {
		pr_err("request_irq failed, rc=%d\n", rc);
		goto error_free_bridge;
	}

	encoder->bridge = &bridge->base;
	priv->bridges[priv->num_bridges++] = &bridge->base;
	display->bridge = bridge;

	return 0;
error_free_bridge:
	kfree(bridge);
error:
	return rc;
}

void dp_drm_bridge_deinit(void *data)
{
	struct dp_display *display = data;
	struct dp_bridge *bridge = display->bridge;

	if (bridge && bridge->base.encoder)
		bridge->base.encoder->bridge = NULL;

	kfree(bridge);
}

#ifdef CONFIG_SEC_DISPLAYPORT
/* Index of max resolution which supported by sink */
static int g_max_res_index;

/* Index of max resolution which supported by dex station */
static int g_dex_max_res_index;
static int g_ignore_ratio = 0;

void secdp_dex_res_init(void)
{
	g_max_res_index = g_dex_max_res_index = -1;
	g_ignore_ratio = 0;
}

static struct secdp_display_timing secdp_supported_resolution[] = {
	{ 0,   640,    480,  60, false, DEX_RES_1920X1080},
	{ 1,   720,    480,  60, false, DEX_RES_1920X1080},
	{ 2,   720,    576,  50, false, DEX_RES_1920X1080},

	{ 3,   1280,   720,  50, false, DEX_RES_1920X1080,   MON_RATIO_16_9},
	{ 4,   1280,   720,  60, false, DEX_RES_1920X1080,   MON_RATIO_16_9},

	{ 5,   1280,   768,  60, false, DEX_RES_1920X1080},                    /* CTS 4.4.1.3 */
	{ 6,   1280,   800,  60, false, DEX_RES_1920X1080,   MON_RATIO_16_10}, /* CTS 18bpp */
	{ 7,   1280,  1024,  60, false, DEX_RES_1920X1080},                    /* CTS 18bpp */
	{ 8,   1360,   768,  60, false, DEX_RES_1920X1080,   MON_RATIO_16_9},  /* CTS 4.4.1.3 */

	{ 9,   1366,  768,   60, false, DEX_RES_1920X1080,   MON_RATIO_16_9},
	{10,   1600,  900,   60, false, DEX_RES_1920X1080,   MON_RATIO_16_9},

	{20,   1920,  1080,  24, false, DEX_RES_1920X1080,   MON_RATIO_16_9},
	{21,   1920,  1080,  25, false, DEX_RES_1920X1080,   MON_RATIO_16_9},
	{22,   1920,  1080,  30, false, DEX_RES_1920X1080,   MON_RATIO_16_9},
	{23,   1920,  1080,  50, false, DEX_RES_1920X1080,   MON_RATIO_16_9},
	{24,   1920,  1080,  60, false, DEX_RES_1920X1080,   MON_RATIO_16_9},

	{25,   1920,  1200,  60, false, DEX_RES_1920X1200,   MON_RATIO_16_10},

	{30,   1920,  1440,  60, false, DEX_RES_NOT_SUPPORT},                  /* CTS 400.3.3.1 */
	{40,   2048,  1536,  60, false, DEX_RES_NOT_SUPPORT},                  /* CTS 18bpp */

#ifdef SECDP_WIDE_21_9_SUPPORT
	{60,   2560,  1080,  60, false, DEX_RES_2560X1080,   MON_RATIO_21_9},
#endif

	{61,   2560,  1440,  60, false, DEX_RES_2560X1440,   MON_RATIO_16_9},
	{62,   2560,  1600,  60, false, DEX_RES_2560X1600,   MON_RATIO_16_10},

	{70,   1440,  2560,  60, false, DEX_RES_NOT_SUPPORT},                  /* TVR test */
	{71,   1440,  2560,  75, false, DEX_RES_NOT_SUPPORT},                  /* TVR test */

#ifdef SECDP_WIDE_21_9_SUPPORT
	{80,   3440,  1440,  50, false, DEX_RES_3440X1440,   MON_RATIO_21_9},
	{81,   3440,  1440,  60, false, DEX_RES_3440X1440,   MON_RATIO_21_9},
#ifdef SECDP_HIGH_REFRESH_SUPPORT
	{82,   3440,  1440,	100, false, DEX_RES_NOT_SUPPORT, MON_RATIO_21_9},
#endif
#endif

#ifdef SECDP_WIDE_32_9_SUPPORT
	{100,  3840, 1080,   60, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_9},
#ifdef SECDP_HIGH_REFRESH_SUPPORT
	{101,  3840,  1080, 100, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_9},
	{102,  3840,  1080, 120, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_9},
	{104,  3840,  1080, 144, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_9},
#endif
#endif

#ifdef SECDP_WIDE_32_10_SUPPORT
	{110,  3840,  1200,	 60, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_10},
#ifdef SECDP_HIGH_REFRESH_SUPPORT
	{111,  3840,  1200, 100, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_10},
	{112,  3840,  1200, 120, false, DEX_RES_NOT_SUPPORT, MON_RATIO_32_10},
#endif
#endif

	{150,  3840,  2160,  24, false, DEX_RES_NOT_SUPPORT, MON_RATIO_16_9},
	{151,  3840,  2160,  25, false, DEX_RES_NOT_SUPPORT, MON_RATIO_16_9},
	{152,  3840,  2160,  30, false, DEX_RES_NOT_SUPPORT, MON_RATIO_16_9},
	{153,  3840,  2160,  50, false, DEX_RES_NOT_SUPPORT, MON_RATIO_16_9},
	{154,  3840,  2160,  60, false, DEX_RES_NOT_SUPPORT, MON_RATIO_16_9},

	{200,  4096,  2160,  24, false, DEX_RES_NOT_SUPPORT},
	{201,  4096,  2160,  25, false, DEX_RES_NOT_SUPPORT},
	{202,  4096,  2160,  30, false, DEX_RES_NOT_SUPPORT},
	{203,  4096,  2160,  50, false, DEX_RES_NOT_SUPPORT},
	{204,  4096,  2160,  60, false, DEX_RES_NOT_SUPPORT},
};

bool secdp_check_dex_reconnect(void)
{
	pr_info("%d, %d\n", g_max_res_index, g_dex_max_res_index);
	if (g_max_res_index == g_dex_max_res_index)
		return false;

	return true;
}

static inline char *secdp_aspect_ratio_to_string(enum mon_aspect_ratio_t ratio)
{
	switch (ratio) {
	case MON_RATIO_16_9:    return DP_ENUM_STR(MON_RATIO_16_9);
	case MON_RATIO_16_10:   return DP_ENUM_STR(MON_RATIO_16_10);
	case MON_RATIO_21_9:    return DP_ENUM_STR(MON_RATIO_21_9);
	case MON_RATIO_32_9:    return DP_ENUM_STR(MON_RATIO_32_9);
	case MON_RATIO_32_10:   return DP_ENUM_STR(MON_RATIO_32_10);
	case MON_RATIO_NA:      return DP_ENUM_STR(MON_RATIO_NA);
	default:                return "unknown";
	}
}

static enum mon_aspect_ratio_t secdp_get_aspect_ratio(struct drm_display_mode *mode)
{
	enum mon_aspect_ratio_t aspect_ratio = MON_RATIO_NA;
	int hdisplay = mode->hdisplay;
	int vdisplay = mode->vdisplay;

	if ((hdisplay == 3840 && vdisplay == 2160) ||
		(hdisplay == 2560 && vdisplay == 1440) ||
		(hdisplay == 1920 && vdisplay == 1080) ||
		(hdisplay == 1600 && vdisplay == 900) ||
		(hdisplay == 1366 && vdisplay == 768)  ||
		(hdisplay == 1280 && vdisplay == 720))
		aspect_ratio = MON_RATIO_16_9;
	else if ((hdisplay == 2560 && vdisplay == 1600) ||
		(hdisplay == 1920 && vdisplay == 1200) ||
		(hdisplay == 1680 && vdisplay == 1050) ||
		(hdisplay == 1440 && vdisplay == 900)  ||
		(hdisplay == 1280 && vdisplay == 800))
		aspect_ratio = MON_RATIO_16_10;
	else if ((hdisplay == 3440 && vdisplay == 1440) ||
		(hdisplay == 2560 && vdisplay == 1080))
		aspect_ratio = MON_RATIO_21_9;
	else if (hdisplay == 3840 && vdisplay == 1080)
		aspect_ratio = MON_RATIO_32_9;
	else if (hdisplay == 3840 && vdisplay == 1200)
		aspect_ratio = MON_RATIO_32_10;

	return aspect_ratio;
}

bool secdp_find_supported_resolution(struct dp_panel_info *timing)
{
	struct secdp_display_timing *secdp_timing = secdp_supported_resolution;
	int  i, res_cnt = ARRAY_SIZE(secdp_supported_resolution);
	u32  h_active, v_active, refresh_rate;
	bool support = false;

	h_active     = timing->h_active;
	v_active     = timing->v_active;
	refresh_rate = timing->refresh_rate;

	for (i = 0; i < res_cnt; i++) {
		if (h_active == secdp_timing[i].active_h &&
				v_active == secdp_timing[i].active_v &&
				refresh_rate == secdp_timing[i].refresh_rate) {
			support = true;
			break;
		}
	}

	return support;
}

static bool secdp_check_supported_resolution(struct drm_display_mode *mode, struct dp_display *dp_disp)
{
	int i, fps_diff;
	int res_cnt = ARRAY_SIZE(secdp_supported_resolution);
	bool interlaced = !!(mode->flags & DRM_MODE_FLAG_INTERLACE);
	static enum mon_aspect_ratio_t prefer_ratio;

	if (mode->type & DRM_MODE_TYPE_PREFERRED) {
		prefer_ratio = secdp_get_aspect_ratio(mode);
		pr_info("preferred_timing! %dx%d@%dhz, %s\n",
			mode->hdisplay, mode->vdisplay, mode->vrefresh,
			secdp_aspect_ratio_to_string(prefer_ratio));
		pr_info("max resolution - mirror : %d, dex : %d\n", g_max_res_index, g_dex_max_res_index);  
		if (g_max_res_index >= 0) {
			if (g_dex_max_res_index < 10) /* less than 1600 x 900 */
			 	g_ignore_ratio = 1;
#ifndef SECDP_USE_PREFERRED
			mode->type = mode->type & (unsigned int)(~DRM_MODE_TYPE_PREFERRED);
#endif
		}
	}

	if (mode->clock > dp_disp->max_pclk_khz)
		return false;
	if (dp_disp->validate_mode(dp_disp, mode->clock) == MODE_BAD)
		return false;

#if !defined (CONFIG_SEC_FACTORY) && defined (SECDP_MAX_RESOLUTION_4K30)
	/*When there is QHD 60hz DP resolution, max DP resolution 4K@30hz change to  QHD 60hz.*/
	if (mode->hdisplay == 2560 && mode->vrefresh == 60) {
		for (i = 0; i < res_cnt; i++) {
			if (secdp_supported_resolution[i].active_h == mode->hdisplay && 
				secdp_supported_resolution[i].active_v == mode->vdisplay && 
				secdp_supported_resolution[i].refresh_rate == mode->vrefresh)
				break;
		}

		if ((mode->vdisplay == 1600) || (mode->vdisplay == 1440 && g_max_res_index != i+1)) {
			if (g_max_res_index < secdp_supported_resolution[i].index)
				g_max_res_index = secdp_supported_resolution[i].index;
		}
	}
	if (mode->hdisplay == 3840 && mode->vrefresh < 60) {
		for (i = 0; i < res_cnt; i++) {
			if (secdp_supported_resolution[i].active_h == 2560 && 
				secdp_supported_resolution[i].active_v == 1440 && 
				secdp_supported_resolution[i].refresh_rate == 60)
				break;
		}

		if (g_max_res_index == secdp_supported_resolution[i].index || g_max_res_index == secdp_supported_resolution[i+1].index)
			return false; 
	}
#endif

	for (i = 0; i < res_cnt; i++) {
		bool ret = false;
		fps_diff = secdp_supported_resolution[i].refresh_rate - drm_mode_vrefresh(mode);
		fps_diff = fps_diff < 0 ? fps_diff * (-1) : fps_diff;

		if (fps_diff > 1)
			continue;

		if (secdp_supported_resolution[i].interlaced != interlaced)
			continue;

		if (secdp_supported_resolution[i].active_h != mode->hdisplay)
			continue;

		if (secdp_supported_resolution[i].active_v != mode->vdisplay)
			continue;

		/* find max resolution which supported by sink */
		if (g_max_res_index < secdp_supported_resolution[i].index)
			g_max_res_index = secdp_supported_resolution[i].index;

		if (secdp_supported_resolution[i].dex_res != DEX_RES_NOT_SUPPORT &&
				secdp_supported_resolution[i].dex_res <= secdp_get_dex_res()) {

#if 0/*TEST*/
			if (secdp_supported_resolution[i].dex_res == DEX_RES_3440X1440) {
				pr_debug("[TEST] RETURN FALSE 3440x1440!!\n");
				ret = false;
			} else if (secdp_supported_resolution[i].dex_res == DEX_RES_2560X1080) {
				pr_debug("[TEST] RETURN FALSE 2560x1080!!\n");
				ret = false;
			} else
#endif
			if (g_ignore_ratio)
				ret = true;
			else if (secdp_supported_resolution[i].mon_ratio == prefer_ratio)
				ret = true;
			else
				ret = false;
		} else
			ret = false;

		/* find max resolution which supported by dex station */
		if (ret && g_dex_max_res_index < secdp_supported_resolution[i].index)
			g_dex_max_res_index = secdp_supported_resolution[i].index;

		if (secdp_check_dex_mode())
			return ret;

		return true;
	}

	return false;
}
#endif

enum drm_mode_status dp_connector_mode_valid(struct drm_connector *connector,
		struct drm_display_mode *mode,
		void *display)
{
	struct dp_display *dp_disp;
	struct dp_debug *debug;
#ifdef CONFIG_SEC_DISPLAYPORT
	enum drm_mode_status ret = MODE_OK;
#endif

	if (!mode || !display) {
		pr_err("invalid params\n");
		return MODE_ERROR;
	}

	dp_disp = display;
	debug = dp_disp->get_debug(dp_disp);

	mode->vrefresh = drm_mode_vrefresh(mode);

#ifndef CONFIG_SEC_DISPLAYPORT
	if (mode->clock > dp_disp->max_pclk_khz)
		return MODE_BAD;

	if (debug->debug_en && (mode->hdisplay != debug->hdisplay ||
			mode->vdisplay != debug->vdisplay ||
			mode->vrefresh != debug->vrefresh ||
			mode->picture_aspect_ratio != debug->aspect_ratio))
		return MODE_BAD;

	return dp_disp->validate_mode(dp_disp, mode->clock);
#else

	if (debug->debug_en && (mode->hdisplay != debug->hdisplay ||
			mode->vdisplay != debug->vdisplay ||
			mode->vrefresh != debug->vrefresh ||
			mode->picture_aspect_ratio != debug->aspect_ratio)) {
		ret = MODE_BAD;
		goto end;
	}

	if (ret == MODE_OK && !secdp_check_supported_resolution(mode, dp_disp)) {
		ret = MODE_BAD;
		goto end;
	}

end:
	pr_info("%s@%dhz | %s | max_pclk: %d | cur_pclk: %d\n", mode->name,
		drm_mode_vrefresh(mode), ret == MODE_BAD ? "not supported" : "supported",
		dp_disp->max_pclk_khz, mode->clock);
	return ret;
#endif
}
