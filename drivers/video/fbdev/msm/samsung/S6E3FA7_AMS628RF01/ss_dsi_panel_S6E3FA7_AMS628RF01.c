/*
 * =================================================================
 *
 *
 *	Description:  samsung display panel file
 *
 *	Author: jb09.kim
 *	Company:  Samsung Electronics
 *
 * ================================================================
 */
/*
<one line to give the program's name and a brief idea of what it does.>
Copyright (C) 2012, Samsung Electronics. All rights reserved.

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
 * You should have received a copy of the GNU General Public License
 *
*/
#include "ss_dsi_panel_S6E3FA7_AMS628RF01.h"
#include "ss_dsi_mdnie_S6E3FA7_AMS628RF01.h"
#include "../../mdss_dsi.h"

/* AOD Mode status on AOD Service */
enum {
	AOD_MODE_ALPM_2NIT_ON = MAX_LPM_MODE + 1,
	AOD_MODE_HLPM_2NIT_ON,
	AOD_MODE_ALPM_60NIT_ON,
	AOD_MODE_HLPM_60NIT_ON,
};

enum {
	ALPM_CTRL_2NIT,
	ALPM_CTRL_60NIT,
	HLPM_CTRL_2NIT,
	HLPM_CTRL_60NIT,
	MAX_LPM_CTRL,
};

/* Register to control brightness level */
#define ALPM_REG	0x53
/* Register to cnotrol ALPM/HLPM mode */
#define ALPM_CTRL_REG	0xBB
/* Register to cnotrol POC */
#define POC_CTRL_REG	0xEB

static int mdss_panel_on_pre(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	int on_reg_list[1][2] = {{POC_CTRL_REG, -EINVAL} };
	struct dsi_panel_cmds *on_cmd_list[1];
	char poc_buffer[4] = {0,};
	static unsigned int i_poc_buffer[4] = {0,};
	int MAX_POC = 4;
	int loop;

	on_cmd_list[0] = &ctrl->on_cmds;

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	LCD_INFO("+: ndx=%d \n", ctrl->ndx);
	mdss_panel_attach_set(ctrl, true);

	if (!vdd->poc_driver.is_support) {
		LCD_DEBUG("Not Support POC Function \n");
		goto end;
	}

	/* Read Panel POC (EBh 1nd~4th) */
	if (get_panel_rx_cmds(ctrl, RX_POC_STATUS)->cmd_cnt) {
		memset(poc_buffer, 0x00, sizeof(poc_buffer[0]) * MAX_POC);

		if (unlikely(vdd->is_factory_mode) &&
				vdd->dtsi_data[ctrl->ndx].samsung_support_factory_panel_swap) {
			memset(i_poc_buffer, 0x00, sizeof(i_poc_buffer[0]) * MAX_POC);
		}

		if (i_poc_buffer[3] == 0) {
			mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_POC_STATUS),
					poc_buffer, LEVEL1_KEY);

			for (loop = 0; loop < MAX_POC; loop++)
				i_poc_buffer[loop] = (unsigned int)poc_buffer[loop];
		}

		LCD_DEBUG("[POC] DSI%d: %02x %02x %02x %02x\n",
				ctrl->ndx,
				i_poc_buffer[0],
				i_poc_buffer[1],
				i_poc_buffer[2],
				i_poc_buffer[3]);

		/*
		 * Update REBh 4th param to 0xFF or 0x64
		 */
		mdss_init_panel_lpm_reg_offset(ctrl, on_reg_list, on_cmd_list,
				sizeof(on_cmd_list) / sizeof(on_cmd_list[0]));

		if ((on_reg_list[0][1] != -EINVAL) &&\
			(vdd->octa_id_dsi[ctrl->ndx][1] == 0x1)) {	/* POC CHECK  C9 3th Para */
			if (i_poc_buffer[3] == 0x33)
				i_poc_buffer[3] = 0x64;

			on_cmd_list[0]->cmds[on_reg_list[0][1]].payload[4] =
				i_poc_buffer[3];

			LCD_DEBUG("Update POC register, 0x%02x\n",
					on_cmd_list[0]->cmds[on_reg_list[0][1]].payload[4]);

		}

		LCD_DEBUG("[POC] DSI%d: octa_id:%d, poc_buffer:%02x, index:%d\n",
				ctrl->ndx,
				vdd->octa_id_dsi[ctrl->ndx][1],
				i_poc_buffer[3],
				on_reg_list[0][1]);
	} else {
		LCD_ERR("DSI%d no poc_rx_cmds cmd\n", ctrl->ndx);
	}

end:
	LCD_INFO("-: ndx=%d \n", ctrl->ndx);

	return true;
}

extern int poweroff_charging;

static int mdss_panel_on_post(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	int ndx = display_ndx_check(vdd->ctrl_dsi[DSI_CTRL_0]);

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return false;
	}

	pr_info("%s %d\n", __func__, ndx);

	self_mask_img_write(ctrl);
	ss_self_mask_on(ctrl, 1);

	return true;
}

#if 0
static int mdss_panel_off_post(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	int ndx = display_ndx_check(vdd->ctrl_dsi[DSI_CTRL_0]);

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return false;
	}

	pr_info("%s %d\n", __func__, ndx);

	ss_self_mask_on(ctrl, 0);

	return true;
}
#endif

static char mdss_panel_revision(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	int ndx = display_ndx_check(vdd->ctrl_dsi[DSI_CTRL_0]);

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return false;
	}

	if (vdd->manufacture_id_dsi[ndx] == PBA_ID)
		mdss_panel_attach_set(ctrl, false);
	else
		mdss_panel_attach_set(ctrl, true);

	vdd->aid_subdivision_enable = true;

	switch (mdss_panel_rev_get(ctrl)) {
	case 0x00:
		vdd->panel_revision = 'C';
		break;
	default:
		vdd->panel_revision = 'C';
		LCD_ERR("Invalid panel_rev(default rev : %c) %d\n",
				vdd->panel_revision, mdss_panel_rev_get(ctrl) );
		break;
	}

	vdd->panel_revision -= 'A';

	LCD_INFO_ONCE("panel_revision = %c %d \n",
					vdd->panel_revision + 'A', vdd->panel_revision);

	return (vdd->panel_revision + 'A');
}

static int mdss_manufacture_date_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	unsigned char date[4];
	int year, month, day;
	int hour, min;
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read mtp (C8h 41,42th) for manufacture date */
	if (get_panel_rx_cmds(ctrl, RX_MANUFACTURE_DATE)->cmd_cnt) {
		mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_MANUFACTURE_DATE),
			date, LEVEL1_KEY);

		year = date[0] & 0xf0;
		year >>= 4;
		year += 2011; /* 0 = 2011 year*/
		month = date[0] & 0x0f;
		day = date[1] & 0x1f;
		hour = date[2] & 0x0f;
		min = date[3] & 0x1f;

		vdd->manufacture_date_dsi[ctrl->ndx] = year * 10000 + month * 100 + day;
		vdd->manufacture_time_dsi[ctrl->ndx] = hour * 100 + min;

		LCD_ERR("manufacture_date DSI%d = (%d%04d) - year(%d) month(%d) day(%d) hour(%d) min(%d)\n",
			ctrl->ndx, vdd->manufacture_date_dsi[ctrl->ndx], vdd->manufacture_time_dsi[ctrl->ndx],
			year, month, day, hour, min);
	} else {
		LCD_ERR("DSI%d no manufacture_date_rx_cmds cmds(%d)", ctrl->ndx, vdd->panel_revision);
		return false;
	}

	return true;
}

static int mdss_ddi_id_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char ddi_id[5];
	int loop;
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read mtp (D6h 1~5th) for ddi id */
	if (get_panel_rx_cmds(ctrl, RX_DDI_ID)->cmd_cnt) {
		mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_DDI_ID),
			ddi_id, LEVEL1_KEY);

		for (loop = 0; loop < 5; loop++)
			vdd->ddi_id_dsi[ctrl->ndx][loop] = ddi_id[loop];

		LCD_INFO("DSI%d : %02x %02x %02x %02x %02x\n", ctrl->ndx,
			vdd->ddi_id_dsi[ctrl->ndx][0], vdd->ddi_id_dsi[ctrl->ndx][1],
			vdd->ddi_id_dsi[ctrl->ndx][2], vdd->ddi_id_dsi[ctrl->ndx][3],
			vdd->ddi_id_dsi[ctrl->ndx][4]);
	} else {
		LCD_ERR("DSI%d no ddi_id_rx_cmds cmds", ctrl->ndx);
		return false;
	}

	return true;
}

static int mdss_cell_id_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char cell_id_buffer[MAX_CELL_ID] = {0,};
	int loop;
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read Panel Unique Cell ID (C8h 41~51th) */
	if (get_panel_rx_cmds(ctrl, RX_CELL_ID)->cmd_cnt) {
		memset(cell_id_buffer, 0x00, MAX_CELL_ID);

		mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_CELL_ID),
			cell_id_buffer, LEVEL1_KEY);

		for (loop = 0; loop < MAX_CELL_ID; loop++)
			vdd->cell_id_dsi[ctrl->ndx][loop] = cell_id_buffer[loop];

		LCD_INFO("DSI%d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			ctrl->ndx, vdd->cell_id_dsi[ctrl->ndx][0],
			vdd->cell_id_dsi[ctrl->ndx][1],	vdd->cell_id_dsi[ctrl->ndx][2],
			vdd->cell_id_dsi[ctrl->ndx][3],	vdd->cell_id_dsi[ctrl->ndx][4],
			vdd->cell_id_dsi[ctrl->ndx][5],	vdd->cell_id_dsi[ctrl->ndx][6],
			vdd->cell_id_dsi[ctrl->ndx][7],	vdd->cell_id_dsi[ctrl->ndx][8],
			vdd->cell_id_dsi[ctrl->ndx][9],	vdd->cell_id_dsi[ctrl->ndx][10]);

	} else {
		LCD_ERR("DSI%d no cell_id_rx_cmds cmd\n", ctrl->ndx);
		return false;
	}

	return true;
}

static int mdss_octa_id_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char octa_id_buffer[MAX_OCTA_ID] = {0,};
	int loop;
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read Panel Unique OCTA ID (D6h 1st~5th) */
	if (get_panel_rx_cmds(ctrl, RX_OCTA_ID)->cmd_cnt) {
		memset(octa_id_buffer, 0x00, MAX_OCTA_ID);

		mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_OCTA_ID),
			octa_id_buffer, LEVEL1_KEY);

		for (loop = 0; loop < MAX_OCTA_ID; loop++)
			vdd->octa_id_dsi[ctrl->ndx][loop] = octa_id_buffer[loop];

		LCD_INFO("DSI%d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			ctrl->ndx, vdd->octa_id_dsi[ctrl->ndx][0], vdd->octa_id_dsi[ctrl->ndx][1],
			vdd->octa_id_dsi[ctrl->ndx][2],	vdd->octa_id_dsi[ctrl->ndx][3],
			vdd->octa_id_dsi[ctrl->ndx][4],	vdd->octa_id_dsi[ctrl->ndx][5],
			vdd->octa_id_dsi[ctrl->ndx][6],	vdd->octa_id_dsi[ctrl->ndx][7],
			vdd->octa_id_dsi[ctrl->ndx][8],	vdd->octa_id_dsi[ctrl->ndx][9],
			vdd->octa_id_dsi[ctrl->ndx][10], vdd->octa_id_dsi[ctrl->ndx][11],
			vdd->octa_id_dsi[ctrl->ndx][12], vdd->octa_id_dsi[ctrl->ndx][13],
			vdd->octa_id_dsi[ctrl->ndx][14], vdd->octa_id_dsi[ctrl->ndx][15],
			vdd->octa_id_dsi[ctrl->ndx][16], vdd->octa_id_dsi[ctrl->ndx][17],
			vdd->octa_id_dsi[ctrl->ndx][18], vdd->octa_id_dsi[ctrl->ndx][19]);

	} else {
		LCD_ERR("DSI%d no octa_id_rx_cmds cmd\n", ctrl->ndx);
		return false;
	}

	return true;
}

static int mdss_elvss_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char elvss_b5[2];
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read mtp (B5h 23th,24th) for elvss*/
	mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_ELVSS),
		elvss_b5, LEVEL1_KEY);
	vdd->display_status_dsi[ctrl->ndx].elvss_value1 = elvss_b5[0]; /*0xB5 23th OTP value*/
	vdd->display_status_dsi[ctrl->ndx].elvss_value2 = elvss_b5[1]; /*0xB5 24th OTP value*/

	return true;
}

static struct dsi_panel_cmds vint_cmd;
static struct dsi_panel_cmds *mdss_vint(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *vint_cmds = get_panel_tx_cmds(ctrl, TX_VINT);
	int cmd_index = 0;  /*xtalk_mode off(default)*/

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(vint_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)vint_cmds);
		return NULL;
	}

	if (vdd->xtalk_mode)
		cmd_index = 1;	/* VGH 6.2 V*/
	else
		cmd_index = 0;	/* VGH 7.0 V*/

	vint_cmd.cmds = &vint_cmds->cmds[cmd_index];

	vint_cmd.cmd_cnt = 1;
	*level_key = LEVEL1_KEY;

	return &vint_cmd;

}

static int mdss_hbm_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	int i, j;
	char hbm_buffer1[33];
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *hbm_gamma_cmds = get_panel_tx_cmds(ctrl, TX_HBM_GAMMA);

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(hbm_gamma_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)hbm_gamma_cmds);
		return false;
	}

	/* Read mtp (B3h 3~34th) for hbm gamma */
	mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_HBM),
		hbm_buffer1, LEVEL1_KEY);

	/* V255 RGB */
	hbm_gamma_cmds->cmds[0].payload[1] = (hbm_buffer1[0] & 0x04) >> 2;
	hbm_gamma_cmds->cmds[0].payload[2] = hbm_buffer1[2];
	hbm_gamma_cmds->cmds[0].payload[3] = (hbm_buffer1[0] & 0x02) >> 1;
	hbm_gamma_cmds->cmds[0].payload[4] = hbm_buffer1[3];
	hbm_gamma_cmds->cmds[0].payload[5] = (hbm_buffer1[0] & 0x01) >> 0;
	hbm_gamma_cmds->cmds[0].payload[6] = hbm_buffer1[4];

	/* V203 ~ V1 */
	for (i = 7, j = 5; i <= 33; i++, j++)
		hbm_gamma_cmds->cmds[0].payload[i] = hbm_buffer1[j];

	/* VT RGB */
	hbm_gamma_cmds->cmds[0].payload[34] = hbm_buffer1[0] & 0xF0;
	hbm_gamma_cmds->cmds[0].payload[34] |= (hbm_buffer1[1] & 0xF0) >> 4;
	hbm_gamma_cmds->cmds[0].payload[35] = hbm_buffer1[1] & 0x0F;

	return true;
}

static int get_hbm_candela_value(int level)
{
	if (level == 13)
		return 443;
	else if (level == 6)
		return 465;
	else if (level == 7)
		return 488;
	else if (level == 8)
		return 510;
	else if (level == 9)
		return 533;
	else if (level == 10)
		return 555;
	else if (level == 11)
		return 578;
	else if (level == 12)
		return 600;
	else
		return 600;
}

static struct dsi_panel_cmds *mdss_hbm_gamma(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *hbm_gamma_cmds = get_panel_tx_cmds(ctrl, TX_HBM_GAMMA);

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(hbm_gamma_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmd : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)hbm_gamma_cmds);
		return NULL;
	}

	if (IS_ERR_OR_NULL(vdd->smart_dimming_dsi[ctrl->ndx]->generate_hbm_gamma)) {
		LCD_ERR("generate_hbm_gamma is NULL error");
		return NULL;
	} else {
		vdd->smart_dimming_dsi[ctrl->ndx]->generate_hbm_gamma(
			vdd->smart_dimming_dsi[ctrl->ndx],
			vdd->auto_brightness,
			&hbm_gamma_cmds->cmds[0].payload[1]);

		*level_key = LEVEL1_KEY;
		return hbm_gamma_cmds;
	}
}

#if 0
static struct dsi_panel_cmds *mdss_hbm_off(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *hbm_off_cmds = get_panel_tx_cmds(ctrl, TX_HBM_OFF);

	int elvss_22th_val;

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return NULL;
	}
	elvss_22th_val = vdd->display_status_dsi[ctrl->ndx].elvss_value1;/*22th otp: to recover*/

	/* ELVSS 0xB6 22nd val */
	hbm_off_cmds->cmds[0].payload[22] = elvss_22th_val;

	*level_key = LEVEL1_KEY;

	LCD_INFO("B6_2ND_PARA = 0x%x, B6_22TH_PARA  = 0x%x\n",
		hbm_off_cmds->cmds[0].payload[2], hbm_off_cmds->cmds[0].payload[22]);

	return hbm_off_cmds;

}
#endif

static struct dsi_panel_cmds *mdss_hbm_etc(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *hbm_etc_cmds = get_panel_tx_cmds(ctrl, TX_HBM_ETC);
	int elvss_24th_val;

	char hbm_elvss_offset[] = {
		0x0D,	/* 443 */
		0x0B,	/* 465 */
		0x0A,	/* 488 */
		0x09,	/* 510 */
		0x08,	/* 533 */
		0x06,	/* 555 */
		0x05,	/* 578 */
		0x04,	/* 600 */
	};

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	elvss_24th_val = vdd->display_status_dsi[ctrl->ndx].elvss_value2;

	/* MPS/ELVSS : 0xB5 1th TSET */
	hbm_etc_cmds->cmds[1].payload[1] =
		vdd->temperature > 0 ? vdd->temperature : 0x80|(-1*vdd->temperature);

	/* MPS/ELVSS : 0xB5 3rd val */
	hbm_etc_cmds->cmds[1].payload[3] = hbm_elvss_offset[vdd->auto_brightness - HBM_MODE];

	if (vdd->acl_status == 1) {  /*acl on : 8%*/
		hbm_etc_cmds->cmds[2].payload[1] = 0x50; /*B4 1st*/
		hbm_etc_cmds->cmds[2].payload[13] = 0x50; /*B4 13th*/
		hbm_etc_cmds->cmds[3].payload[1] = 0x02; /*55 1st*/
	} else {  /*acl off*/
		hbm_etc_cmds->cmds[2].payload[1] = 0x40; /*B4 1st*/
		hbm_etc_cmds->cmds[2].payload[13] = 0x40; /*B4 13th*/
		hbm_etc_cmds->cmds[3].payload[1] = 0x00; /*55 1st*/
	}
	/* Read B5h 24th para -> Write to B5h 23th para */
	hbm_etc_cmds->cmds[1].payload[23] = vdd->display_status_dsi[ctrl->ndx].elvss_value2;

	*level_key = LEVEL1_KEY;

	LCD_INFO("B6_3rd_PARA = 0x%x, TSET = 0x%x, 23th = 0x%x \n",
		hbm_etc_cmds->cmds[1].payload[3], hbm_etc_cmds->cmds[1].payload[1], hbm_etc_cmds->cmds[1].payload[23]);

	return hbm_etc_cmds;

}

#define COORDINATE_DATA_SIZE 6

#define F1(x, y) ((y)-((353*(x))/326)+30)
#define F2(x, y) ((y)-((20*(x))/19)-14)
#define F3(x, y) ((y)+((185*(x))/42)-16412)
#define F4(x, y) ((y)+((337*(x))/106)-12601)

/* Normal Mode */
static char coordinate_data_1[][COORDINATE_DATA_SIZE] = {
	{0xff, 0x00, 0xff, 0x00, 0xff, 0x00}, /* dummy */
	{0xff, 0x00, 0xfb, 0x00, 0xfb, 0x00}, /* Tune_1 */
	{0xff, 0x00, 0xfc, 0x00, 0xff, 0x00}, /* Tune_2 */
	{0xfb, 0x00, 0xf9, 0x00, 0xff, 0x00}, /* Tune_3 */
	{0xff, 0x00, 0xfe, 0x00, 0xfc, 0x00}, /* Tune_4 */
	{0xff, 0x00, 0xff, 0x00, 0xff, 0x00}, /* Tune_5 */
	{0xfb, 0x00, 0xfc, 0x00, 0xff, 0x00}, /* Tune_6 */
	{0xfd, 0x00, 0xff, 0x00, 0xfa, 0x00}, /* Tune_7 */
	{0xfc, 0x00, 0xff, 0x00, 0xfc, 0x00}, /* Tune_8 */
	{0xfb, 0x00, 0xff, 0x00, 0xff, 0x00}, /* Tune_9 */
};

/* sRGB/Adobe RGB Mode */
static char coordinate_data_2[][COORDINATE_DATA_SIZE] = {
	{0xff, 0x00, 0xf7, 0x00, 0xef, 0x00}, /* dummy */
	{0xff, 0x00, 0xf4, 0x00, 0xec, 0x00}, /* Tune_1 */
	{0xff, 0x00, 0xf5, 0x00, 0xef, 0x00}, /* Tune_2 */
	{0xff, 0x00, 0xf6, 0x00, 0xf3, 0x00}, /* Tune_3 */
	{0xff, 0x00, 0xf7, 0x00, 0xed, 0x00}, /* Tune_4 */
	{0xff, 0x00, 0xf7, 0x00, 0xef, 0x00}, /* Tune_5 */
	{0xff, 0x00, 0xf8, 0x00, 0xf2, 0x00}, /* Tune_6 */
	{0xff, 0x00, 0xfa, 0x00, 0xed, 0x00}, /* Tune_7 */
	{0xff, 0x00, 0xfa, 0x00, 0xef, 0x00}, /* Tune_8 */
	{0xff, 0x00, 0xfb, 0x00, 0xf3, 0x00}, /* Tune_9 */
};

static char (*coordinate_data_multi[MAX_MODE])[COORDINATE_DATA_SIZE] = {
	coordinate_data_2, /* DYNAMIC - DCI */
	coordinate_data_2, /* STANDARD - sRGB/Adobe RGB */
	coordinate_data_2, /* NATURAL - sRGB/Adobe RGB */
	coordinate_data_1, /* MOVIE - Normal */
	coordinate_data_1, /* AUTO - Normal */
	coordinate_data_1, /* READING - Normal */
};

static int mdnie_coordinate_index(int x, int y)
{
	int tune_number = 0;

	if (F1(x, y) > 0) {
		if (F3(x, y) > 0) {
			tune_number = 3;
		} else {
			if (F4(x, y) < 0)
				tune_number = 1;
			else
				tune_number = 2;
		}
	} else {
		if (F2(x, y) < 0) {
			if (F3(x, y) > 0) {
				tune_number = 9;
			} else {
				if (F4(x, y) < 0)
					tune_number = 7;
				else
					tune_number = 8;
			}
		} else {
			if (F3(x, y) > 0)
				tune_number = 6;
			else {
				if (F4(x, y) < 0)
					tune_number = 4;
				else
					tune_number = 5;
			}
		}
	}

	return tune_number;
}

static int mdss_mdnie_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char x_y_location[4];
	int mdnie_tune_index = 0;
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx\n", __func__, (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read mtp (D6h 1~5th) for ddi id */
	if (get_panel_rx_cmds(ctrl, RX_MDNIE)->cmd_cnt) {
		mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_MDNIE),
			x_y_location, LEVEL1_KEY);

		vdd->mdnie_x[ctrl->ndx] = x_y_location[0] << 8 | x_y_location[1];	/* X */
		vdd->mdnie_y[ctrl->ndx] = x_y_location[2] << 8 | x_y_location[3];	/* Y */

		mdnie_tune_index = mdnie_coordinate_index(vdd->mdnie_x[ctrl->ndx], vdd->mdnie_y[ctrl->ndx]);

		coordinate_tunning_multi(ctrl->ndx, coordinate_data_multi, mdnie_tune_index,
			ADDRESS_SCR_WHITE_RED, COORDINATE_DATA_SIZE);

		LCD_INFO("PANEL%d : X-%d Y-%d \n", ctrl->ndx,
			vdd->mdnie_x[ctrl->ndx], vdd->mdnie_y[ctrl->ndx]);
	} else {
		LCD_ERR("PANEL%d error\n", ctrl->ndx);
		return false;
	}

	return true;
}

static int mdss_smart_dimming_init(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	int ndx = display_ndx_check(vdd->ctrl_dsi[DSI_CTRL_0]);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	vdd->smart_dimming_dsi[ndx] = vdd->panel_func.samsung_smart_get_conf();

	if (IS_ERR_OR_NULL(vdd->smart_dimming_dsi[ndx])) {
		LCD_ERR("DSI%d error\n", ndx);
		return false;
	} else {
		if (get_panel_rx_cmds(ctrl, RX_SMART_DIM_MTP)->cmd_cnt) {
			mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_SMART_DIM_MTP),
			vdd->smart_dimming_dsi[ctrl->ndx]->mtp_buffer, LEVEL1_KEY);

			/* Initialize smart dimming related things here */
			vdd->smart_dimming_dsi[ctrl->ndx]->lux_tab = vdd->dtsi_data[ctrl->ndx].candela_map_table[vdd->panel_revision].cd;
			vdd->smart_dimming_dsi[ctrl->ndx]->lux_tabsize = vdd->dtsi_data[ctrl->ndx].candela_map_table[vdd->panel_revision].tab_size;
			vdd->smart_dimming_dsi[ctrl->ndx]->man_id = vdd->manufacture_id_dsi[ctrl->ndx];

			if (vdd->panel_func.samsung_panel_revision)
				vdd->smart_dimming_dsi[ctrl->ndx]->panel_revision = vdd->panel_func.samsung_panel_revision(ctrl);

			/* copy hbm gamma payload for hbm interpolation calc */
			vdd->smart_dimming_dsi[ctrl->ndx]->hbm_payload = &get_panel_tx_cmds(ctrl, TX_HBM_GAMMA)->cmds[0].payload[1];

			/* Just a safety check to ensure smart dimming data is initialised well */
			vdd->smart_dimming_dsi[ndx]->init(vdd->smart_dimming_dsi[ndx]);

			vdd->temperature = 20; // default temperature

			vdd->smart_dimming_loaded_dsi[ndx] = true;
		} else {
			LCD_ERR("DSI%d error\n", ndx);
			return false;
		}
	}

	LCD_INFO("DSI%d : --\n", ndx);

	return true;
}

static struct dsi_panel_cmds aid_cmd;
static struct dsi_panel_cmds *mdss_aid(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	int cd_index = 0;

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	if (vdd->pac)
		cd_index = vdd->pac_cd_idx;
	else
		cd_index = vdd->bl_level;

	aid_cmd.cmd_cnt = 1;
	aid_cmd.cmds = &(get_panel_tx_cmds(ctrl, TX_AID_SUBDIVISION)->cmds[cd_index]);
	LCD_DEBUG("[%d] level(%d), aid(%x %x)\n", cd_index, vdd->bl_level, aid_cmd.cmds->payload[1], aid_cmd.cmds->payload[2]);

	*level_key = LEVEL1_KEY;

	return &aid_cmd;
}

#define GRADUAL_ACL_STEP_JP2 6 //refer config_display.xml
static struct dsi_panel_cmds *mdss_acl_on(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	u8 acl_value[GRADUAL_ACL_STEP_JP2] = {0x00, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F};
	int step;

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	*level_key = LEVEL1_KEY;

	if (vdd->gradual_acl_val
			&& vdd->gradual_acl_val < GRADUAL_ACL_STEP_JP2)
		step = vdd->gradual_acl_val;
	else
		step = GRADUAL_ACL_STEP_JP2 - 1; /* default value */

	if (vdd->gradual_acl_val)
	 get_panel_tx_cmds(ctrl, TX_ACL_ON)->cmds[0].payload[5] = acl_value[step];

	return get_panel_tx_cmds(ctrl, TX_ACL_ON);
}

static struct dsi_panel_cmds *mdss_acl_off(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	*level_key = LEVEL1_KEY;

	return get_panel_tx_cmds(ctrl, TX_ACL_OFF);
}

#if 0
static struct dsi_panel_cmds acl_percent_cmd;
static struct dsi_panel_cmds *mdss_acl_precent(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	int ndx = display_ndx_check(vdd->ctrl_dsi[DSI_CTRL_0]);
	int cd_index = 0;
	int cmd_idx = 0;

	if (IS_ERR_OR_NULL(vdd)) {
		pr_err("%s: Invalid data ctrl : 0x%zx vdd : 0x%zx", __func__, (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	cd_index = get_cmd_index(vdd, ndx);

	if (!vdd->dtsi_data[ndx].acl_map_table[vdd->panel_revision].size ||
		cd_index > vdd->dtsi_data[ndx].acl_map_table[vdd->panel_revision].size)
		goto end;

	cmd_idx = vdd->dtsi_data[ndx].acl_map_table[vdd->panel_revision].cmd_idx[cd_index];

	acl_percent_cmd.cmds = &(vdd->dtsi_data[ndx].acl_percent_tx_cmds[vdd->panel_revision].cmds[cmd_idx]);
	acl_percent_cmd.cmd_cnt = 1;

	*level_key = PANEL_LEVE1_KEY;
	return &acl_percent_cmd;

end:
	pr_err("%s error", __func__);
	return NULL;
}
#endif

static struct dsi_panel_cmds elvss_cmd;
static struct dsi_panel_cmds *mdss_elvss(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *elvss_cmds = get_panel_tx_cmds(ctrl, TX_ELVSS);
	int ndx = display_ndx_check(vdd->ctrl_dsi[DSI_CTRL_0]);
	int cd_index = 0;
	int cmd_idx = 0;
	int candela_value = 0;

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx \n", (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	if (vdd->temperature > 0) // high temp
		elvss_cmds = get_panel_tx_cmds(ctrl, TX_ELVSS_HIGH);
	else if (vdd->temperature <= -15) // low temp
		elvss_cmds = get_panel_tx_cmds(ctrl, TX_ELVSS_LOW);
	else // mid temp
		elvss_cmds = get_panel_tx_cmds(ctrl, TX_ELVSS_MID);

	if (IS_ERR_OR_NULL(elvss_cmds)) {
		LCD_ERR("Invalid data ctrl : cmds : 0x%zx \n", (size_t)elvss_cmds);
		return NULL;
	}

	cd_index = vdd->cd_idx;
	candela_value = vdd->candela_level;

	if (!vdd->dtsi_data[ndx].smart_acl_elvss_map_table[vdd->panel_revision].size ||
		cd_index > vdd->dtsi_data[ndx].smart_acl_elvss_map_table[vdd->panel_revision].size)
		goto end;

	cmd_idx = vdd->dtsi_data[ndx].smart_acl_elvss_map_table[vdd->panel_revision].cmd_idx[cd_index];

	LCD_DEBUG("cd_index (%d) cmd_idx(%d) candela_value(%d) B5 1st(%x) 2nd (%x) 3rd (%x)\n",
		cd_index, cmd_idx, candela_value,
		elvss_cmds->cmds[cmd_idx].payload[1],
		elvss_cmds->cmds[cmd_idx].payload[2],
		elvss_cmds->cmds[cmd_idx].payload[3]);

	elvss_cmd.cmds = &(elvss_cmds->cmds[cmd_idx]);
	elvss_cmd.cmd_cnt = 1;

	/* TEST */
	elvss_cmd.cmds->payload[1] = vdd->temperature > 0 ? vdd->temperature : 0x80|(-1*vdd->temperature);

	/* Read B5h 23th para -> Write to B5h 23th para */
	elvss_cmd.cmds->payload[23] = vdd->display_status_dsi[ctrl->ndx].elvss_value1;

	*level_key = LEVEL1_KEY;

	return &elvss_cmd;
end:
	LCD_ERR("error");
	return NULL;
}

#if 0
static struct dsi_panel_cmds *mdss_elvss_temperature1(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *cmds = get_panel_tx_cmds(ctrl, TX_ELVSS_LOWTEMP);
	char elvss_22th_val;

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)cmds);
		return NULL;
	}

	/* OTP value - B5 22th */
	elvss_22th_val = vdd->display_status_dsi[ctrl->ndx].elvss_value1;
	LCD_DEBUG("OTP val %x\n", elvss_22th_val);

	/* 0xB5 1th TSET */
	cmds->cmds[0].payload[1] =
		vdd->temperature > 0 ? vdd->temperature : 0x80|(-1*vdd->temperature);

	LCD_DEBUG("acl : %d, interpolation_temp : %d temp : %d, cd : %d, B8 1st :0x%xn",
		vdd->acl_status, vdd->elvss_interpolation_temperature, vdd->temperature, vdd->candela_level,
		cmds->cmds[0].payload[1]);

	*level_key = LEVEL1_KEY;

	return cmds;
}
#endif

static struct dsi_panel_cmds *mdss_gamma(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds  *gamma_cmds = get_panel_tx_cmds(ctrl, TX_GAMMA);

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(gamma_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)gamma_cmds);
		return NULL;
	}

	LCD_DEBUG("bl_level : %d candela : %dCD\n", vdd->bl_level, vdd->candela_level);

	if (IS_ERR_OR_NULL(vdd->smart_dimming_dsi[ctrl->ndx]->generate_gamma)) {
		LCD_ERR("generate_gamma is NULL error");
		return NULL;
	} else {
		vdd->smart_dimming_dsi[ctrl->ndx]->generate_gamma(
			vdd->smart_dimming_dsi[ctrl->ndx],
			vdd->candela_level,
			&gamma_cmds->cmds[0].payload[1]);

		*level_key = LEVEL1_KEY;

		return gamma_cmds;
	}
}

/* IRC */
static int mdss_irc_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char irc_b8[2];
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	/* Read mtp (B5h 23th,24th) for elvss*/
	mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_IRC),
		irc_b8, LEVEL1_KEY);
	vdd->display_status_dsi[ctrl->ndx].irc_value1 = irc_b8[0]; /*0xB8 1st OTP value*/
	vdd->display_status_dsi[ctrl->ndx].irc_value2 = irc_b8[1]; /*0xB8 2nd OTP value*/

	return true;
}

static struct dsi_panel_cmds irc_cmd;
static struct dsi_panel_cmds *mdss_irc(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *irc_cmds = get_panel_tx_cmds(ctrl, TX_IRC_SUBDIVISION);
	int cd_index = 0;

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(irc_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)irc_cmds);
		return NULL;
	}

	if (IS_ERR_OR_NULL(irc_cmds->cmds)) {
		LCD_ERR("No irc_subdivision_tx_cmds\n");
		return NULL;
	}

	if (!vdd->samsung_support_irc)
		return NULL;

	/* IRC Subdivision works like as AID Subdivision */
	if (vdd->pac)
		cd_index = vdd->pac_cd_idx;
	else
		cd_index = vdd->bl_level;

	LCD_DEBUG("irc idx (%d)\n", cd_index);

	irc_cmd.cmds = &(irc_cmds->cmds[cd_index]);
	irc_cmd.cmd_cnt = 1;
	*level_key = LEVEL1_KEY;

	/* read B8 1st,2nd from MTP and write to B8 1st,2nd */
	irc_cmd.cmds->payload[1] = vdd->display_status_dsi[ctrl->ndx].irc_value1;
	irc_cmd.cmds->payload[2] = vdd->display_status_dsi[ctrl->ndx].irc_value2;

	return &irc_cmd;
}

static struct dsi_panel_cmds hbm_irc_cmd;
static struct dsi_panel_cmds *mdss_hbm_irc(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *hbm_irc_cmds = get_panel_tx_cmds(ctrl, TX_HBM_IRC);
	int para_idx = 0;

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(hbm_irc_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)hbm_irc_cmds);
		return NULL;
	}

	if (IS_ERR_OR_NULL(hbm_irc_cmds->cmds)) {
		LCD_ERR("No irc_tx_cmds\n");
		return NULL;
	}

	if (!vdd->samsung_support_irc)
		return NULL;

	*level_key = LEVEL1_KEY;

	para_idx = vdd->auto_brightness_level - vdd->auto_brightness;

	hbm_irc_cmd.cmds = &(hbm_irc_cmds->cmds[para_idx]);
	hbm_irc_cmd.cmd_cnt = 1;

	/* read B8 1st,2nd from MTP and write to B8 1st,2nd */
	hbm_irc_cmd.cmds->payload[1] = vdd->display_status_dsi[ctrl->ndx].irc_value1;
	hbm_irc_cmd.cmds->payload[2] = vdd->display_status_dsi[ctrl->ndx].irc_value2;

	return &hbm_irc_cmd;
}

// ========================
//			HMT
// ========================
static struct dsi_panel_cmds *mdss_gamma_hmt(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds  *hmt_gamma_cmds = get_panel_tx_cmds(ctrl, TX_HMT_GAMMA);

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(hmt_gamma_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)hmt_gamma_cmds);
		return NULL;
	}

	LCD_DEBUG("hmt_bl_level : %d candela : %dCD\n", vdd->hmt_stat.hmt_bl_level, vdd->hmt_stat.candela_level_hmt);

	if (IS_ERR_OR_NULL(vdd->smart_dimming_dsi_hmt[ctrl->ndx]->generate_gamma)) {
		LCD_ERR("generate_gamma is NULL");
		return NULL;
	} else {
		vdd->smart_dimming_dsi_hmt[ctrl->ndx]->generate_gamma(
			vdd->smart_dimming_dsi_hmt[ctrl->ndx],
			vdd->hmt_stat.candela_level_hmt,
			&hmt_gamma_cmds->cmds[0].payload[1]);

		*level_key = LEVEL1_KEY;

		return hmt_gamma_cmds;
	}
}

static struct dsi_panel_cmds hmt_aid_cmd;
static struct dsi_panel_cmds *mdss_aid_hmt(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds  *hmt_aid_cmds = get_panel_tx_cmds(ctrl, TX_HMT_AID);
	int cmd_idx = 0;

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	if (!vdd->dtsi_data[ctrl->ndx].hmt_reverse_aid_map_table[vdd->panel_revision].size ||
		vdd->hmt_stat.cmd_idx_hmt > vdd->dtsi_data[ctrl->ndx].hmt_reverse_aid_map_table[vdd->panel_revision].size)
		goto end;

	cmd_idx = vdd->dtsi_data[ctrl->ndx].hmt_reverse_aid_map_table[vdd->panel_revision].cmd_idx[vdd->hmt_stat.cmd_idx_hmt];

	hmt_aid_cmd.cmds = &hmt_aid_cmds->cmds[cmd_idx];
	hmt_aid_cmd.cmd_cnt = 1;

	*level_key = LEVEL1_KEY;

	return &hmt_aid_cmd;

end:
	LCD_ERR("error");
	return NULL;
}

static struct dsi_panel_cmds *mdss_elvss_hmt(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return NULL;
	}

	/* 0xB5 1th TSET */
	get_panel_tx_cmds(ctrl, TX_HMT_ELVSS)->cmds[0].payload[1] =
		vdd->temperature > 0 ? vdd->temperature : 0x80|(-1*vdd->temperature);

	/* ELVSS(MPS_CON) setting condition is equal to normal birghtness */ // B5 2nd para : MPS_CON
	if (vdd->hmt_stat.candela_level_hmt > 40) {
		get_panel_tx_cmds(ctrl, TX_HMT_ELVSS)->cmds[0].payload[2] = 0xDC;
	} else {
		get_panel_tx_cmds(ctrl, TX_HMT_ELVSS)->cmds[0].payload[2] = 0xCC;
	}

	*level_key = LEVEL1_KEY;

	return get_panel_tx_cmds(ctrl, TX_HMT_ELVSS);
}


static struct dsi_panel_cmds hmt_irc_cmd;
static struct dsi_panel_cmds *mdss_irc_hmt(struct mdss_dsi_ctrl_pdata *ctrl, int *level_key)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);
	struct dsi_panel_cmds *hmt_irc_cmds = get_panel_tx_cmds(ctrl, TX_HMT_IRC);
	int cd_index = 0;

	if (IS_ERR_OR_NULL(vdd) || IS_ERR_OR_NULL(hmt_irc_cmds)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx cmds : 0x%zx", (size_t)ctrl, (size_t)vdd, (size_t)hmt_irc_cmds);
		return NULL;
	}

	if (IS_ERR_OR_NULL(hmt_irc_cmds->cmds)) {
		LCD_ERR("No irc_subdivision_tx_cmds\n");
		return NULL;
	}

	if (!vdd->samsung_support_irc)
		return NULL;

	if (vdd->pac)
		cd_index = vdd->pac_cd_idx;
	else
		cd_index = vdd->bl_level;

	hmt_irc_cmd.cmds = &(hmt_irc_cmds->cmds[cd_index]);
	hmt_irc_cmd.cmd_cnt = 1;
	*level_key = LEVEL1_KEY;

	/* read B8 1st,2nd from MTP and write to B8 1st,2nd */
	hmt_irc_cmd.cmds->payload[1] = vdd->display_status_dsi[ctrl->ndx].irc_value1;
	hmt_irc_cmd.cmds->payload[2] = vdd->display_status_dsi[ctrl->ndx].irc_value2;

	return &hmt_irc_cmd;

}

static void mdss_make_sdimconf_hmt(struct mdss_dsi_ctrl_pdata *ctrl, struct samsung_display_driver_data *vdd)
{
	/* Set the mtp read buffer pointer and read the NVM value*/
	mdss_samsung_panel_data_read(ctrl, get_panel_rx_cmds(ctrl, RX_SMART_DIM_MTP),
				vdd->smart_dimming_dsi_hmt[ctrl->ndx]->mtp_buffer, LEVEL1_KEY);

	/* Initialize smart dimming related things here */
	/* lux_tab setting for 350cd */
	vdd->smart_dimming_dsi_hmt[ctrl->ndx]->lux_tab = vdd->dtsi_data[ctrl->ndx].hmt_candela_map_table[vdd->panel_revision].cd;
	vdd->smart_dimming_dsi_hmt[ctrl->ndx]->lux_tabsize = vdd->dtsi_data[ctrl->ndx].hmt_candela_map_table[vdd->panel_revision].tab_size;
	vdd->smart_dimming_dsi_hmt[ctrl->ndx]->man_id = vdd->manufacture_id_dsi[ctrl->ndx];
	if (vdd->panel_func.samsung_panel_revision)
		vdd->smart_dimming_dsi_hmt[ctrl->ndx]->panel_revision = vdd->panel_func.samsung_panel_revision(ctrl);

	/* Just a safety check to ensure smart dimming data is initialised well */
	vdd->smart_dimming_dsi_hmt[ctrl->ndx]->init(vdd->smart_dimming_dsi_hmt[ctrl->ndx]);

	LCD_INFO("[HMT] smart dimming done!\n");
}

static int mdss_samart_dimming_init_hmt(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct samsung_display_driver_data *vdd = check_valid_ctrl(ctrl);

	LCD_INFO("DSI%d : ++\n", ctrl->ndx);

	if (IS_ERR_OR_NULL(vdd)) {
		LCD_ERR("Invalid data ctrl : 0x%zx vdd : 0x%zx", (size_t)ctrl, (size_t)vdd);
		return false;
	}

	vdd->smart_dimming_dsi_hmt[ctrl->ndx] = vdd->panel_func.samsung_smart_get_conf_hmt();

	if (IS_ERR_OR_NULL(vdd->smart_dimming_dsi_hmt[ctrl->ndx])) {
		LCD_ERR("DSI%d error", ctrl->ndx);
		return false;
	} else {
		vdd->hmt_stat.hmt_on = 0;
		vdd->hmt_stat.hmt_bl_level = 0;
		vdd->hmt_stat.hmt_reverse = 0;
		vdd->hmt_stat.hmt_is_first = 1;

		mdss_make_sdimconf_hmt(ctrl, vdd);

		vdd->smart_dimming_hmt_loaded_dsi[ctrl->ndx] = true;
	}

	LCD_INFO("DSI%d : --\n", ctrl->ndx);

	return true;
}

static int mdss_update_panel_lpm_cmds(struct mdss_dsi_ctrl_pdata *ctrl, int bl_level, int mode)
{
	struct samsung_display_driver_data *vdd = NULL;
	struct dsi_panel_cmds *lpm_on = NULL;

	if (IS_ERR_OR_NULL(ctrl))
		goto end;

	vdd = check_valid_ctrl(ctrl);

	lpm_on = get_panel_tx_cmds(ctrl, TX_LPM_ON);

	switch (bl_level) {
	case PANEL_LPM_40NIT:
	case PANEL_LPM_60NIT:
		lpm_on->cmds[3].payload[2] = 0x0C;
		lpm_on->cmds[4].payload[1] = 0x02;
		break;
	case PANEL_LPM_2NIT:
	default:
		lpm_on->cmds[3].payload[2] = 0x8C;
		lpm_on->cmds[4].payload[1] = 0x03;
		break;
	}

end:
	return 0;
}

static void mdss_get_panel_lpm_mode(struct mdss_dsi_ctrl_pdata *ctrl, u8 *mode)
{
	struct samsung_display_driver_data *vdd = NULL;
	int panel_lpm_mode = 0, lpm_bl_level = 0;

	if (IS_ERR_OR_NULL(ctrl))
		return;

	/*
	 * if the mode value is lower than MAX_LPM_MODE
	 * this function was not called by mdss_samsung_alpm_store()
	 * so the mode will not be changed
	 */
	if (*mode < MAX_LPM_MODE)
		return;

	vdd = check_valid_ctrl(ctrl);

	/* default Hz is 30Hz */
	vdd->panel_lpm.hz = TX_LPM_30HZ;

	/* Check mode and bl_level */
	switch (*mode) {
	case AOD_MODE_ALPM_2NIT_ON:
		panel_lpm_mode = ALPM_MODE_ON;
		lpm_bl_level = PANEL_LPM_2NIT;
		break;
	case AOD_MODE_HLPM_2NIT_ON:
		panel_lpm_mode = HLPM_MODE_ON;
		lpm_bl_level = PANEL_LPM_2NIT;
		break;
	case AOD_MODE_ALPM_60NIT_ON:
		panel_lpm_mode = ALPM_MODE_ON;
		lpm_bl_level = PANEL_LPM_60NIT;
		break;
	case AOD_MODE_HLPM_60NIT_ON:
		panel_lpm_mode = HLPM_MODE_ON;
		lpm_bl_level = PANEL_LPM_60NIT;
		break;
	default:
		panel_lpm_mode = MODE_OFF;
		break;
	}

	*mode = panel_lpm_mode;

	/* Save mode and bl_level */
	vdd->panel_lpm.lpm_bl_level = lpm_bl_level;

	mdss_update_panel_lpm_cmds(ctrl, lpm_bl_level, panel_lpm_mode);
}

static void dsi_update_mdnie_data(void)
{
	/* Update mdnie command */
	mdnie_data.DSI0_COLOR_BLIND_MDNIE_1 = DSI0_COLOR_BLIND_MDNIE_1;
	mdnie_data.DSI0_RGB_SENSOR_MDNIE_1 = DSI0_RGB_SENSOR_MDNIE_1;
	mdnie_data.DSI0_RGB_SENSOR_MDNIE_2 = DSI0_RGB_SENSOR_MDNIE_2;
	mdnie_data.DSI0_RGB_SENSOR_MDNIE_3 = DSI0_RGB_SENSOR_MDNIE_3;
	mdnie_data.DSI0_TRANS_DIMMING_MDNIE = DSI0_RGB_SENSOR_MDNIE_3;

	mdnie_data.DSI0_BYPASS_MDNIE = DSI0_BYPASS_MDNIE;
	mdnie_data.DSI0_NEGATIVE_MDNIE = DSI0_NEGATIVE_MDNIE;
	mdnie_data.DSI0_COLOR_BLIND_MDNIE = DSI0_COLOR_BLIND_MDNIE;
	mdnie_data.DSI0_HBM_CE_MDNIE = DSI0_HBM_CE_MDNIE;
	mdnie_data.DSI0_RGB_SENSOR_MDNIE = DSI0_RGB_SENSOR_MDNIE;
	mdnie_data.DSI0_GRAYSCALE_MDNIE = DSI0_GRAYSCALE_MDNIE;
	mdnie_data.DSI0_GRAYSCALE_NEGATIVE_MDNIE = DSI0_GRAYSCALE_NEGATIVE_MDNIE;
	mdnie_data.DSI0_CURTAIN = DSI0_SCREEN_CURTAIN_MDNIE;
	mdnie_data.DSI0_NIGHT_MODE_MDNIE = DSI0_NIGHT_MODE_MDNIE;
	mdnie_data.DSI0_NIGHT_MODE_MDNIE_SCR = DSI0_NIGHT_MODE_MDNIE_1;
	mdnie_data.DSI0_COLOR_BLIND_MDNIE_SCR = DSI0_COLOR_BLIND_MDNIE_1;
	mdnie_data.DSI0_RGB_SENSOR_MDNIE_SCR = DSI0_RGB_SENSOR_MDNIE_1;
	mdnie_data.DSI0_COLOR_LENS_MDNIE = DSI0_COLOR_LENS_MDNIE;
	mdnie_data.DSI0_COLOR_LENS_MDNIE_SCR = DSI0_COLOR_LENS_MDNIE_1;

	mdnie_data.mdnie_tune_value_dsi0 = mdnie_tune_value_dsi0;
	mdnie_data.hmt_color_temperature_tune_value_dsi0 = hmt_color_temperature_tune_value_dsi0;

	/* Update MDNIE data related with size, offset or index */
	mdnie_data.dsi0_bypass_mdnie_size = ARRAY_SIZE(DSI0_BYPASS_MDNIE);
	mdnie_data.mdnie_color_blinde_cmd_offset = MDNIE_COLOR_BLINDE_CMD_OFFSET;
	mdnie_data.mdnie_step_index[MDNIE_STEP1] = MDNIE_STEP1_INDEX;
	mdnie_data.mdnie_step_index[MDNIE_STEP2] = MDNIE_STEP2_INDEX;
	mdnie_data.mdnie_step_index[MDNIE_STEP3] = MDNIE_STEP3_INDEX;
	mdnie_data.address_scr_white[ADDRESS_SCR_WHITE_RED_OFFSET] = ADDRESS_SCR_WHITE_RED;
	mdnie_data.address_scr_white[ADDRESS_SCR_WHITE_GREEN_OFFSET] = ADDRESS_SCR_WHITE_GREEN;
	mdnie_data.address_scr_white[ADDRESS_SCR_WHITE_BLUE_OFFSET] = ADDRESS_SCR_WHITE_BLUE;
	mdnie_data.DSI0_NIGHT_MODE_MDNIE = DSI0_NIGHT_MODE_MDNIE;
//	mdnie_data.DSI0_NIGHT_MODE_MDNIE_SCR = DSI0_NIGHT_MODE_MDNIE_2;
	mdnie_data.dsi0_rgb_sensor_mdnie_1_size = DSI0_RGB_SENSOR_MDNIE_1_SIZE;
	mdnie_data.dsi0_rgb_sensor_mdnie_2_size = DSI0_RGB_SENSOR_MDNIE_2_SIZE;
	mdnie_data.dsi0_rgb_sensor_mdnie_3_size = DSI0_RGB_SENSOR_MDNIE_3_SIZE;
//	mdnie_data.dsi0_rgb_sensor_mdnie_index = MDNIE_RGB_SENSOR_INDEX;
	mdnie_data.dsi0_trans_dimming_data_index = MDNIE_TRANS_DIMMING_DATA_INDEX;
	mdnie_data.dsi0_adjust_ldu_table = adjust_ldu_data;
	mdnie_data.dsi1_adjust_ldu_table = NULL;
	mdnie_data.dsi0_max_adjust_ldu = 6;
	mdnie_data.dsi1_max_adjust_ldu = 6;
	mdnie_data.dsi0_night_mode_table = night_mode_data;
	mdnie_data.dsi1_night_mode_table = NULL;
	mdnie_data.dsi0_max_night_mode_index = 11;
	mdnie_data.dsi1_max_night_mode_index = 11;
	mdnie_data.dsi0_color_lens_table = color_lens_data;
	mdnie_data.dsi1_color_lens_table = NULL;
	mdnie_data.dsi0_white_default_r = 0xff;
	mdnie_data.dsi0_white_default_g = 0xff;
	mdnie_data.dsi0_white_default_b = 0xff;
	mdnie_data.dsi0_white_rgb_enabled = 0;
	mdnie_data.dsi1_white_default_r = 0xff;
	mdnie_data.dsi1_white_default_g = 0xff;
	mdnie_data.dsi1_white_default_b = 0xff;
	mdnie_data.dsi1_white_rgb_enabled = 0;
	mdnie_data.dsi0_scr_step_index = MDNIE_STEP1_INDEX;
	mdnie_data.dsi1_scr_step_index = MDNIE_STEP1_INDEX;
	mdnie_data.light_notification_tune_value_dsi0 = light_notification_tune_value_dsi0;
	mdnie_data.light_notification_tune_value_dsi1 = light_notification_tune_value_dsi0;
}


#if 0 //joann_test
static int multires;
static void mdss_samsung_event_frame_update(struct mdss_panel_data *pdata, int event, void *arg)
{
	int ndx;
	struct mdss_dsi_ctrl_pdata *ctrl = NULL;
	struct samsung_display_driver_data *vdd =
		(struct samsung_display_driver_data *)pdata->panel_private;
	struct panel_func *panel_func = NULL;

	ctrl = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	panel_func = &vdd->panel_func;

	ndx = display_ndx_check(ctrl);

	if (ctrl->cmd_sync_wait_broadcast) {
		if (ctrl->cmd_sync_wait_trigger) {
			if (vdd->display_status_dsi[ndx].wait_disp_on) {
				ATRACE_BEGIN(__func__);
				mdss_samsung_send_cmd(ctrl, PANEL_DISPLAY_ON);
				vdd->display_status_dsi[ndx].wait_disp_on = 0;

				if (vdd->panel_func.samsung_backlight_late_on)
					vdd->panel_func.samsung_backlight_late_on(ctrl);

				if (vdd->dtsi_data[0].hmt_enabled &&
					vdd->vdd_blank_mode[0] != FB_BLANK_NORMAL) {
					if (vdd->hmt_stat.hmt_on) {
						LCD_INFO("hmt reset ..\n");
						vdd->hmt_stat.hmt_enable(ctrl, vdd);
						vdd->hmt_stat.hmt_reverse_update(ctrl, 1);
						vdd->hmt_stat.hmt_bright_update(ctrl);
					}
				}
				LCD_INFO("DISPLAY_ON\n");
				ATRACE_END(__func__);
			}
		} else
			vdd->display_status_dsi[ndx].wait_disp_on = 0;
	} else {
		/* Check TE duration when the panel turned on */
		/*
		if (vdd->display_status_dsi[ndx].wait_disp_on) {
			vdd->te_fitting_info.status &= ~TE_FITTING_DONE;
			vdd->te_fitting_info.te_duration = 0;
		}
		 */

		if (vdd->dtsi_data[ndx].samsung_osc_te_fitting &&
				!(vdd->te_fitting_info.status & TE_FITTING_DONE)) {
			if (panel_func->mdss_samsung_event_osc_te_fitting)
				panel_func->mdss_samsung_event_osc_te_fitting(pdata, event, arg);
		}

		if (vdd->display_status_dsi[ndx].wait_disp_on) {
			MDSS_XLOG(ndx);
			ATRACE_BEGIN(__func__);
			if (!IS_ERR_OR_NULL(vdd->dtsi_data[DISPLAY_1].display_on_tx_cmds[vdd->panel_revision].cmds))
				mdss_samsung_send_cmd(ctrl, PANEL_DISPLAY_ON);
			vdd->display_status_dsi[ndx].wait_disp_on = 0;

			if (vdd->panel_func.samsung_backlight_late_on)
				vdd->panel_func.samsung_backlight_late_on(ctrl);

			if (vdd->dtsi_data[0].hmt_enabled &&
				vdd->vdd_blank_mode[0] != FB_BLANK_NORMAL) {
				if (vdd->hmt_stat.hmt_on) {
					LCD_INFO("hmt reset ..\n");
					vdd->hmt_stat.hmt_enable(ctrl, vdd);
					vdd->hmt_stat.hmt_reverse_update(ctrl, 1);
					vdd->hmt_stat.hmt_bright_update(ctrl);
				}
			}
			MDSS_XLOG(ndx);
			LCD_INFO("DISPLAY_ON\n");
			ATRACE_END(__func__);
		}
	}

	if (multires) {
		if (--multires == 0)
			mdss_samsung_send_cmd(ctrl, PANEL_DISPLAY_ON);
	}

}
#endif

#if 0
static void mdss_panel_multires(struct samsung_display_driver_data *vdd)
{

	if (vdd->multires_stat.prev_mode != vdd->multires_stat.curr_mode) {
		LCD_INFO("vdd->multires_stat.prev_mode = %d, vdd-multires_stat.curr_mode = %d\n",
			vdd->multires_stat.prev_mode, vdd->multires_stat.curr_mode);

		mdss_samsung_send_cmd(vdd->ctrl_dsi[DISPLAY_1], PANEL_DISPLAY_OFF);
		multires = 3;

		if (vdd->multires_stat.curr_mode == MULTIRES_FHD)
			mdss_samsung_send_cmd(vdd->ctrl_dsi[DISPLAY_1], PANEL_MULTIRES_FHD);
		else if (vdd->multires_stat.curr_mode == MULTIRES_HD)
			mdss_samsung_send_cmd(vdd->ctrl_dsi[DISPLAY_1], PANEL_MULTIRES_HD);
		vdd->multires_stat.prev_mode = vdd->multires_stat.curr_mode;


	}
}
#endif

static void mdss_panel_init(struct samsung_display_driver_data *vdd)
{
	pr_info("%s", __func__);

	/* ON/OFF */
	vdd->panel_func.samsung_panel_on_pre = mdss_panel_on_pre;
	vdd->panel_func.samsung_panel_on_post = mdss_panel_on_post;
//	vdd->panel_func.samsung_panel_off_post = mdss_panel_off_post;

	/* DDI RX */
	vdd->panel_func.samsung_panel_revision = mdss_panel_revision;
	vdd->panel_func.samsung_manufacture_date_read = mdss_manufacture_date_read;
	vdd->panel_func.samsung_ddi_id_read = mdss_ddi_id_read;
	vdd->panel_func.samsung_cell_id_read = mdss_cell_id_read;
	vdd->panel_func.samsung_octa_id_read = mdss_octa_id_read;
	vdd->panel_func.samsung_elvss_read = mdss_elvss_read;
	vdd->panel_func.samsung_hbm_read = mdss_hbm_read;
	vdd->panel_func.samsung_mdnie_read = mdss_mdnie_read;
	vdd->panel_func.samsung_irc_read = mdss_irc_read;

	vdd->panel_func.samsung_smart_dimming_init = mdss_smart_dimming_init;

	vdd->panel_func.samsung_smart_get_conf = smart_get_conf_S6E3FA7_AMS628RF01;

	/* Brightness */
	vdd->panel_func.samsung_brightness_hbm_off = NULL;
	vdd->panel_func.samsung_brightness_aid = mdss_aid;
	vdd->panel_func.samsung_brightness_acl_on = mdss_acl_on;
	vdd->panel_func.samsung_brightness_acl_percent = NULL;
	vdd->panel_func.samsung_brightness_acl_off = mdss_acl_off;
	vdd->panel_func.samsung_brightness_elvss = mdss_elvss;
	//vdd->panel_func.samsung_brightness_elvss_temperature1 = mdss_elvss_temperature1;
	vdd->panel_func.samsung_brightness_elvss_temperature1 = NULL;
	vdd->panel_func.samsung_brightness_elvss_temperature2 = NULL;
	vdd->panel_func.samsung_brightness_vint = mdss_vint;
	vdd->panel_func.samsung_brightness_irc = mdss_irc;
	vdd->panel_func.samsung_brightness_gamma = mdss_gamma;

	/* HBM */
	vdd->panel_func.samsung_hbm_gamma = mdss_hbm_gamma;
	vdd->panel_func.samsung_hbm_etc = mdss_hbm_etc;
	vdd->panel_func.samsung_hbm_irc = mdss_hbm_irc;
	vdd->panel_func.get_hbm_candela_value = get_hbm_candela_value;

	/* HMT */
	vdd->panel_func.samsung_brightness_gamma_hmt = mdss_gamma_hmt;
	vdd->panel_func.samsung_brightness_aid_hmt = mdss_aid_hmt;
	vdd->panel_func.samsung_brightness_elvss_hmt = mdss_elvss_hmt;
	vdd->panel_func.samsung_brightness_vint_hmt = NULL;
	vdd->panel_func.samsung_brightness_irc_hmt = mdss_irc_hmt;
	vdd->panel_func.samsung_smart_dimming_hmt_init = mdss_samart_dimming_init_hmt;
	vdd->panel_func.samsung_smart_get_conf_hmt = smart_get_conf_S6E3FA7_AMS628RF01_hmt;

	/* Panel LPM */
	vdd->panel_func.samsung_get_panel_lpm_mode = mdss_get_panel_lpm_mode;

	/* default brightness */
	vdd->bl_level = 255;

	/* mdnie */
	vdd->support_mdnie_lite = true;
	vdd->support_mdnie_trans_dimming = true;
	/* for mdnie tuning */
	vdd->mdnie_tune_size[0] = sizeof(DSI0_BYPASS_MDNIE_1);
	vdd->mdnie_tune_size[1] = sizeof(DSI0_BYPASS_MDNIE_2);
	vdd->mdnie_tune_size[2] = sizeof(DSI0_BYPASS_MDNIE_3);
	dsi_update_mdnie_data();

	/* send recovery pck before sending image date (for ESD recovery) */
	vdd->send_esd_recovery = false;

	vdd->auto_brightness_level = 13;

	/* Support DDI HW CURSOR */
	vdd->panel_func.ddi_hw_cursor = NULL;

	/* Enable panic on first pingpong timeout */
	vdd->debug_data->panic_on_pptimeout = true;

	/* COLOR WEAKNESS */
	vdd->panel_func.color_weakness_ccb_on_off = NULL;

	/* Support DDI HW CURSOR */
	vdd->panel_func.ddi_hw_cursor = NULL;

#if 0 //joann_test
	vdd->panel_func.mdss_samsung_event_frame_update =
		mdss_samsung_event_frame_update;
#endif

	/* ACL default ON */
	vdd->acl_status = 1;

	if (!ss_self_display_init()) {
		vdd->self_disp.operation[FLAG_SELF_MASK].img_buf = self_mask_img_data;
		vdd->self_disp.operation[FLAG_SELF_MASK].img_size = ARRAY_SIZE(self_mask_img_data);
		make_self_dispaly_img_cmds(TX_SELF_MASK_IMAGE, FLAG_SELF_MASK);
		vdd->self_disp.operation[FLAG_SELF_MASK].img_checksum = SELF_MASK_IMG_CHECKSUM;

		vdd->self_disp.operation[FLAG_SELF_ICON].img_buf = self_icon_img_data;
		vdd->self_disp.operation[FLAG_SELF_ICON].img_size = ARRAY_SIZE(self_icon_img_data);
		make_self_dispaly_img_cmds(TX_SELF_ICON_IMAGE, FLAG_SELF_ICON);

		vdd->self_disp.operation[FLAG_SELF_ACLK].img_buf = self_aclock_img_data;
		vdd->self_disp.operation[FLAG_SELF_ACLK].img_size = ARRAY_SIZE(self_aclock_img_data);
		make_self_dispaly_img_cmds(TX_SELF_ACLOCK_IMAGE, FLAG_SELF_ACLK);

		vdd->self_disp.operation[FLAG_SELF_DCLK].img_buf = self_dclock_img_data;
		vdd->self_disp.operation[FLAG_SELF_DCLK].img_size = ARRAY_SIZE(self_dclock_img_data);
		make_self_dispaly_img_cmds(TX_SELF_DCLOCK_IMAGE, FLAG_SELF_DCLK);
	}

	return;
}

static int __init samsung_panel_init(void)
{
	struct samsung_display_driver_data *vdd = samsung_get_vdd();
	char panel_string[] = "ss_dsi_panel_S6E3FA7_AMS628RF01_FHD";

	vdd->panel_name = mdss_mdp_panel + 8;

	LCD_INFO("%s / %s\n", vdd->panel_name, panel_string);

	if (!strncmp(vdd->panel_name, panel_string, strlen(panel_string)))
		vdd->panel_func.samsung_panel_init = mdss_panel_init;

	return 0;
}
early_initcall(samsung_panel_init);
