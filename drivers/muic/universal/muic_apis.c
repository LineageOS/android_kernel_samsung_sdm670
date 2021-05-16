/*
 * muic_apis.c
 *
 * Copyright (C) 2014 Samsung Electronics
 * Thomas Ryu <smilesr.ryu@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/host_notify.h>
#include <linux/string.h>
#if defined(CONFIG_MUIC_SUPPORT_EARJACK)
#include <linux/input.h>
#include <linux/switch.h>
#endif

#include <linux/muic/muic.h>

#if defined(CONFIG_MUIC_NOTIFIER)
#include <linux/muic/muic_notifier.h>
#endif /* CONFIG_MUIC_NOTIFIER */

#if defined (CONFIG_OF)
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#endif /* CONFIG_OF */

#include "muic-internal.h"
#include "muic_i2c.h"
#include "muic_regmap.h"

int attach_ta(muic_data_t *pmuic)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;

	if (pvendor->attach_ta) {
		pr_info("%s: ", __func__);
		pvendor->attach_ta(pmuic->regmapdesc);
	} 
	else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return 0;
}

int detach_ta(muic_data_t *pmuic)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;

	if (pvendor->detach_ta) {
		pr_info("%s: ", __func__);
		pvendor->detach_ta(pmuic->regmapdesc);
	} 
	else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return 0;
}
#if !defined(CONFIG_MUIC_SUPPORT_KEYBOARDDOCK)
static int get_charger_type(muic_data_t *pmuic)
{
	struct regmap_ops *pops = pmuic->regmapdesc->regmapops;
	int uattr;

	pops->ioctl(pmuic->regmapdesc, GET_CHGTYPE, NULL, &uattr);
	return regmap_read_value(pmuic->regmapdesc, uattr);
}
#endif
static int set_BCD_RESCAN_reg(muic_data_t *pmuic, int value)
{
	struct regmap_ops *pops = pmuic->regmapdesc->regmapops;
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int uattr, ret;

	if (pvendor && pvendor->rescan) {
		ret = pvendor->rescan(pmuic->regmapdesc, value);
		return ret;
	}

	pops->ioctl(pmuic->regmapdesc, GET_RESID3, NULL, &uattr);

#if defined(CONFIG_MUIC_UNIVERSAL_SM5504)
	value = !value;
#else
	uattr |= _ATTR_OVERWRITE_M;
#endif

	ret = regmap_write_value(pmuic->regmapdesc, uattr, value);
	_REGMAP_TRACE(pmuic->regmapdesc, 'w', ret, uattr, value);

	return ret;
}

int do_BCD_rescan(muic_data_t *pmuic)
{
#if !defined(CONFIG_MUIC_SUPPORT_KEYBOARDDOCK)
	static int bcd_rescan = 0;

	pr_info("%s\n", __func__);

	if (bcd_rescan) {
		int chg_type = get_charger_type(pmuic);
		int new_dev = 0;

		bcd_rescan = 0;

		if (chg_type < 0)
			pr_err("%s:%s err %d\n", MUIC_DEV_NAME, __func__, chg_type);

		pr_info("%s [MUIC] BCD result chg_type = 0x%x \n", __func__, chg_type);
		switch(chg_type) {
		case 0x01 : // DCP
			new_dev = ATTACHED_DEV_TA_MUIC;
			break;
		case 0x02 : // CDP
			new_dev = ATTACHED_DEV_CDP_MUIC;
			break;
		case 0x04 : // SDP
			new_dev = ATTACHED_DEV_USB_MUIC;
			break;
		case 0x08 : // Time out SDP
			new_dev = ATTACHED_DEV_USB_MUIC;
			break;
		case 0x10 : // U200
			new_dev = ATTACHED_DEV_TA_MUIC;
			break;
		}

		return new_dev;
	}

	pr_info("[MUIC] 219K USB Cable/Charger Connected\n");
#endif
	pr_info("[MUIC] BCD rescan\n");

	// 0x21 -> 1  0x21 -> 0
	set_BCD_RESCAN_reg(pmuic, 0x01);
	msleep(1);
	pr_info("[MUIC] Writing BCD_RECAN\n");
	set_BCD_RESCAN_reg(pmuic, 0x00);
#if !defined(CONFIG_MUIC_SUPPORT_KEYBOARDDOCK)
	bcd_rescan = 1;
#endif
	return 0;
}

int get_switch_mode(muic_data_t *pmuic)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int val=0;

	if (pvendor->get_switch) {
		pr_info("%s: \n", __func__);
		val = pvendor->get_switch(pmuic->regmapdesc);
	}
	else {
		pr_info("%s: No Vendor API ready.\n", __func__);
		val = -1;
	}
	return val;
}

void set_switch_mode(muic_data_t *pmuic, int mode)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;

	if (pvendor->set_switch) {
		pvendor->set_switch(pmuic->regmapdesc,mode);
		pr_info("%s: done\n", __func__);
	} 
	else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return;
}

#if defined(CONFIG_MUIC_SUPPORT_EARJACK)
void set_earjack_mode(muic_data_t *pmuic, int mode)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int ret = 0;

	if (pvendor->set_earjack_mode) {
		ret = pvendor->set_earjack_mode(pmuic->regmapdesc,mode);
		if (ret) 
			pr_info("%s: done\n", __func__);
	} 
	else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return;
}

void set_earjack_state(muic_data_t *pmuic, int intr1, int intr2, int btn1, int btn2)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int ret = 0;

	if (pvendor->set_earjack_state) {
		ret = pvendor->set_earjack_state(pmuic->regmapdesc, intr1, intr2, btn1, btn2);
		if (ret) 
			pr_info("%s: done\n", __func__);
	}
	else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return;
}

int get_attached_earjack_type(muic_data_t *pmuic)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int ret = 0;

	if (pvendor->attached_earjack_type) {
		pr_info("%s: ", __func__);
		ret = pvendor->attached_earjack_type(pmuic->regmapdesc);
	} else {
		pr_info("%s: No Vendor API ready.\n", __func__);
		ret = ATTACHED_DEV_NONE_MUIC;
	}
	return ret;
}
#endif

int get_adc_scan_mode(muic_data_t *pmuic)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int value = 0;

	if (pvendor->get_adc_scan_mode) {
		pr_info("%s: ", __func__);
		value = pvendor->get_adc_scan_mode(pmuic->regmapdesc);
	} else{
		pr_info("%s: No Vendor API ready.\n", __func__);
		value = -1;
	}
	return value;
}

void set_adc_scan_mode(muic_data_t *pmuic, const u8 val)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;

	if (pvendor->set_adc_scan_mode) {
		pr_info("%s: ", __func__);
		pvendor->set_adc_scan_mode(pmuic->regmapdesc,val);
	} else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return;
}

#define com_to_open com_to_open_with_vbus

#ifndef com_to_open
int com_to_open(muic_data_t *pmuic)
{
	int ret = 0;

	ret = regmap_com_to(pmuic, COM_OPEN);
	if (ret < 0)
		pr_err("%s:%s com_to_open err\n", MUIC_DEV_NAME, __func__);

	return ret;
}
#endif
int com_to_open_with_vbus(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);
	ret = regmap_com_to(pmuic, COM_OPEN_WITH_V_BUS);
	if (ret < 0)
		pr_err("%s:%s com_to_open err\n", MUIC_DEV_NAME, __func__);

	return ret;
}

int com_to_usb_ap(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);
	ret = regmap_com_to(pmuic, COM_USB_AP);
	if (ret < 0)
		pr_err("%s:%s set_com_usb err\n", MUIC_DEV_NAME, __func__);

	return ret;
}

int com_to_usb_cp(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);
	ret = regmap_com_to(pmuic, COM_USB_CP);
	if (ret < 0)
		pr_err("%s:%s set_com_usb err\n", MUIC_DEV_NAME, __func__);

	return ret;
}

int cable_redetection(muic_data_t *pmuic)
{
	switch (do_BCD_rescan(pmuic)) {
		case CHGTYPE_NONE:
			pmuic->legacy_dev = ATTACHED_DEV_UNDEFINED_CHARGING_MUIC;
			com_to_open_with_vbus(pmuic);
			break;
		case CHGTYPE_DCP:
		case CHGTYPE_U200:
		case CHGTYPE_LO_TA:
			pmuic->legacy_dev = ATTACHED_DEV_TA_MUIC;
			com_to_open_with_vbus(pmuic);
			break;
		case CHGTYPE_CDP:
			pmuic->legacy_dev = ATTACHED_DEV_CDP_MUIC;
			break;
		case CHGTYPE_SDP:
			pmuic->legacy_dev = ATTACHED_DEV_USB_MUIC;
			break;
		case CHGTYPE_TIMEOUT_SDP:
			pmuic->legacy_dev = ATTACHED_DEV_TIMEOUT_OPEN_MUIC;
			break;
		default:
			pr_info("%s: Unsupported Chger Type\n", __func__);
		return 0;
		}

	muic_notifier_attach_attached_dev(pmuic->legacy_dev);
	
	return 0;
}

static int set_rustproof_mode(struct regmap_desc *pdesc, int op)
{
	struct vendor_ops *pvendor = pdesc->vendorops;

	if (pvendor->set_rustproof) {
		pr_info("%s: %s", __func__, op ? "On" : "Off");
		pvendor->set_rustproof(pdesc, op);
	} else
		pr_err("%s: No Vendor API ready.\n", __func__);

	return 0;
}

int com_to_uart_ap(muic_data_t *pmuic)
{
	int com_index = 0, ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);
	com_index = pmuic->is_rustproof ? COM_OPEN_WITH_V_BUS : COM_UART_AP;

	ret = regmap_com_to(pmuic, com_index);
	if (ret < 0)
		pr_err("%s:%s set_com_uart err\n", MUIC_DEV_NAME, __func__);

	if (pmuic->is_rustproof) {
		pr_info("%s:%s rustproof mode Enabled\n",
			MUIC_DEV_NAME, __func__);

		set_rustproof_mode(pmuic->regmapdesc, 1);
	}

	return ret;
}

int com_to_uart_cp(muic_data_t *pmuic)
{
	int com_index = 0, ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);
	com_index = pmuic->is_rustproof ? COM_OPEN_WITH_V_BUS : COM_UART_CP;

	ret = regmap_com_to(pmuic, com_index);
	if (ret < 0)
		pr_err("%s:%s set_com_uart err\n", MUIC_DEV_NAME, __func__);

	if (pmuic->is_rustproof) {
		pr_info("%s:%s rustproof mode Enabled\n",
			MUIC_DEV_NAME, __func__);

		set_rustproof_mode(pmuic->regmapdesc, 1);
	}

	return ret;
}

int com_to_audio(muic_data_t *pmuic)
{
	int ret = 0;

	ret = regmap_com_to(pmuic, COM_AUDIO);
	if (ret < 0)
		pr_err("%s:%s set_com_audio err\n", MUIC_DEV_NAME, __func__);

	return ret;
}

int switch_to_ap_usb(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = com_to_usb_ap(pmuic);
	if (ret < 0) {
		pr_err("%s:%s com->usb set err\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	return ret;
}

int switch_to_cp_usb(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = com_to_usb_cp(pmuic);
	if (ret < 0) {
		pr_err("%s:%s com->usb set err\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	return ret;
}

int switch_to_ap_uart(muic_data_t *pmuic)
{
	struct muic_platform_data *pdata = pmuic->pdata;
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	if (pdata->set_gpio_uart_sel)
		pdata->set_gpio_uart_sel(MUIC_PATH_UART_AP);

	ret = com_to_uart_ap(pmuic);
	if (ret < 0) {
		pr_err("%s:%s com->uart set err\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	return ret;
}

int switch_to_cp_uart(muic_data_t *pmuic)
{
	struct muic_platform_data *pdata = pmuic->pdata;
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	if (pdata->set_gpio_uart_sel)
		pdata->set_gpio_uart_sel(MUIC_PATH_UART_CP);

	pmuic->pdata->uart_path = MUIC_PATH_UART_CP;
	ret = com_to_uart_cp(pmuic);
	if (ret < 0) {
		pr_err("%s:%s com->uart set err\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	return ret;
}

int switch_to_audio(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

        ret = com_to_audio(pmuic);
	if (ret < 0) {
		pr_err("%s:%s com->audio set err\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	return ret;
}


int attach_uart_util(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	pmuic->attached_dev = new_dev;
	if (pmuic->pdata->usb_path == MUIC_PATH_UART_AP) {
		ret = switch_to_ap_uart(pmuic);
	}
	else if (pmuic->pdata->usb_path == MUIC_PATH_UART_CP) {
		ret = switch_to_cp_uart(pmuic);
	}
	else
		pr_warn("%s:%s invalid usb_path\n", MUIC_DEV_NAME, __func__);

	return ret;
}


int attach_usb_util(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	pmuic->attached_dev = new_dev;
	if (pmuic->pdata->usb_path == MUIC_PATH_USB_AP) {
		ret = switch_to_ap_usb(pmuic);
	}
	else if (pmuic->pdata->usb_path == MUIC_PATH_USB_CP) {
		ret = switch_to_cp_usb(pmuic);
	}
	else
		pr_warn("%s:%s invalid usb_path\n", MUIC_DEV_NAME, __func__);

	return ret;
}

int attach_usb(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	if (pmuic->attached_dev == new_dev) {
		pr_info("%s:%s duplicated(USB)\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);
#if defined(CONFIG_MUIC_SUPPORT_KEYBOARDDOCK)
	if (pmuic->vps_table == VPS_TYPE_SCATTERED)
		set_switch_mode(pmuic, SWMODE_MANUAL);
#endif
	ret = attach_usb_util(pmuic, new_dev);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}
	return ret;
}

int detach_usb(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s attached_dev type(%d)\n", MUIC_DEV_NAME, __func__,
			pmuic->attached_dev);

	ret = com_to_open_with_vbus(pmuic);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}

#if defined(CONFIG_SEC_DEBUG)
	pmuic->usb_to_ta_state = false;
#endif
	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

int attach_otg_usb(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	if (pmuic->attached_dev == new_dev) {
		pr_info("%s:%s duplicated(USB)\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	/* LANHUB doesn't work under AUTO switch mode, so turn it off */
	/* set MANUAL SW mode */
	set_switch_mode(pmuic,SWMODE_MANUAL);

	/* enable RAW DATA mode, only for OTG LANHUB */
	set_adc_scan_mode(pmuic,ADC_SCANMODE_CONTINUOUS);

	ret = switch_to_ap_usb(pmuic);

	pmuic->attached_dev = new_dev;

	return ret;
}

int detach_otg_usb(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s attached_dev type(%d)\n", MUIC_DEV_NAME, __func__,
			pmuic->attached_dev);

	ret = com_to_open_with_vbus(pmuic);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}

	if (get_switch_mode(pmuic) != SWMODE_AUTO)
		set_switch_mode(pmuic, SWMODE_AUTO);

	if (get_adc_scan_mode(pmuic) != ADC_SCANMODE_ONESHOT)
		set_adc_scan_mode(pmuic, ADC_SCANMODE_ONESHOT);

	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

int attach_ps_cable(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	pr_info("%s:%s new_dev(%d)\n", MUIC_DEV_NAME, __func__, new_dev);
	com_to_open_with_vbus(pmuic);

	pmuic->attached_dev = new_dev;

	return ret;
}

int detach_ps_cable(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}


/* Do the followings on attachment.
  * 1. Do not run charger detection.
  * 2. Set AP USB path
  * 3. Set continuous adc scan mode with USB's notification.
  */
int attach_gamepad(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
//	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int ret = 0;

	if (pmuic->attached_dev == new_dev) {
		pr_info("%s:%s duplicated(gamepad)\n", MUIC_DEV_NAME, __func__);
		return ret;
	}

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

//	if (pvendor && pvendor->enable_chgdet)
//		pvendor->enable_chgdet(pmuic->regmapdesc, 0); 

	ret = switch_to_ap_usb(pmuic);

	pmuic->attached_dev = new_dev;

	return 0;
}

int detach_gamepad(muic_data_t *pmuic)
{
//	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;
	int ret = 0;

	pr_info("%s:%s attached_dev type(%d)\n", MUIC_DEV_NAME, __func__,
			pmuic->attached_dev);

	ret = com_to_open_with_vbus(pmuic);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}

//	if (pvendor && pvendor->enable_chgdet)
//		pvendor->enable_chgdet(pmuic->regmapdesc, 1);

	set_adc_scan_mode(pmuic, ADC_SCANMODE_ONESHOT);

	pmuic->is_gamepad = false;
	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return 0;
}

#if defined(CONFIG_MUIC_SUPPORT_EARJACK)
int attach_earjack(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	pr_info("%s:%s, attached = %d, new = %d\n", MUIC_DEV_NAME, __func__, pmuic->attached_dev, new_dev);

	if (new_dev == ATTACHED_DEV_EARJACK_MUIC) {
	/*	Earjack processing	*/
		if (pmuic->is_earkeypressed) {
			/* send event sendend key type to upper layer */
			pmuic->is_earkeypressed = false;
			input_event(pmuic->input, EV_KEY,
					pmuic->old_keycode, pmuic->is_earkeypressed);
			input_sync(pmuic->input);
		}
		if (pmuic->attached_dev == new_dev) {
			pr_info("%s:%s duplicated(earjack)\n", MUIC_DEV_NAME, __func__);
			return ret;
		}
		set_earjack_mode(pmuic, 1);
		msleep(150);	

		ret = com_to_audio(pmuic);
		pmuic->attached_dev = new_dev;
	} 
	else if (new_dev == ATTACHED_STUCK_EARJACK_MUIC) {
		if (pmuic->is_earkeypressed) {
			/* send event sendend key type to upper layer */
			pmuic->is_earkeypressed = false;
			input_event(pmuic->input, EV_KEY,
					pmuic->old_keycode, pmuic->is_earkeypressed);
			input_sync(pmuic->input);
		}
		if (pmuic->attached_dev == new_dev) {
			pr_info("%s:%s duplicated(earjack)\n", MUIC_DEV_NAME, __func__);
			return ret;
		}
		ret = com_to_audio(pmuic);
		pmuic->attached_dev = ATTACHED_DEV_EARJACK_MUIC;	
	}
	else {
	/*	Earkey processing	*/
		int code = 0;
		switch(new_dev) {
			case ATTACHED_DEV_SEND_MUIC:
				code = KEY_MEDIA;
				pmuic->old_keycode = code;
				break;
			case ATTACHED_DEV_VOLDN_MUIC:
				code = KEY_VOLUMEDOWN;
				pmuic->old_keycode = code;
				break;
			case ATTACHED_DEV_VOLUP_MUIC:
				code = KEY_VOLUMEUP;
				pmuic->old_keycode = code;
				break;
			default:
				pr_warn("%s:%s unsupported dev=%dn",
						MUIC_DEV_NAME, __func__, new_dev);
				break;
		}
		/* send event sendend key type to upper layer */
		input_event(pmuic->input, EV_KEY, code, pmuic->is_earkeypressed);
		input_sync(pmuic->input);
#if defined(CONFIG_MUIC_UNIVERSAL_SM5703)	
		/* 
		 * SM5703 : when short key pressed, interrupt is occured on release key.
		 *			it needs to send release event immediately.
		 */
		input_event(pmuic->input, EV_KEY, code, 0);
		input_sync(pmuic->input);
#endif		
	}
	return 0;
}

int attach_long_earjackkey(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int code = 0;
	
	pr_info("%d:%s, attached = %d, new = %d\n", pmuic->is_earkeypressed, __func__, pmuic->attached_dev, new_dev);

	switch (new_dev) {
		case ATTACHED_DEV_LP_SEND_MUIC:
			code = KEY_MEDIA;
			pmuic->old_keycode = code;
			break;
		case ATTACHED_DEV_LP_VOLDN_MUIC:
			code = KEY_VOLUMEDOWN;
			pmuic->old_keycode = code;
			break;
		case ATTACHED_DEV_LP_VOLUP_MUIC:
			code = KEY_VOLUMEUP;
			pmuic->old_keycode = code;
			break;
		default:
			pr_warn("%s:%s unsupported dev=%dn",
					MUIC_DEV_NAME, __func__, new_dev);
			break;
	}

	input_event(pmuic->input, EV_KEY, code, pmuic->is_earkeypressed);
	input_sync(pmuic->input);

	return 0;
}

int detach_long_earjackkey(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int code = 0;

	pr_info("%d:%s, attached = %d, new = %d\n", pmuic->is_earkeypressed, __func__, pmuic->attached_dev, new_dev);

	switch(new_dev) {
		case ATTACHED_DEV_LR_SEND_MUIC:
			code = KEY_MEDIA;
			pmuic->old_keycode = code;
			break;
		case ATTACHED_DEV_LR_VOLDN_MUIC:
			code = KEY_VOLUMEDOWN;
			pmuic->old_keycode = code;
			break;
		case ATTACHED_DEV_LR_VOLUP_MUIC:
			code = KEY_VOLUMEUP;
			pmuic->old_keycode = code;
			break;
		default:
			pr_warn("%s:%s unsupported dev=%dn",
					MUIC_DEV_NAME, __func__, new_dev);
			break;
	}
	input_event(pmuic->input, EV_KEY, code, pmuic->is_earkeypressed);
	input_sync(pmuic->input);

	return 0;
}

int detach_earjack(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s attached_dev type(%d)\n", MUIC_DEV_NAME, __func__,
			pmuic->attached_dev);

	ret = com_to_open_with_vbus(pmuic);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}
	pmuic->is_earkeypressed = false;

	input_event(pmuic->input, EV_KEY, pmuic->old_keycode, pmuic->is_earkeypressed);
	input_sync(pmuic->input);

	pmuic->old_keycode = 0;

	set_earjack_mode(pmuic, 0);
	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return 0;
}
#endif

int attach_deskdock(muic_data_t *pmuic,
			muic_attached_dev_t new_dev)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	/* Audio-out doesn't work under AUTO switch mode, so turn it off */
	/* set MANUAL SW mode */
	set_switch_mode(pmuic,SWMODE_MANUAL);
	ret = com_to_audio(pmuic);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}

	pmuic->attached_dev = new_dev;

	return ret;
}

int detach_deskdock(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	set_switch_mode(pmuic,SWMODE_AUTO);
	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

int attach_audiodock(muic_data_t *pmuic,
			muic_attached_dev_t new_dev, u8 vbus)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = attach_usb_util(pmuic, new_dev);
	if (ret < 0)
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);

	return ret;
}

int detach_audiodock(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = com_to_open_with_vbus(pmuic);
	if (ret < 0)
		return ret;

	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

int attach_jig_uart_boot_off(muic_data_t *pmuic, muic_attached_dev_t new_dev,
				u8 vbvolt)
{
	struct muic_platform_data *pdata = pmuic->pdata;

	int ret = 0;

	pr_info("%s:%s JIG UART BOOT-OFF(0x%x)\n", MUIC_DEV_NAME, __func__,
			vbvolt);

	if (pdata->uart_path == MUIC_PATH_UART_AP)
		ret = switch_to_ap_uart(pmuic);
	else
		ret = switch_to_cp_uart(pmuic);

	if (ret < 0)
		pr_err("%s:%s com->uart set err\n", MUIC_DEV_NAME, __func__);
		
	/* if VBUS is enabled, call host_notify_cb to check if it is OTGTEST*/
	if (vbvolt) {
		if (pmuic->is_otg_test) {
			pr_info("%s:%s OTG_TEST\n", MUIC_DEV_NAME, __func__);
			/* in OTG_TEST mode, do not charge */
			new_dev = ATTACHED_DEV_JIG_UART_OFF_VB_OTG_MUIC;
		} else
			/* JIG_UART_OFF_VB */
			new_dev = ATTACHED_DEV_JIG_UART_OFF_VB_MUIC;
	} else
		new_dev = ATTACHED_DEV_JIG_UART_OFF_MUIC;

	pmuic->attached_dev = new_dev;

	return new_dev;
}
int detach_jig_uart_boot_off(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	if(pmuic->is_rustproof) {
		pr_info("%s:%s rustproof mode : Set Auto SW mode\n",
			MUIC_DEV_NAME, __func__);

		set_rustproof_mode(pmuic->regmapdesc, 0);
	}

	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

/*
 * QA's requirement on JIG_UART_ON(619K)
 * 1. Factory Test Mode
 *     Send a deskdock Noti. to wakeup the device.
 *      (OPEN->619K->OPEN->523K )
 * 2. Normal
 *     Do not charge the device. (No charging Icon and current)
 *     Need to set the path OPEN and cut off VBUS input.
 */
int attach_jig_uart_boot_on(muic_data_t *pmuic, muic_attached_dev_t new_dev)
{
	int com_index = COM_OPEN;
	int ret = 0;

	pr_info("%s:%s JIG UART BOOT-ON(0x%x)\n",
			MUIC_DEV_NAME, __func__, new_dev);

	ret = regmap_com_to(pmuic, com_index);
	if (ret < 0)
		pr_err("%s:%s set_com_uart err\n", MUIC_DEV_NAME, __func__);

	if (pmuic->is_rustproof) {
		pr_info("%s:%s rustproof mode is set.\n",
				MUIC_DEV_NAME, __func__);
		set_rustproof_mode(pmuic->regmapdesc, 1);
	}

	pmuic->attached_dev = new_dev;

	return ret;
}

int detach_jig_uart_boot_on(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s rustproof mode is restored.\n",
			MUIC_DEV_NAME, __func__);

	set_rustproof_mode(pmuic->regmapdesc, 0);

	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

int attach_jig_usb_boot_off(muic_data_t *pmuic,
				u8 vbvolt)
{
	int ret = 0;

	if (pmuic->attached_dev == ATTACHED_DEV_JIG_USB_OFF_MUIC) {
		pr_info("%s:%s duplicated(JIG USB OFF)\n", MUIC_DEV_NAME,
				__func__);
		return ret;
	}

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = attach_usb_util(pmuic, ATTACHED_DEV_JIG_USB_OFF_MUIC);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}

	return ret;
}

int attach_jig_usb_boot_on(muic_data_t *pmuic,
				u8 vbvolt)
{
	int ret = 0;

	if (pmuic->attached_dev == ATTACHED_DEV_JIG_USB_ON_MUIC) {
		pr_info("%s:%s duplicated(JIG USB ON)\n", MUIC_DEV_NAME,
				__func__);
		return ret;
	}

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = attach_usb_util(pmuic, ATTACHED_DEV_JIG_USB_ON_MUIC);
	if (ret < 0)
		return ret;

	return ret;
}

int attach_mhl(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	ret = com_to_open_with_vbus(pmuic);
	if (ret < 0) {
		pr_err("%s:%s fail.(%d)\n", MUIC_DEV_NAME, __func__, ret);
		return ret;
	}

	pmuic->attached_dev = ATTACHED_DEV_MHL_MUIC;

	return ret;
}

int detach_mhl(muic_data_t *pmuic)
{
	int ret = 0;

	pr_info("%s:%s\n", MUIC_DEV_NAME, __func__);

	if(ret < 0)
		pr_err("%s:%s err detach_charger(%d)\n", MUIC_DEV_NAME, __func__, ret);

	pmuic->attached_dev = ATTACHED_DEV_NONE_MUIC;

	return ret;
}

int get_adc(muic_data_t *pmuic)
{
	struct regmap_ops *pops = pmuic->regmapdesc->regmapops;
	int uattr;

	pops->ioctl(pmuic->regmapdesc, GET_ADC, NULL, &uattr);
	return regmap_read_value(pmuic->regmapdesc, uattr);
}

int get_vps_data(muic_data_t *pmuic, void *pdata)
{
	struct vendor_ops *pvendor = pmuic->regmapdesc->vendorops;

	if (pvendor->get_vps_data)
		pvendor->get_vps_data(pmuic->regmapdesc, pdata);
	else
		pr_info("%s: No Vendor API ready.\n", __func__);

	return 0;
}
