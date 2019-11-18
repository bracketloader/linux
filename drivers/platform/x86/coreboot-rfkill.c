// SPDX-License-Identifier: GPL-2.0
//
// Copyright 2019 Google LLC.

#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/rfkill.h>

enum coreboot_rfkill_radio_type {
	COREBOOT_WLAN = 0,
	COREBOOT_BLUETOOTH,
	COREBOOT_UWB,
	COREBOOT_WIMAX,
	COREBOOT_WWAN,
	COREBOOT_GPS,
	COREBOOT_FM,
	COREBOOT_NFC,
	COREBOOT_MAX,
};

static const char *const coreboot_rfkill_radio_names[] = {
	"wlan",
	"bluetooth",
	"uwb",
	"wimax",
	"wwan",
	"gps",
	"fm",
	"nfc"
};

static const enum rfkill_type coreboot_rfkill_mapping[] = {
	RFKILL_TYPE_WLAN,
	RFKILL_TYPE_BLUETOOTH,
	RFKILL_TYPE_UWB,
	RFKILL_TYPE_WIMAX,
	RFKILL_TYPE_WWAN,
	RFKILL_TYPE_GPS,
	RFKILL_TYPE_FM,
	RFKILL_TYPE_NFC,
};

struct coreboot_rfkill_radio {
	struct acpi_device *device;
	struct rfkill *rfkill;
	enum coreboot_rfkill_radio_type type;
	bool registered;
};

struct coreboot_rfkill_data {
	struct coreboot_rfkill_radio *radios[COREBOOT_MAX];
};


static struct coreboot_rfkill_radio *alloc_radio(struct acpi_device *device,
					  enum coreboot_rfkill_radio_type type)
{
	struct coreboot_rfkill_radio *radio;

	radio = kmalloc(sizeof(struct coreboot_rfkill_radio), GFP_KERNEL);
	if (!radio)
		return NULL;
	radio->device = device;
	radio->type = type;
	return radio;
}

static void coreboot_rfkill_query(struct rfkill *rfkill, void *data)
{
	struct coreboot_rfkill_radio *radio;
	unsigned long long soft, hard;
	acpi_status status;
	bool soft_state, hard_state;

	radio = (struct coreboot_rfkill_radio *)data;
	status = acpi_evaluate_integer(radio->device->handle, "SSTA", NULL,
				       &soft);
	if (ACPI_FAILURE(status))
		return;

	status = acpi_evaluate_integer(radio->device->handle, "HSTA", NULL,
				       &hard);
	if (ACPI_FAILURE(status))
		return;

	soft_state = !(soft & (1 << radio->type));
	hard_state = !(hard & (1 << radio->type));

	rfkill_set_states(rfkill, soft_state, hard_state);
}

static int coreboot_rfkill_set_block(void *data, bool blocked)
{
	struct coreboot_rfkill_radio *radio;
	struct acpi_object_list input;
	unsigned long long output;
	union acpi_object param;
	acpi_status status;

	radio = (struct coreboot_rfkill_radio *)data;
	status = acpi_evaluate_integer(radio->device->handle, "SSTA", NULL,
				       &output);
	if (ACPI_FAILURE(status))
		return -EINVAL;

	output &= ~(1 << radio->type);
	output |= ((!blocked) << radio->type);

	param.type = ACPI_TYPE_INTEGER;
	param.integer.value = output;
	input.count = 1;
	input.pointer = &param;

	status = acpi_evaluate_object(radio->device->handle, "CNTL", &input,
				      NULL);
	if (ACPI_FAILURE(status))
		return -EINVAL;

	return 0;
}

static const struct rfkill_ops coreboot_rfkill_ops = {
	.query = coreboot_rfkill_query,
	.set_block = coreboot_rfkill_set_block,
};

static int coreboot_rfkill_remove(struct acpi_device *device)
{
	struct coreboot_rfkill_data *data;
	int i;

	data = dev_get_drvdata(&device->dev);

	for (i = 0; i < COREBOOT_MAX; i++) {
		if (data->radios[i] == NULL)
			continue;

		if (data->radios[i]->registered)
			rfkill_unregister(data->radios[i]->rfkill);
		rfkill_destroy(data->radios[i]->rfkill);
		kfree(data->radios[i]);
	}

	kfree(data);

	return 0;
}

static int coreboot_rfkill_add(struct acpi_device *device)
{
	struct coreboot_rfkill_radio *radio;
	struct coreboot_rfkill_data *data;
	unsigned long long output;
	struct rfkill *rfkill;
	acpi_status status;
	int i, ret;

	data = kzalloc(sizeof(struct coreboot_rfkill_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	dev_set_drvdata(&device->dev, data);

	/* Find out what devices we have */
	status = acpi_evaluate_integer(device->handle, "DEVS", NULL, &output);
	if (ACPI_FAILURE(status))
		return -ENODEV;

	for (i = 0; i < COREBOOT_MAX; i++) {
		if (output & (1 << i)) {
			char *name;

			radio = alloc_radio(device, i);
			if (!radio) {
				coreboot_rfkill_remove(device);
				return -ENOMEM;
			}

			name = kasprintf(GFP_KERNEL, "coreboot-rfkill-%s",
					 coreboot_rfkill_radio_names[i]);
			if (!name) {
				coreboot_rfkill_remove(device);
				return -ENOMEM;
			}
			rfkill = rfkill_alloc(name, &device->dev,
					      coreboot_rfkill_mapping[i],
					      &coreboot_rfkill_ops, radio);
			if (!rfkill) {
				kfree(name);
				coreboot_rfkill_remove(device);
				return -ENOMEM;
			}

			data->radios[i] = radio;
			radio->rfkill = rfkill;

			ret = rfkill_register(radio->rfkill);
			if (ret) {
				kfree(name);
				coreboot_rfkill_remove(device);
				return ret;
			}
			radio->registered = true;
			kfree(name);
		}
	}

	return 0;
}

static const struct acpi_device_id coreboot_rfkill_ids[] = {
	{ "COR0001", 0},
	{ "", 0 },
};

static struct acpi_driver coreboot_rfkill_driver = {
	.name = "coreboot-rfkill",
	.ids = coreboot_rfkill_ids,
	.ops = {
		.add = coreboot_rfkill_add,
		.remove = coreboot_rfkill_remove,
	},
	.owner = THIS_MODULE,
};

module_acpi_driver(coreboot_rfkill_driver);
MODULE_LICENSE("GPL");
