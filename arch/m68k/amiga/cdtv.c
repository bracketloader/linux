/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Driver for the CD drive in the Commodore CDTV. Based on reverse engineering
 * work performed by Mark Knibbs and the CDTV emulation code in UAE written
 * by Tony Wilen.
 *
 * Copyright 2018 Google LLC.
 */

#include <linux/blkdev.h>
#include <linux/cdrom.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/zorro.h>

#include <asm/amigacdtv.h>
#include <asm/amigadmac.h>
#include <asm/amigaints.h>

static int cdtv_major;

static void cdtv_cd_readdisk_dma(struct work_struct *work);
static DECLARE_WORK(work, cdtv_cd_readdisk_dma);
static LIST_HEAD(cdtv_deferred);
static DEFINE_MUTEX(cdtv_mutex);
static DECLARE_WAIT_QUEUE_HEAD(cdtv_queue);
static DEFINE_SPINLOCK(cdtv_lock);

#define CDTV_TIMEOUT (HZ * 7)

static struct cdtv_data {
	struct gendisk *disk;
	struct cdrom_device_info *cdinfo;
	struct dmac *dmac;
	struct request_queue *cdrom_rq;
	char response[20];
	int response_count;
	int response_read;
	char dma;
	unsigned char *bounce_buffer;
	int bounce_len;
	unsigned char *dma_target;
	int dma_len;
} cdtv_data;

static int cdtv_cd_bdops_open(struct block_device *bdev, fmode_t mode)
{
	int ret;

	mutex_lock(&cdtv_mutex);
	ret = cdrom_open(cdtv_data.cdinfo, bdev, mode);
	mutex_unlock(&cdtv_mutex);
	return ret;
}

static void cdtv_cd_bdops_release(struct gendisk *disk, fmode_t mode)
{
	mutex_lock(&cdtv_mutex);
	cdrom_release(cdtv_data.cdinfo, mode);
	mutex_unlock(&cdtv_mutex);
}

static unsigned int cdtv_cd_bdops_check_events(struct gendisk *disk,
					       unsigned int clearing)
{
	return cdrom_check_events(cdtv_data.cdinfo, clearing);
}

static int cdtv_cd_bdops_ioctl(struct block_device *bdev, fmode_t mode,
			       unsigned int cmd, unsigned long arg)
{
	int ret;

	mutex_lock(&cdtv_mutex);
	ret = cdrom_ioctl(cdtv_data.cdinfo, bdev, mode, cmd, arg);
	mutex_unlock(&cdtv_mutex);

	return ret;
}

static const struct block_device_operations cdtv_cd_bdops = {
	.owner = THIS_MODULE,
	.open = cdtv_cd_bdops_open,
	.release = cdtv_cd_bdops_release,
	.check_events = cdtv_cd_bdops_check_events,
	.ioctl = cdtv_cd_bdops_ioctl,
};

static irqreturn_t cdtv_intr(int irq, void *data)
{
	struct dmac_regs *regs = cdtv_data.dmac->regs;
	char cdtv_intr = ISTR_E_INT | ISTR_INT_P;
	irqreturn_t ret = IRQ_NONE;
	char mps6525_intr;
	int bounce = 0;

	/* DMA interrupt */
	if ((regs->ISTR & (cdtv_intr)) == cdtv_intr) {
		if (cdtv_data.bounce_buffer != NULL)
			bounce = 1;
		dmac_dma_stop(cdtv_data.dmac, bounce, 1, 0,
			      cdtv_data.bounce_buffer, cdtv_data.dma_target,
			      cdtv_data.dma_len);
		if (cdtv_data.bounce_buffer)
			cdtv_data.bounce_buffer = NULL;
		cdtv_data.dma = 0;
		wake_up_interruptible(&cdtv_queue);
		ret = IRQ_HANDLED;
	}

	/* MPS6525 interrupt */
	mps6525_intr = regs->AIR;
	if (mps6525_intr & AIR_STEN) {
		regs->PRB &= ~(PRB_CMD | PRB_ENABLE);
		cdtv_data.response[cdtv_data.response_read++] = regs->XTPORT0;
		regs->PRB |= (PRB_CMD | PRB_ENABLE);
		if (cdtv_data.response_read == cdtv_data.response_count)
			wake_up_interruptible(&cdtv_queue);
	}

	if (mps6525_intr)
		ret = IRQ_HANDLED;

	return ret;
}

static int cdtv_cd_send_command(char *command, int inlen, int responselen)
{
	struct dmac_regs *regs = cdtv_data.dmac->regs;
	int i, err;

	cdtv_data.response_read = 0;
	regs->PRB &= ~(PRB_CMD | PRB_ENABLE);
	for (i = 0; i < inlen; i++)
		regs->XTPORT0 = command[i];
	cdtv_data.response_count = responselen;
	regs->PRB |= (PRB_CMD | PRB_ENABLE);

	if (responselen) {
		err = wait_event_interruptible_timeout(cdtv_queue,
			 cdtv_data.response_read == responselen, CDTV_TIMEOUT);
		if (err < 1)
			return -ETIMEDOUT;
	}

	return 0;
}

static void cdtv_cd_readdisk_dma(struct work_struct *work)
{
	struct dmac_regs *regs = cdtv_data.dmac->regs;
	struct list_head *elem, *next;
	struct request *req;
	char command[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	int block, block_cnt, err;

	if (list_empty(&cdtv_deferred))
		return;

	spin_lock(&cdtv_lock);
	list_for_each_safe(elem, next, &cdtv_deferred) {
		req = list_entry(elem, struct request, queuelist);
		spin_unlock(&cdtv_lock);
		block = blk_rq_pos(req) / 4;
		block_cnt = blk_rq_sectors(req) / 4;

		command[1] = (block >> 16) & 0xff;
		command[2] = (block >> 8) & 0xff;
		command[3] = block & 0xff;
		command[4] = (block_cnt >> 8) & 0xff;
		command[5] = block_cnt & 0xff;

		cdtv_cd_send_command(command, sizeof(command), 0);

		/* /ENABLE low */
		regs->PRB &= ~(PRB_ENABLE);

		/* /CMD high */
		regs->PRB |= PRB_CMD;

		cdtv_data.dma_target = bio_data(req->bio);
		cdtv_data.dma_len = block_cnt * 2048;
		cdtv_data.dma = 1;
		dmac_dma_setup(cdtv_data.dmac, 1, CNTR_INTEN | CNTR_TCEN,
			       &cdtv_data.bounce_buffer, &cdtv_data.bounce_len,
			       (char *)virt_to_bus(bio_data(req->bio)),
			       block_cnt * 2048);
		err = wait_event_interruptible_timeout(cdtv_queue,
						       cdtv_data.dma == 0,
						       CDTV_TIMEOUT);
		if (err > 0) {
			err = BLK_STS_OK;
		} else {
			err = BLK_STS_IOERR;
			mutex_unlock(&cdtv_data.dmac->mutex);
		}

		spin_lock(&cdtv_lock);
		list_del_init(&req->queuelist);
		__blk_end_request_all(req, err);
	}
	spin_unlock(&cdtv_lock);
}

static void cdtv_cd_request(struct request_queue *rq)
{
	struct request *req;

	while ((req = blk_fetch_request(rq)) != NULL) {
		if (req_op(req) == REQ_OP_READ) {
			list_add_tail(&req->queuelist, &cdtv_deferred);
			schedule_work(&work);
		} else {
			__blk_end_request_all(req, BLK_STS_IOERR);
		}
	}
}

static int cdtv_cd_open(struct cdrom_device_info *devinfo, int purpose)
{
	return 0;
}

static void cdtv_cd_release(struct cdrom_device_info *devinfo)
{
}

static int cdtv_cd_get_status(struct cdrom_device_info *devinfo, int slot)
{
	char command[] = { 0x81 };
	int err;

	err = cdtv_cd_send_command(command, 1, 1);
	if (err)
		return err;

	if (!(cdtv_data.response[0] & (1 << 0)))
		return CDS_DRIVE_NOT_READY;
	if (!(cdtv_data.response[0] & (1 << 6)))
		return CDS_NO_DISC;

	return CDS_DISC_OK;
}

static unsigned int cdtv_cd_check_events(struct cdrom_device_info *cd_info,
					 unsigned int clearing, int ignore)
{
	return 0;
}

static int cdtv_cd_audio_ioctl(struct cdrom_device_info *cdi,
			       unsigned int cmd, void *arg)
{
	int err;
	char command[7] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct cdrom_tochdr *header;
	struct cdrom_tocentry *entry;

	switch (cmd) {
	case CDROMREADTOCHDR:
		if (!arg)
			return -EINVAL;
		command[0] = 0x89;
		err = cdtv_cd_send_command(command, 7, 5);
		if (err)
			return err;
		header = (struct cdrom_tochdr *)arg;
		header->cdth_trk0 = cdtv_data.response[0];
		header->cdth_trk1 = cdtv_data.response[1];
		return 0;
	case CDROMREADTOCENTRY:
		if (!arg)
			return -EINVAL;
		entry = (struct cdrom_tocentry *)arg;
		command[0] = 0x8a;
		command[1] = entry->cdte_format;
		command[2] = entry->cdte_track;
		err = cdtv_cd_send_command(command, 7, 8);
		if (err)
			return err;
		entry->cdte_ctrl = cdtv_data.response[1];
		entry->cdte_format = 0;
	default:
		return -EINVAL;
	}
}

static const struct cdrom_device_ops cdtv_cdrom_dops = {
	.open = cdtv_cd_open,
	.release = cdtv_cd_release,
	.drive_status = cdtv_cd_get_status,
	.check_events = cdtv_cd_check_events,
	.audio_ioctl = cdtv_cd_audio_ioctl,
	.generic_packet = cdrom_dummy_generic_packet,
	.capability = CDC_DRIVE_STATUS,
};

static void cdtv_cd_set_sector_size(int sector_size)
{
	char command[] = { 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	command[2] = (sector_size >> 8) & 0xff;
	command[3] = sector_size & 0xff;
	cdtv_cd_send_command(command, sizeof(command), 0);
}

void cdtv_cd_remove(struct zorro_dev *z)
{
	flush_work(&work);
	blk_cleanup_queue(cdtv_data.cdrom_rq);

	unregister_cdrom(cdtv_data.cdinfo);
	del_gendisk(cdtv_data.disk);
	unregister_blkdev(cdtv_major, "cdtv");
	kfree(cdtv_data.cdinfo);
	dmac_free(cdtv_data.dmac);
	free_irq(IRQ_AMIGA_PORTS, &cdtv_data);
	release_mem_region(z->resource.start, 256);
}
EXPORT_SYMBOL_GPL(cdtv_cd_remove);

int cdtv_cd_probe(struct zorro_dev *z, const struct zorro_device_id *ent)
{
	struct cdrom_device_info *devinfo;
	struct dmac_regs *regs;
	int error;

	if (!request_mem_region(z->resource.start, 256, "CDTV"))
		return -EBUSY;

	regs = ZTWO_VADDR(z->resource.start);

	error = request_irq(IRQ_AMIGA_PORTS, cdtv_intr, IRQF_SHARED, "CDTV",
			    &cdtv_data);
	if (error)
		goto fail_irq;

	cdtv_data.dmac = dmac_init(regs, CNTR_PDMD | CNTR_INTEN);
	if (IS_ERR(cdtv_data.dmac)) {
		error = PTR_ERR(cdtv_data.dmac);
		goto fail_dmac;
	}

	devinfo = kzalloc(sizeof(*devinfo), GFP_KERNEL);
	if (!devinfo) {
		error = -ENOMEM;
		goto fail_devinfo;
	}

	error = register_blkdev(0, "cdtv");
	if (error < 0)
		goto fail_blkdev;

	cdtv_major = error;

	cdtv_data.disk = alloc_disk(1);
	if (!cdtv_data.disk) {
		error = -ENODEV;
		goto fail_disk;
	}

	devinfo->ops = &cdtv_cdrom_dops;
	devinfo->speed = 1;
	devinfo->capacity = 1;
	devinfo->handle = z;
	strcpy(devinfo->name, "cdtv");

	error = register_cdrom(devinfo);
	if (error)
		goto fail_cdrom;

	cdtv_data.disk->fops = &cdtv_cd_bdops;
	cdtv_data.cdrom_rq = blk_init_queue(cdtv_cd_request, &cdtv_lock);
	if (!cdtv_data.cdrom_rq) {
		error = -ENOMEM;
		goto fail_rq;
	}

	blk_queue_bounce_limit(cdtv_data.cdrom_rq, BLK_BOUNCE_ISA);
	blk_queue_logical_block_size(cdtv_data.cdrom_rq, 2048);
	blk_queue_max_segments(cdtv_data.cdrom_rq, 1);
	blk_queue_max_segment_size(cdtv_data.cdrom_rq, 2048);

	cdtv_data.disk->queue = cdtv_data.cdrom_rq;
	cdtv_data.cdinfo = devinfo;

	cdtv_data.disk->major = cdtv_major;
	cdtv_data.disk->first_minor = 1;
	cdtv_data.disk->minors = 1;
	strcpy(cdtv_data.disk->disk_name, "cdtv");

	/*
	 * Do initial register setup. This is largely based on what the
	 * original Commodore driver does.
	 */

	/* Set all lines on port A to input */
	regs->DDRA = 0;
	regs->PRB = (PRB_CMD | PRB_ENABLE | PRB_XAEN | PRB_DTEN | PRB_WEPROM |
		     PRB_DACATT | PRB_DACST | PRB_DACLCH);
	/* Set all lines on port B to output */
	regs->DDRB = 0xff;
	regs->PRC = PRC_INT2;
	/* Mask all interrupts before switching to mode 1 */
	regs->DDRC = 0;
	/* Switch the MPS6525 to mode 1 */
	regs->CR = (CR_MC | CR_CA0 | CR_CA1 | CR_CB0 | CR_CB1);
	/* Enable interrupts 0-3 */
	regs->DDRC = (PRC_SCOR | PRC_STCH | PRC_STEN | PRC_INT2);
	/* Clear the interrupt latches */
	regs->PRC = 0;

	cdtv_cd_set_sector_size(2048);

	add_disk(cdtv_data.disk);
	return 0;

fail_rq:
	unregister_cdrom(devinfo);
fail_cdrom:
	del_gendisk(cdtv_data.disk);
fail_disk:
	unregister_blkdev(cdtv_major, "cdtv");
fail_blkdev:
	kfree(devinfo);
fail_devinfo:
	dmac_free(cdtv_data.dmac);
fail_dmac:
	free_irq(IRQ_AMIGA_PORTS, &cdtv_data);
fail_irq:
	release_mem_region(z->resource.start, 256);
	return error;
}
EXPORT_SYMBOL_GPL(cdtv_cd_probe);

MODULE_DESCRIPTION("CDTV CD-ROM");
MODULE_LICENSE("GPL");
