#include <linux/types.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/zorro.h>
#include <linux/module.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/amigaints.h>
#include <asm/amigahw.h>
#include <asm/amigadmac.h>

#include "scsi.h"
#include "wd33c93.h"
#include "a2091.h"


struct a2091_hostdata {
	struct WD33C93_hostdata wh;
	struct dmac *dmac;
};

static irqreturn_t a2091_intr(int irq, void *data)
{
	struct Scsi_Host *instance = data;
	struct a2091_hostdata *hdata = shost_priv(instance);
	unsigned int status = hdata->dmac->regs->ISTR;
	unsigned long flags;

	if (!(status & (ISTR_INT_F | ISTR_INT_P)) || !(status & ISTR_INTS))
		return IRQ_NONE;

	spin_lock_irqsave(instance->host_lock, flags);
	wd33c93_intr(instance);
	spin_unlock_irqrestore(instance->host_lock, flags);
	return IRQ_HANDLED;
}

static int dma_setup(struct scsi_cmnd *cmd, int dir_in)
{
	struct Scsi_Host *instance = cmd->device->host;
	struct a2091_hostdata *hdata = shost_priv(instance);
	struct WD33C93_hostdata *wh = &hdata->wh;

	/* remember direction */
	wh->dma_dir = dir_in;

	return dmac_dma_setup(hdata->dmac, dir_in, CNTR_PDMD | CNTR_INTEN,
			      &wh->dma_bounce_buffer, &wh->dma_bounce_len,
			      (char *)virt_to_bus(cmd->SCp.ptr),
			      cmd->SCp.this_residual);
}

static void dma_stop(struct Scsi_Host *instance, struct scsi_cmnd *SCpnt,
		     int status)
{
	struct a2091_hostdata *hdata = shost_priv(instance);
	struct WD33C93_hostdata *wh = &hdata->wh;
	int bounce = status && bounce;

	return dmac_dma_stop(hdata->dmac, bounce, wh->dma_dir, CNTR_PDMD,
			     wh->dma_bounce_buffer, SCpnt->SCp.ptr,
			     SCpnt->SCp.this_residual);
}

static struct scsi_host_template a2091_scsi_template = {
	.module			= THIS_MODULE,
	.name			= "Commodore A2091/A590 SCSI",
	.show_info		= wd33c93_show_info,
	.write_info		= wd33c93_write_info,
	.proc_name		= "A2901",
	.queuecommand		= wd33c93_queuecommand,
	.eh_abort_handler	= wd33c93_abort,
	.eh_host_reset_handler	= wd33c93_host_reset,
	.can_queue		= CAN_QUEUE,
	.this_id		= 7,
	.sg_tablesize		= SG_ALL,
	.cmd_per_lun		= CMD_PER_LUN,
	.use_clustering		= DISABLE_CLUSTERING
};

int a2091_probe(struct zorro_dev *z, const struct zorro_device_id *ent)
{
	struct Scsi_Host *instance;
	int error;
	struct dmac_regs *regs;
	wd33c93_regs wdregs;
	struct a2091_hostdata *hdata;

	if (!request_mem_region(z->resource.start, 256, "wd33c93"))
		return -EBUSY;

	instance = scsi_host_alloc(&a2091_scsi_template,
				   sizeof(struct a2091_hostdata));
	if (!instance) {
		error = -ENOMEM;
		goto fail_alloc;
	}

	instance->irq = IRQ_AMIGA_PORTS;
	instance->unique_id = z->slotaddr;

	regs = ZTWO_VADDR(z->resource.start);

	wdregs.SASR = &regs->SASR;
	wdregs.SCMD = &regs->SCMD;

	hdata = shost_priv(instance);
	hdata->wh.no_sync = 0xff;
	hdata->wh.fast = 0;
	hdata->wh.dma_mode = CTRL_DMA;

	wd33c93_init(instance, wdregs, dma_setup, dma_stop, WD33C93_FS_8_10);
	error = request_irq(IRQ_AMIGA_PORTS, a2091_intr, IRQF_SHARED,
			    "A2091 SCSI", instance);
	if (error)
		goto fail_irq;

	hdata->dmac = dmac_init(regs, CNTR_PDMD | CNTR_INTEN);
	if (PTR_ERR(hdata->dmac))
		goto fail_dmac;

	error = scsi_add_host(instance, NULL);
	if (error)
		goto fail_host;

	zorro_set_drvdata(z, instance);

	scsi_scan_host(instance);
	return 0;

fail_host:
	dmac_free(hdata->dmac);
fail_dmac:
	free_irq(IRQ_AMIGA_PORTS, instance);
fail_irq:
	scsi_host_put(instance);
fail_alloc:
	release_mem_region(z->resource.start, 256);
	return error;
}
EXPORT_SYMBOL_GPL(a2091_probe);

void a2091_remove(struct zorro_dev *z)
{
	struct Scsi_Host *instance = zorro_get_drvdata(z);
	struct a2091_hostdata *hdata = shost_priv(instance);

	dmac_free(hdata->dmac);
	scsi_remove_host(instance);
	free_irq(IRQ_AMIGA_PORTS, instance);
	scsi_host_put(instance);
	release_mem_region(z->resource.start, 256);
}
EXPORT_SYMBOL_GPL(a2091_remove);

MODULE_DESCRIPTION("Commodore A2091/A590 SCSI");
MODULE_LICENSE("GPL");
