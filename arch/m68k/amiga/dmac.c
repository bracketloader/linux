#include <asm/amigadmac.h>
#include <asm/cacheflush_mm.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

int dmac_dma_setup(struct dmac *dmac, int dir_in, unsigned short cntr,
		   unsigned char **bounce_buffer, int *bounce_len,
		   unsigned char *source, int residual)
{
	struct dmac_regs *regs = dmac->regs;
	unsigned long addr = virt_to_bus(source);

	if (addr & DMAC_XFER_MASK) {
		*bounce_len = (residual + 511) & ~0x1ff;
		*bounce_buffer = kmalloc(*bounce_len, GFP_KERNEL|GFP_DMA);
		/* can't allocate memory; use PIO */
		if (!*bounce_buffer) {
			*bounce_len = 0;
			return 1;
		}

		/* get the physical address of the bounce buffer */
		addr = virt_to_bus(*bounce_buffer);

		/* the bounce buffer may not be in the first 16M of physmem */
		if (addr & DMAC_XFER_MASK) {
			/* we could use chipmem... maybe later */
			kfree(*bounce_buffer);
			*bounce_buffer = NULL;
			*bounce_len = 0;
			return 1;
		}

		if (!dir_in) {
			/* copy to bounce buffer for a write */
			memcpy(*bounce_buffer, source, residual);
		}
	}

	/* setup dma direction */
	if (!dir_in)
		cntr |= CNTR_DDIR;

	/* Take the mutex before we start any register writes */
	mutex_lock(&dmac->mutex);

	regs->CNTR = cntr;

	/* setup DMA *physical* address */
	regs->ACR = addr;

	regs->WTC = residual/2;

	if (dir_in) {
		/* invalidate any cache */
		cache_clear(addr, residual);
	} else {
		/* push any dirty cache */
		cache_push(addr, residual);
	}
	/* start DMA */
	regs->ST_DMA = 1;

	/* return success */
	return 0;
}
EXPORT_SYMBOL_GPL(dmac_dma_setup);

void dmac_dma_stop(struct dmac *dmac, int bounce, int dir_in,
		   unsigned short cntr, unsigned char *bounce_buffer,
		   unsigned char *target, int residual)
{
	struct dmac_regs *regs = dmac->regs;

	if (!dir_in)
		cntr |= CNTR_DDIR;

	/* disable interrupts */
	regs->CNTR = cntr;

	/* flush if we were reading */
	if (dir_in) {
		regs->FLUSH = 1;
		while (!(regs->ISTR & ISTR_FE_FLG))
			;
	}

	/* clear a possible interrupt */
	regs->CINT = 1;

	/* stop DMA */
	regs->SP_DMA = 1;

	/* restore the CONTROL bits (minus the direction flag) */
	regs->CNTR = CNTR_PDMD | CNTR_INTEN;

	if (bounce) {
		if (dir_in) {
			memcpy(target, bounce_buffer, residual);
		}
		// FIXME
		amiga_chip_free(bounce_buffer);
	}

	mutex_unlock(&dmac->mutex);
}
EXPORT_SYMBOL_GPL(dmac_dma_stop);

void dmac_free(struct dmac *dmac)
{
	dmac->regs->CNTR = 0;
	kfree(dmac);
}
EXPORT_SYMBOL_GPL(dmac_free);

struct dmac *dmac_init(struct dmac_regs *regs, unsigned short cntr)
{
	struct dmac *dmac = kmalloc(sizeof(struct dmac), GFP_KERNEL);

	if (!dmac)
		return ERR_PTR(-ENOMEM);

	dmac->regs = regs;
	mutex_init(&dmac->mutex);
	regs->DAWR = DAWR_DMAC;
	regs->CNTR = cntr;

	return dmac;
}
EXPORT_SYMBOL_GPL(dmac_init);

MODULE_DESCRIPTION("Commodore Amiga DMA controller");
MODULE_LICENSE("GPL");
