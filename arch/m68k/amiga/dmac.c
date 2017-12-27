#include <asm/amigadmac.h>
#include <asm/amigahw.h>
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

	mutex_lock(&dmac->mutex);

	if (addr & DMAC_XFER_MASK) {
		/* Attempt to use the existing allocation if we've already
		 * fallen back to chip RAM
		 */
		if (dmac->chip_ram && residual <= dmac->chip_ram_len) {
			*bounce_buffer = dmac->chip_ram;
			*bounce_len = residual;
		} else {
			/* Free any existing chip RAM buffer, then try to
			 * allocate an appropriate Zorro II space, then
			 * fall back to allocating a big enough chip RAM
			 * buffer
			 */
			if (dmac->chip_ram) {
				amiga_chip_free(dmac->chip_ram);
				dmac->chip_ram = NULL;
			}

			*bounce_len = (residual + 511) & ~0x1ff;
			*bounce_buffer = kmalloc(*bounce_len,
						 GFP_KERNEL|GFP_DMA);

			/* If we couldn't allocate the buffer or it doesn't
			 * meet our requirements, fall back to chip RAM
			*/
			if (!*bounce_buffer ||
			    virt_to_bus(*bounce_buffer) & DMAC_XFER_MASK) {
				kfree(*bounce_buffer);

				*bounce_buffer = amiga_chip_alloc(residual,
							 "DMAC Bounce Buffer");
				*bounce_len = residual;

				/* Couldn't allocate chip RAM - fall back to
				 * PIO if supported
				 */
				if (!*bounce_buffer) {
					*bounce_len = 0;
					mutex_unlock(&dmac->mutex);
					return 1;
				}

				dmac->chip_ram = *bounce_buffer;
				dmac->chip_ram_len = residual;
			}
		}

		/* get the physical address of the bounce buffer */
		addr = virt_to_bus(*bounce_buffer);

		if (!dir_in) {
			/* copy to bounce buffer for a write */
			memcpy(*bounce_buffer, source, residual);
		}

	}

	/* setup dma direction */
	if (!dir_in)
		cntr |= CNTR_DDIR;

	regs->CNTR = cntr;

	/* setup DMA *physical* address */
	regs->ACR = addr & 0xffffff;

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
		if (dir_in)
			memcpy(target, bounce_buffer, residual);
		if (!dmac->chip_ram)
			kfree(bounce_buffer);
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
	struct dmac *dmac = kzalloc(sizeof(struct dmac), GFP_KERNEL);

	if (!dmac)
		return ERR_PTR(-ENOMEM);

	dmac->regs = regs;
	mutex_init(&dmac->mutex);
	regs->DAWR = DAWR_DMAC;
	regs->CNTR = cntr;

	return dmac;
}
EXPORT_SYMBOL_GPL(dmac_init);

static struct zorro_device_id dmac_zorro_tbl[] = {
	{ ZORRO_PROD_CBM_A590_A2091_1 },
	{ ZORRO_PROD_CBM_A590_A2091_2 },
	{ 0 }
};
MODULE_DEVICE_TABLE(zorro, dmac_zorro_tbl);

static int dmac_probe(struct zorro_dev *z, const struct zorro_device_id *ent)
{
	return a2091_probe(z, ent);
}

static void dmac_remove(struct zorro_dev *z)
{
	a2091_remove(z);
}

static struct zorro_driver dmac_driver = {
	.name		= "dmac",
	.id_table	= dmac_zorro_tbl,
	.probe		= dmac_probe,
	.remove		= dmac_remove,
};

static int __init dmac_init(void)
{
	return zorro_register_driver(&dmac_driver);
}
module_init(dmac_init);

static void __exit dmac_exit(void)
{
	zorro_unregister_driver(&dmac_driver);
}
module_exit(dmac_exit);

MODULE_DESCRIPTION("Commodore Amiga DMA controller");
MODULE_LICENSE("GPL");
