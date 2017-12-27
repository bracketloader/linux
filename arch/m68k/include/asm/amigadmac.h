/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DMAC_H
#define DMAC_H

#include <linux/mutex.h>
#include <linux/zorro.h>

/*
 * if the transfer address ANDed with this results in a non-zero
 * result, then we can't use DMA.
 */
#define DMAC_XFER_MASK         (0xff000001)

struct dmac_regs {
		 unsigned char  pad1[64];
	volatile unsigned short ISTR;
	volatile unsigned short CNTR;
		 unsigned char  pad2[60];
	volatile unsigned int   WTC;
	volatile unsigned long  ACR;
		 unsigned char  pad3[6];
	volatile unsigned short DAWR;
		 unsigned char  pad4;
	volatile unsigned char  SASR;
		 unsigned char  pad5;
	volatile unsigned char  SCMD;
		 unsigned char  pad6[76];
	volatile unsigned short ST_DMA;
	volatile unsigned short SP_DMA;
	volatile unsigned short CINT;
		 unsigned char  pad7[2];
	volatile unsigned short FLUSH;
};

struct dmac {
	struct dmac_regs *regs;
	struct mutex mutex;
	void *chip_ram;
	int chip_ram_len;
};

#define DAWR_DMAC              (3)

/* CNTR bits. */
#define CNTR_TCEN               (1<<7)
#define CNTR_PREST              (1<<6)
#define CNTR_PDMD               (1<<5)
#define CNTR_INTEN              (1<<4)
#define CNTR_DDIR               (1<<3)

/* ISTR bits. */
#define ISTR_INTX               (1<<8)
#define ISTR_INT_F              (1<<7)
#define ISTR_INTS               (1<<6)
#define ISTR_E_INT              (1<<5)
#define ISTR_INT_P              (1<<4)
#define ISTR_UE_INT             (1<<3)
#define ISTR_OE_INT             (1<<2)
#define ISTR_FF_FLG             (1<<1)
#define ISTR_FE_FLG             (1<<0)

int dmac_dma_setup(struct dmac *dmac, int dir_in, unsigned short cntr,
		   unsigned char **bounce_buffer, int *bounce_len,
		   unsigned char *addr, int residual);
void dmac_dma_stop(struct dmac *dmac, int status, int dir_in,
		   unsigned short cntr, unsigned char *bounce,
		   unsigned char *target, int residual);
void dmac_free(struct dmac *dmac);
struct dmac *dmac_init(struct dmac_regs *regs, unsigned short cntr);

int a2091_probe(struct zorro_dev *z, const struct zorro_device_id *ent);
void a2091_remove(struct zorro_dev *z);
#endif /* DMAC_H */
