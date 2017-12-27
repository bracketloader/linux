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
		 unsigned char  pad6[13];
	volatile unsigned char	XTPORT0;
		 unsigned char  pad7;
	volatile unsigned char	XTPORT1;
		 unsigned char  pad8;
	volatile unsigned char	XTPORT2;
		 unsigned char  pad9;
	volatile unsigned char	XTPORT3;
		 unsigned char  pad10[9];
	volatile unsigned char  PRA;
		 unsigned char  pad11;
	volatile unsigned char  PRB;
		 unsigned char  pad12;
	volatile unsigned char  PRC;
		 unsigned char  pad13;
	volatile unsigned char  DDRA;
		 unsigned char  pad14;
	volatile unsigned char  DDRB;
		 unsigned char  pad15;
	volatile unsigned char  DDRC;
		 unsigned char  pad16;
	volatile unsigned char  CR;
		 unsigned char  pad17;
	volatile unsigned char  AIR;
		 unsigned char  pad18[32];
	volatile unsigned short ST_DMA;
	volatile unsigned short SP_DMA;
	volatile unsigned short CINT;
		 unsigned char  pad19[2];
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

#if IS_ENABLED(CONFIG_A2091_SCSI)
int a2091_probe(struct zorro_dev *z, const struct zorro_device_id *ent);
void a2091_remove(struct zorro_dev *z);
#else
static inline int a2091_probe(struct zorro_dev *z,
			      const struct zorro_device_id *ent) {
	return -ENODEV;
}
static inline void a2091_remove(struct zorro_dev *z) { }
#endif
#if IS_ENABLED(CONFIG_AMIGA_CDTV)
int cdtv_cd_probe(struct zorro_dev *z, const struct zorro_device_id *ent);
void cdtv_cd_remove(struct zorro_dev *z);
#else
static inline int cdtv_cd_probe(struct zorro_dev *z,
			      const struct zorro_device_id *ent) {
	return -ENODEV;
}
static inline void cdtv_cd_remove(struct zorro_dev *z) { }
#endif

#endif /* DMAC_H */
