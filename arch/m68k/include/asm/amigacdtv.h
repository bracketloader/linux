/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CDTV-specific constants.
 *
 * Copyright 2018 Google LLC.
 *
 */

#ifndef CDTV_H
#define CDTV_H

#define PRB_CMD (1 << 0) /* Command pin of CD-ROM */
#define PRB_ENABLE (1 << 1) /* Enable pin of CD-ROM */
#define PRB_XAEN (1 << 2) /* XAEN pin of CD-ROM */
#define PRB_DTEN (1 << 3) /* DTEN pin of CD-ROM */
#define PRB_WEPROM (1 << 4) /* WEPROM signal */
#define PRB_DACATT (1 << 5) /* DAC ATT pin */
#define PRB_DACST (1 << 6) /* DAC SHIFT pin */
#define PRB_DACLCH (1 << 7) /* DAC LATCH pin */

#define PRC_SCR (1 << 0) /* Subcode ready */
#define PRC_SCOR (1 << 1) /* SCOR pin of CD-ROM */
#define PRC_STCH (1 << 2) /* STCH pin of CD-ROM */
#define PRC_STEN (1 << 3) /* STEN pin of CD-ROM */
#define PRC_DRQ (1 << 4) /* DRQ pin of CD-ROM */
#define PRC_INT2 (1 << 5) /* INT2 line */
#define PRC_MS0 (1 << 6) /* genlock mode 0 */
#define PRC_MS1 (1 << 7) /* genlock mode 1 */

#define CR_MC (1 << 0) /* Mode Control */
#define CR_IP (1 << 1) /* Interrupt Priority */
#define CR_IE3 (1 << 2) /* I3 Active Edge Select */
#define CR_IE4 (1 << 3) /* I4 Active Edge Select */
#define CR_CA0 (1 << 4) /* CA Line Control */
#define CR_CA1 (1 << 5) /* CA Line Control */
#define CR_CB0 (1 << 6) /* CB Line Control */
#define CR_CB1 (1 << 7) /* CB Line Control */

#define AIR_SCOR (1 << 1) /* Set if SCOR goes low */
#define AIR_STCH (1 << 2) /* Set if STCH goes low */
#define AIR_STEN (1 << 3) /* Set if STEN goes low */

#endif /* CDTV_H */
