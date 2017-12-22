/* SPDX-License-Identifier: GPL-2.0 */
#ifndef A2091_H
#define A2091_H

/* $Id: a2091.h,v 1.4 1997/01/19 23:07:09 davem Exp $
 *
 * Header file for the Commodore A2091 Zorro II SCSI controller for Linux
 *
 * Written and (C) 1993, Hamish Macdonald, see a2091.c for more info
 *
 */

#include <linux/types.h>

#ifndef CMD_PER_LUN
#define CMD_PER_LUN		2
#endif

#ifndef CAN_QUEUE
#define CAN_QUEUE		16
#endif

#endif /* A2091_H */
