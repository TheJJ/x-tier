/*
 * X-TIER_hypercall.h
 *
 * Contains all hypercall related definitions.
 *
 *  Created on: May 23, 2013
 *      Author: Sebastian Vogl <vogls@sec.in.tum.de>
 */

#ifndef XTIER_HYPERCALL_H_
#define XTIER_HYPERCALL_H_

/* The interrupt number that signals a hypercall */
#define XTIER_HYPERCALL_INTERRUPT 42

// CONVENTION:
// 	-> COMMAND: RAX
//	-> FIRST PARAM: RBX
//	-> SECOND PARAM: RCX
//
//	-> RETURN VALUE: RAX

/* The individual hypercall commands. The command register is RAX. */
#define XTIER_HYPERCALL_RESERVE_MEMORY 12345
#define XTIER_HYPERCALL_PRINT 2
#define XTIER_HYPERCALL_DATA_TRANSFER 3
#define XTIER_HYPERCALL_EXTERNAL_FUNCTION_CALL 42

#endif /* XTIER_HYPERCALL_H_*/
