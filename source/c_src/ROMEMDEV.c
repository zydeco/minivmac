/*
	ROMEMDEV.c

	Copyright (C) 2007 Philip Cummins, Paul C. Pratt

	You can redistribute this file and/or modify it under the terms
	of version 2 of the GNU General Public License as published by
	the Free Software Foundation.  You should have received a copy
	of the license along with this file; see the file COPYING.

	This file is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	license for more details.
*/

/*
	Read Only Memory EMulated DEVice

	Checks the header of the loaded ROM image, and then patches
	the ROM image.

	This code descended from "ROM.c" in vMac by Philip Cummins.
*/

#ifndef AllFiles
#include "SYSDEPNS.h"
#include "MYOSGLUE.h"
#include "ENDIANAC.h"
#endif

#include "ROMEMDEV.h"

#if CurEmu <= kEmuClassic
LOCALVAR const ui4b sony_driver[] = {
/*
	Replacement for .Sony driver
	68k machine code, compiled from mydriver.c
*/
#if CurEmu <= kEmu512K
	0x4F00, 0x0000, 0x0000, 0x0000,
	0x0018, 0x002C, 0x0040, 0x005C,
	0x0092, 0x052E, 0x536F, 0x6E79,
	0x48E7, 0x00C0, 0x48E7, 0x00C0,
	0x6100, 0x02E0, 0x504F, 0x4CDF,
	0x0300, 0x4E75, 0x48E7, 0x00C0,
	0x48E7, 0x00C0, 0x6100, 0x043E,
	0x504F, 0x4CDF, 0x0300, 0x602E,
	0x48E7, 0x00C0, 0x48E7, 0x00C0,
	0x6100, 0x0614, 0x504F, 0x4CDF,
	0x0300, 0x0C68, 0x0001, 0x001A,
	0x6614, 0x4E75, 0x48E7, 0x00C0,
	0x48E7, 0x00C0, 0x6100, 0x0726,
	0x504F, 0x4CDF, 0x0300, 0x3228,
	0x0006, 0x0801, 0x0009, 0x670C,
	0x4A40, 0x6F02, 0x4240, 0x3140,
	0x0010, 0x4E75, 0x4A40, 0x6F04,
	0x4240, 0x4E75, 0x2F38, 0x08FC,
	0x4E75, 0x48E7, 0x00C0, 0x48E7,
	0x00C0, 0x6100, 0x075C, 0x504F,
	0x4CDF, 0x0300, 0x4E75, 0x48E7,
	0xE0C0, 0x2F2F, 0x0014, 0x6100,
	0x0160, 0x584F, 0x4CDF, 0x0307,
	0x584F, 0x4E73, 0x7FFF, 0xFFF0,
	0x8100, 0x0108, 0x8100, 0x7104,
	0x8100, 0x8902, 0x8100, 0x8901,
	0x8100, 0x8901, 0x8100, 0x8901,
	0x8100, 0x8901, 0x8100, 0x8901,
	0x8100, 0x7101, 0x8100, 0x0101,
	0x80FF, 0xFE01, 0x8000, 0x0001,
	0x8000, 0x0001, 0x8000, 0x0001,
	0x8000, 0x0001, 0x83FF, 0xFFC1,
	0x8400, 0x0021, 0x8400, 0x0021,
	0x8400, 0x0021, 0x8400, 0x0021,
	0x8400, 0x0021, 0x8406, 0x3021,
	0x8406, 0x6021, 0x8406, 0xC021,
	0x8407, 0x8021, 0x8407, 0x0021,
	0x8406, 0x0021, 0x8400, 0x0021,
	0x8400, 0x0021, 0x8400, 0x0021,
	0x7FFF, 0xFFFE, 0x3FFF, 0xFFF0,
	0x7FFF, 0xFFF0, 0xFFFF, 0xFFFC,
	0xFFFF, 0xFFFC, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0x7FFF, 0xFFFC,
	0x3FFF, 0xFFFC, 0x0000, 0x2140,
	0x0006, 0x43F8, 0x0308, 0x4EF9,
	0x0040, 0x0B20, 0x4E56, 0x0000,
	0x48E7, 0x1108, 0x3E2E, 0x000A,
	0x2878, 0x0134, 0xBE6C, 0x0018,
	0x6422, 0x200C, 0x724A, 0xD081,
	0x7400, 0x3407, 0x2602, 0xC4FC,
	0x0042, 0x4843, 0xC6FC, 0x0042,
	0x4843, 0x4243, 0xD483, 0xD480,
	0x2002, 0x6002, 0x7000, 0x4CEE,
	0x1088, 0xFFF4, 0x4E5E, 0x4E75,
	0x4E56, 0xFFE0, 0x48E7, 0x1F18,
	0x282E, 0x0008, 0x49EE, 0xFFE0,
	0x2A3C, 0x0000, 0xFFFF, 0xCA84,
	0x2678, 0x0134, 0x48C5, 0x2F05,
	0x4EBA, 0xFF9A, 0x2E00, 0x5680,
	0x2040, 0x7000, 0x1010, 0x4A80,
	0x584F, 0x6600, 0x00B4, 0x38BC,
	0x5B17, 0x396B, 0x001A, 0x0002,
	0x397C, 0x0005, 0x0004, 0x3945,
	0x0014, 0x206B, 0x0014, 0x208C,
	0x4A6C, 0x0006, 0x6600, 0x0092,
	0x2C2C, 0x000C, 0x7009, 0xE0AE,
	0x0C86, 0x0000, 0x0320, 0x662A,
	0x2007, 0x7212, 0xD081, 0x2040,
	0x4210, 0x2007, 0x7413, 0xD082,
	0x2040, 0x4210, 0x2007, 0x720A,
	0xD081, 0x2040, 0x4250, 0x2007,
	0x7214, 0xD081, 0x2040, 0x4250,
	0x6032, 0x2007, 0x720E, 0xD081,
	0x2040, 0x30BC, 0xFFFE, 0x2007,
	0x740A, 0xD082, 0x2040, 0x30BC,
	0x0001, 0x2007, 0x7212, 0xD081,
	0x2040, 0x3086, 0x2006, 0x4240,
	0x4840, 0x2607, 0x7214, 0xD681,
	0x2043, 0x3080, 0x2004, 0x4240,
	0x4840, 0x2207, 0x5481, 0x2041,
	0x1080, 0x2007, 0x5680, 0x2040,
	0x10BC, 0x0001, 0x307C, 0x0007,
	0x48C5, 0x2005, 0x5280, 0xA02F,
	0x4CEE, 0x18F8, 0xFFC4, 0x4E5E,
	0x4E75, 0x4E56, 0xFFDE, 0x48E7,
	0x1F18, 0x49EE, 0xFFE0, 0x2C3C,
	0x00F4, 0x0000, 0x78FF, 0x38BC,
	0x5B17, 0x426C, 0x0002, 0x397C,
	0x0001, 0x0004, 0x297C, 0x4C92,
	0x19E6, 0x0008, 0x2046, 0x208C,
	0x3A2C, 0x000C, 0x38BC, 0x5B17,
	0x3945, 0x0002, 0x397C, 0x0006,
	0x0004, 0x2046, 0x208C, 0x4AAC,
	0x0010, 0x6706, 0x4244, 0x6000,
	0x0118, 0x38BC, 0x5B17, 0x3945,
	0x0002, 0x397C, 0x0001, 0x0004,
	0x2046, 0x208C, 0x7000, 0x302C,
	0x0006, 0x4A80, 0x6600, 0x00FA,
	0x362C, 0x0008, 0x7000, 0x3003,
	0x2200, 0xC0FC, 0x0042, 0x4841,
	0xC2FC, 0x0042, 0x4841, 0x4241,
	0xD081, 0x2E00, 0x704A, 0xDE80,
	0x0C87, 0x0000, 0x00FA, 0x6406,
	0x2E3C, 0x0000, 0x00FA, 0x2007,
	0xA71E, 0x2648, 0x200B, 0x6700,
	0x00C0, 0x277C, 0x8413, 0x39E2,
	0x0010, 0x2746, 0x0014, 0x3743,
	0x0018, 0x3745, 0x001A, 0x21CB,
	0x0134, 0x2078, 0x011C, 0x2278,
	0x011C, 0x2368, 0x0010, 0x0004,
	0x41FA, 0xFDEC, 0x303C, 0xA04E,
	0xA047, 0x4278, 0x0308, 0x7000,
	0x21C0, 0x030A, 0x21C0, 0x030E,
	0x4246, 0x6050, 0x2007, 0x5680,
	0x2040, 0x4210, 0x2007, 0x5880,
	0x2040, 0x10BC, 0x0001, 0x2007,
	0x5A80, 0x2040, 0x4210, 0x48C6,
	0x2006, 0x5280, 0x2207, 0x740C,
	0xD282, 0x2041, 0x3080, 0x2007,
	0x720E, 0xD081, 0x2040, 0x30BC,
	0xFFFB, 0x2007, 0x5C80, 0x2040,
	0x48C6, 0x2006, 0x5280, 0x4840,
	0x4240, 0xD0BC, 0x0000, 0xFFFB,
	0xA04E, 0x5246, 0x48C6, 0x2F06,
	0x4EBA, 0xFD8A, 0x2E00, 0x584F,
	0x66A2, 0x38BC, 0x5B17, 0x3945,
	0x0002, 0x397C, 0x0007, 0x0004,
	0x41FA, 0xFC4C, 0x2948, 0x0010,
	0x206B, 0x0014, 0x208C, 0x4244,
	0x3004, 0x4CEE, 0x18F8, 0xFFC2,
	0x4E5E, 0x4E75, 0x4E56, 0xFFD6,
	0x48E7, 0x1F18, 0x2E2E, 0x0008,
	0x49EE, 0xFFDC, 0x2007, 0x7216,
	0xD081, 0x2040, 0x7000, 0x3010,
	0x5380, 0x3D40, 0xFFDA, 0x2678,
	0x0134, 0x7000, 0x302E, 0xFFDA,
	0x2F00, 0x4EBA, 0xFD28, 0x2D40,
	0xFFFC, 0x584F, 0x6608, 0x7CC8,
	0x7A00, 0x6000, 0x0174, 0x202E,
	0xFFFC, 0x5680, 0x2D40, 0xFFD6,
	0x2040, 0x1810, 0x7000, 0x1004,
	0x0C40, 0x0002, 0x6732, 0x7000,
	0x1004, 0x0C40, 0x0001, 0x660A,
	0x206E, 0xFFD6, 0x10BC, 0x0002,
	0x601E, 0x7CBF, 0x2007, 0x7210,
	0xD081, 0x2040, 0x3086, 0x2007,
	0x7428, 0xD082, 0x2040, 0x7200,
	0x2081, 0x3006, 0x6000, 0x0156,
	0x2007, 0x722C, 0xD081, 0x2040,
	0x7000, 0x3010, 0x740F, 0xC440,
	0x0C42, 0x0003, 0x6276, 0xD442,
	0x343B, 0x2006, 0x4EFB, 0x2000,
	0x006E, 0x000A, 0x0016, 0x0056,
	0x2007, 0x722E, 0xD081, 0x2040,
	0x2810, 0x6064, 0x38BC, 0x5B17,
	0x396B, 0x001A, 0x0002, 0x397C,
	0x0005, 0x0004, 0x396E, 0xFFDA,
	0x0014, 0x206B, 0x0014, 0x208C,
	0x282C, 0x000C, 0x4A6C, 0x0006,
	0x57C3, 0x4403, 0x4883, 0x3C03,
	0x6706, 0x3006, 0x6000, 0x00EE,
	0x2007, 0x722E, 0xD081, 0x2040,
	0x9890, 0x6024, 0x2007, 0x722E,
	0xD081, 0x2040, 0x202E, 0x000C,
	0x7410, 0xD082, 0x2240, 0x2811,
	0xD890, 0x600C, 0x202E, 0x000C,
	0x7210, 0xD081, 0x2040, 0x2810,
	0x2007, 0x7224, 0xD081, 0x2040,
	0x2A10, 0x38BC, 0x5B17, 0x396B,
	0x001A, 0x0002, 0x2944, 0x0008,
	0x2945, 0x000C, 0x2007, 0x7420,
	0xD082, 0x2040, 0x2950, 0x0010,
	0x396E, 0xFFDA, 0x0014, 0x2007,
	0x5C80, 0x2040, 0x7000, 0x3010,
	0x363C, 0xF0FF, 0xC640, 0x0443,
	0xA002, 0x6706, 0x5343, 0x6718,
	0x6042, 0x397C, 0x0002, 0x0004,
	0x206B, 0x0014, 0x208C, 0x2A2C,
	0x000C, 0x3C2C, 0x0006, 0x6030,
	0x202E, 0xFFFC, 0x5480, 0x2040,
	0x7000, 0x1010, 0x4A80, 0x6706,
	0x7A00, 0x7CD4, 0x601A, 0x397C,
	0x0003, 0x0004, 0x206B, 0x0014,
	0x208C, 0x2A2C, 0x000C, 0x3C2C,
	0x0006, 0x6004, 0x70EF, 0x602C,
	0x2007, 0x7210, 0xD081, 0x2040,
	0x3086, 0x2007, 0x7428, 0xD082,
	0x2040, 0x2085, 0x202E, 0x000C,
	0xD081, 0x2040, 0x2005, 0xD090,
	0x262E, 0x000C, 0xD681, 0x2043,
	0x2080, 0x3006, 0x4CEE, 0x18F8,
	0xFFBA, 0x4E5E, 0x4E75, 0x4E56,
	0xFFDC, 0x48E7, 0x1F18, 0x2A2E,
	0x0008, 0x49EE, 0xFFDC, 0x2005,
	0x721A, 0xD081, 0x2040, 0x7600,
	0x3610, 0x2005, 0x7216, 0xD081,
	0x2040, 0x7000, 0x3010, 0x2800,
	0x5384, 0x2678, 0x0134, 0x7000,
	0x3004, 0x2F00, 0x4EBA, 0xFB36,
	0x2C00, 0x584F, 0x6606, 0x7EC8,
	0x6000, 0x00DE, 0x2006, 0x5680,
	0x2040, 0x7000, 0x1010, 0x4A80,
	0x6606, 0x7EBF, 0x6000, 0x00CA,
	0x38BC, 0x5B17, 0x396B, 0x001A,
	0x0002, 0x3944, 0x0014, 0x2003,
	0x5380, 0x671C, 0x5980, 0x671E,
	0x5380, 0x674E, 0x5380, 0x671C,
	0x0480, 0x0000, 0x000E, 0x6746,
	0x5580, 0x6768, 0x6000, 0x0098,
	0x7EFF, 0x6000, 0x0094, 0x4247,
	0x6000, 0x008E, 0x2006, 0x5480,
	0x2040, 0x4210, 0x2006, 0x5680,
	0x2040, 0x4210, 0x2006, 0x720E,
	0xD081, 0x2040, 0x30BC, 0xFFFB,
	0x397C, 0x0004, 0x0004, 0x206B,
	0x0014, 0x208C, 0x3E2C, 0x0006,
	0x605E, 0x4247, 0x605A, 0x2006,
	0x720A, 0xD081, 0x2040, 0x7000,
	0x3010, 0x4A80, 0x6712, 0x41FA,
	0xF984, 0x2005, 0x721C, 0xD081,
	0x2240, 0x2288, 0x4247, 0x6038,
	0x7EEF, 0x6034, 0x2006, 0x720A,
	0xD081, 0x2040, 0x7000, 0x3010,
	0x4A80, 0x6704, 0x7C01, 0x6002,
	0x7C02, 0x7000, 0x3004, 0x4A80,
	0x6706, 0x0686, 0x0000, 0x0900,
	0x2005, 0x721C, 0xD081, 0x2040,
	0x2086, 0x4247, 0x6002, 0x7EEF,
	0x3007, 0x4CEE, 0x18F8, 0xFFC0,
	0x4E5E, 0x4E75, 0x4E56, 0x0000,
	0x48E7, 0x1F00, 0x2A2E, 0x0008,
	0x2005, 0x7216, 0xD081, 0x2040,
	0x7000, 0x3010, 0x2800, 0x5384,
	0x2005, 0x741A, 0xD082, 0x2040,
	0x7000, 0x3010, 0x7608, 0xB680,
	0x6630, 0x7000, 0x3004, 0x2F00,
	0x4EBA, 0xFA0A, 0x2E00, 0x584F,
	0x6604, 0x78C8, 0x601E, 0x2C05,
	0x701C, 0xDC80, 0x7A0B, 0x600A,
	0x2047, 0x2246, 0x3290, 0x5487,
	0x5486, 0x5385, 0x6CF2, 0x4244,
	0x6002, 0x78EE, 0x3004, 0x4CEE,
	0x00F8, 0xFFEC, 0x4E5E, 0x4E75,
	0x4E56, 0x0000, 0x70E8, 0x4E5E,
	0x4E75
#else
	0x4F00, 0x0000, 0x0000, 0x0000,
	0x0018, 0x002C, 0x0040, 0x005C,
	0x0092, 0x052E, 0x536F, 0x6E79,
	0x48E7, 0x00C0, 0x48E7, 0x00C0,
	0x6100, 0x02FA, 0x504F, 0x4CDF,
	0x0300, 0x4E75, 0x48E7, 0x00C0,
	0x48E7, 0x00C0, 0x6100, 0x045A,
	0x504F, 0x4CDF, 0x0300, 0x602E,
	0x48E7, 0x00C0, 0x48E7, 0x00C0,
	0x6100, 0x0630, 0x504F, 0x4CDF,
	0x0300, 0x0C68, 0x0001, 0x001A,
	0x6614, 0x4E75, 0x48E7, 0x00C0,
	0x48E7, 0x00C0, 0x6100, 0x0742,
	0x504F, 0x4CDF, 0x0300, 0x3228,
	0x0006, 0x0801, 0x0009, 0x670C,
	0x4A40, 0x6F02, 0x4240, 0x3140,
	0x0010, 0x4E75, 0x4A40, 0x6F04,
	0x4240, 0x4E75, 0x2F38, 0x08FC,
	0x4E75, 0x48E7, 0x00C0, 0x48E7,
	0x00C0, 0x6100, 0x0778, 0x504F,
	0x4CDF, 0x0300, 0x4E75, 0x48E7,
	0xE0C0, 0x2F2F, 0x0014, 0x6100,
	0x0152, 0x584F, 0x4CDF, 0x0307,
	0x584F, 0x4E73, 0x7FFF, 0xFFF0,
	0x8100, 0x0108, 0x8100, 0x7104,
	0x8100, 0x8902, 0x8100, 0x8901,
	0x8100, 0x8901, 0x8100, 0x8901,
	0x8100, 0x8901, 0x8100, 0x8901,
	0x8100, 0x7101, 0x8100, 0x0101,
	0x80FF, 0xFE01, 0x8000, 0x0001,
	0x8000, 0x0001, 0x8000, 0x0001,
	0x8000, 0x0001, 0x83FF, 0xFFC1,
	0x8400, 0x0021, 0x8400, 0x0021,
	0x8400, 0x0021, 0x8400, 0x0021,
	0x8400, 0x0021, 0x8406, 0x3021,
	0x8406, 0x6021, 0x8406, 0xC021,
	0x8407, 0x8021, 0x8407, 0x0021,
	0x8406, 0x0021, 0x8400, 0x0021,
	0x8400, 0x0021, 0x8400, 0x0021,
	0x7FFF, 0xFFFE, 0x3FFF, 0xFFF0,
	0x7FFF, 0xFFF0, 0xFFFF, 0xFFFC,
	0xFFFF, 0xFFFC, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
	0xFFFF, 0xFFFF, 0x7FFF, 0xFFFC,
	0x3FFF, 0xFFFC, 0x0000, 0x4E56,
	0x0000, 0x48E7, 0x1108, 0x3E2E,
	0x000A, 0x2878, 0x0134, 0xBE6C,
	0x0018, 0x6422, 0x200C, 0x724A,
	0xD081, 0x7400, 0x3407, 0x2602,
	0xC4FC, 0x0042, 0x4843, 0xC6FC,
	0x0042, 0x4843, 0x4243, 0xD483,
	0xD480, 0x2002, 0x6002, 0x7000,
	0x4CEE, 0x1088, 0xFFF4, 0x4E5E,
	0x4E75, 0x4E56, 0xFFE0, 0x48E7,
	0x1F18, 0x282E, 0x0008, 0x49EE,
	0xFFE0, 0x2A3C, 0x0000, 0xFFFF,
	0xCA84, 0x2678, 0x0134, 0x48C5,
	0x2F05, 0x4EBA, 0xFF9A, 0x2E00,
	0x5680, 0x2040, 0x7000, 0x1010,
	0x4A80, 0x584F, 0x6600, 0x00D4,
	0x38BC, 0x5B17, 0x396B, 0x001A,
	0x0002, 0x397C, 0x0005, 0x0004,
	0x3945, 0x0014, 0x206B, 0x0014,
	0x208C, 0x4A6C, 0x0006, 0x6600,
	0x00B2, 0x2C2C, 0x000C, 0x7009,
	0xE0AE, 0x0C86, 0x0000, 0x0320,
	0x6708, 0x0C86, 0x0000, 0x0640,
	0x6642, 0x0C86, 0x0000, 0x0320,
	0x660C, 0x2007, 0x7212, 0xD081,
	0x2040, 0x4210, 0x600C, 0x2007,
	0x7212, 0xD081, 0x2040, 0x10BC,
	0x00FF, 0x2007, 0x7213, 0xD081,
	0x2040, 0x10BC, 0x00FF, 0x2007,
	0x740A, 0xD082, 0x2040, 0x4250,
	0x2007, 0x7214, 0xD081, 0x2040,
	0x4250, 0x6032, 0x2007, 0x720E,
	0xD081, 0x2040, 0x30BC, 0xFFFE,
	0x2007, 0x740A, 0xD082, 0x2040,
	0x30BC, 0x0001, 0x2007, 0x7212,
	0xD081, 0x2040, 0x3086, 0x2006,
	0x4240, 0x4840, 0x2607, 0x7214,
	0xD681, 0x2043, 0x3080, 0x2004,
	0x4240, 0x4840, 0x2207, 0x5481,
	0x2041, 0x1080, 0x2007, 0x5680,
	0x2040, 0x10BC, 0x0001, 0x307C,
	0x0007, 0x48C5, 0x2005, 0x5280,
	0xA02F, 0x4CEE, 0x18F8, 0xFFC4,
	0x4E5E, 0x4E75, 0x4E56, 0x0000,
	0x4E5E, 0x4E75, 0x4E56, 0xFFDE,
	0x48E7, 0x1F18, 0x49EE, 0xFFE0,
	0x2C3C, 0x00F4, 0x0000, 0x78FF,
	0x38BC, 0x5B17, 0x426C, 0x0002,
	0x397C, 0x0001, 0x0004, 0x297C,
	0x4C92, 0x19E6, 0x0008, 0x2046,
	0x208C, 0x3A2C, 0x000C, 0x38BC,
	0x5B17, 0x3945, 0x0002, 0x397C,
	0x0006, 0x0004, 0x2046, 0x208C,
	0x4AAC, 0x0010, 0x6706, 0x4244,
	0x6000, 0x011A, 0x38BC, 0x5B17,
	0x3945, 0x0002, 0x397C, 0x0001,
	0x0004, 0x2046, 0x208C, 0x7000,
	0x302C, 0x0006, 0x4A80, 0x6600,
	0x00FC, 0x362C, 0x0008, 0x7000,
	0x3003, 0x2200, 0xC0FC, 0x0042,
	0x4841, 0xC2FC, 0x0042, 0x4841,
	0x4241, 0xD081, 0x2E00, 0x704A,
	0xDE80, 0x0C87, 0x0000, 0x0310,
	0x6406, 0x2E3C, 0x0000, 0x0310,
	0x2007, 0xA71E, 0x2648, 0x200B,
	0x6700, 0x00C2, 0x277C, 0x8413,
	0x39E2, 0x0010, 0x2746, 0x0014,
	0x3743, 0x0018, 0x3745, 0x001A,
	0x21CB, 0x0134, 0x2078, 0x011C,
	0x2278, 0x011C, 0x2368, 0x0010,
	0x0004, 0x206E, 0x000C, 0x117C,
	0x0001, 0x0007, 0x41FA, 0xFF1E,
	0x2748, 0x0022, 0x41EB, 0x001C,
	0xA058, 0x4246, 0x6052, 0x2007,
	0x5680, 0x2040, 0x4210, 0x2007,
	0x5880, 0x2040, 0x10BC, 0x0001,
	0x2007, 0x5A80, 0x2040, 0x10BC,
	0x00FF, 0x48C6, 0x2006, 0x5280,
	0x2207, 0x740C, 0xD282, 0x2041,
	0x3080, 0x2007, 0x720E, 0xD081,
	0x2040, 0x30BC, 0xFFFB, 0x2007,
	0x5C80, 0x2040, 0x48C6, 0x2006,
	0x5280, 0x4840, 0x4240, 0xD0BC,
	0x0000, 0xFFFB, 0xA04E, 0x5246,
	0x48C6, 0x2F06, 0x4EBA, 0xFD60,
	0x2E00, 0x584F, 0x66A0, 0x38BC,
	0x5B17, 0x3945, 0x0002, 0x397C,
	0x0007, 0x0004, 0x41FA, 0xFC30,
	0x2948, 0x0010, 0x206B, 0x0014,
	0x208C, 0x4244, 0x3004, 0x4CEE,
	0x18F8, 0xFFC2, 0x4E5E, 0x4E75,
	0x4E56, 0xFFD6, 0x48E7, 0x1F18,
	0x2E2E, 0x0008, 0x49EE, 0xFFDC,
	0x2007, 0x7216, 0xD081, 0x2040,
	0x7000, 0x3010, 0x5380, 0x3D40,
	0xFFDA, 0x2678, 0x0134, 0x7000,
	0x302E, 0xFFDA, 0x2F00, 0x4EBA,
	0xFCFE, 0x2D40, 0xFFFC, 0x584F,
	0x6608, 0x7CC8, 0x7A00, 0x6000,
	0x0174, 0x202E, 0xFFFC, 0x5680,
	0x2D40, 0xFFD6, 0x2040, 0x1810,
	0x7000, 0x1004, 0x0C40, 0x0002,
	0x6732, 0x7000, 0x1004, 0x0C40,
	0x0001, 0x660A, 0x206E, 0xFFD6,
	0x10BC, 0x0002, 0x601E, 0x7CBF,
	0x2007, 0x7210, 0xD081, 0x2040,
	0x3086, 0x2007, 0x7428, 0xD082,
	0x2040, 0x7200, 0x2081, 0x3006,
	0x6000, 0x0156, 0x2007, 0x722C,
	0xD081, 0x2040, 0x7000, 0x3010,
	0x740F, 0xC440, 0x0C42, 0x0003,
	0x6276, 0xD442, 0x343B, 0x2006,
	0x4EFB, 0x2000, 0x006E, 0x000A,
	0x0016, 0x0056, 0x2007, 0x722E,
	0xD081, 0x2040, 0x2810, 0x6064,
	0x38BC, 0x5B17, 0x396B, 0x001A,
	0x0002, 0x397C, 0x0005, 0x0004,
	0x396E, 0xFFDA, 0x0014, 0x206B,
	0x0014, 0x208C, 0x282C, 0x000C,
	0x4A6C, 0x0006, 0x57C3, 0x4403,
	0x4883, 0x3C03, 0x6706, 0x3006,
	0x6000, 0x00EE, 0x2007, 0x722E,
	0xD081, 0x2040, 0x9890, 0x6024,
	0x2007, 0x722E, 0xD081, 0x2040,
	0x202E, 0x000C, 0x7410, 0xD082,
	0x2240, 0x2811, 0xD890, 0x600C,
	0x202E, 0x000C, 0x7210, 0xD081,
	0x2040, 0x2810, 0x2007, 0x7224,
	0xD081, 0x2040, 0x2A10, 0x38BC,
	0x5B17, 0x396B, 0x001A, 0x0002,
	0x2944, 0x0008, 0x2945, 0x000C,
	0x2007, 0x7420, 0xD082, 0x2040,
	0x2950, 0x0010, 0x396E, 0xFFDA,
	0x0014, 0x2007, 0x5C80, 0x2040,
	0x7000, 0x3010, 0x363C, 0xF0FF,
	0xC640, 0x0443, 0xA002, 0x6706,
	0x5343, 0x6718, 0x6042, 0x397C,
	0x0002, 0x0004, 0x206B, 0x0014,
	0x208C, 0x2A2C, 0x000C, 0x3C2C,
	0x0006, 0x6030, 0x202E, 0xFFFC,
	0x5480, 0x2040, 0x7000, 0x1010,
	0x4A80, 0x6706, 0x7A00, 0x7CD4,
	0x601A, 0x397C, 0x0003, 0x0004,
	0x206B, 0x0014, 0x208C, 0x2A2C,
	0x000C, 0x3C2C, 0x0006, 0x6004,
	0x70EF, 0x602C, 0x2007, 0x7210,
	0xD081, 0x2040, 0x3086, 0x2007,
	0x7428, 0xD082, 0x2040, 0x2085,
	0x202E, 0x000C, 0xD081, 0x2040,
	0x2005, 0xD090, 0x262E, 0x000C,
	0xD681, 0x2043, 0x2080, 0x3006,
	0x4CEE, 0x18F8, 0xFFBA, 0x4E5E,
	0x4E75, 0x4E56, 0xFFDC, 0x48E7,
	0x1F18, 0x2A2E, 0x0008, 0x49EE,
	0xFFDC, 0x2005, 0x721A, 0xD081,
	0x2040, 0x7600, 0x3610, 0x2005,
	0x7216, 0xD081, 0x2040, 0x7000,
	0x3010, 0x2800, 0x5384, 0x2678,
	0x0134, 0x7000, 0x3004, 0x2F00,
	0x4EBA, 0xFB0C, 0x2C00, 0x584F,
	0x6606, 0x7EC8, 0x6000, 0x00DE,
	0x2006, 0x5680, 0x2040, 0x7000,
	0x1010, 0x4A80, 0x6606, 0x7EBF,
	0x6000, 0x00CA, 0x38BC, 0x5B17,
	0x396B, 0x001A, 0x0002, 0x3944,
	0x0014, 0x2003, 0x5380, 0x671C,
	0x5980, 0x671E, 0x5380, 0x674E,
	0x5380, 0x671C, 0x0480, 0x0000,
	0x000E, 0x6746, 0x5580, 0x6768,
	0x6000, 0x0098, 0x7EFF, 0x6000,
	0x0094, 0x4247, 0x6000, 0x008E,
	0x2006, 0x5480, 0x2040, 0x4210,
	0x2006, 0x5680, 0x2040, 0x4210,
	0x2006, 0x720E, 0xD081, 0x2040,
	0x30BC, 0xFFFB, 0x397C, 0x0004,
	0x0004, 0x206B, 0x0014, 0x208C,
	0x3E2C, 0x0006, 0x605E, 0x4247,
	0x605A, 0x2006, 0x720A, 0xD081,
	0x2040, 0x7000, 0x3010, 0x4A80,
	0x6712, 0x41FA, 0xF968, 0x2005,
	0x721C, 0xD081, 0x2240, 0x2288,
	0x4247, 0x6038, 0x7EEF, 0x6034,
	0x2006, 0x720A, 0xD081, 0x2040,
	0x7000, 0x3010, 0x4A80, 0x6704,
	0x7C01, 0x6002, 0x7C03, 0x7000,
	0x3004, 0x4A80, 0x6706, 0x0686,
	0x0000, 0x0900, 0x2005, 0x721C,
	0xD081, 0x2040, 0x2086, 0x4247,
	0x6002, 0x7EEF, 0x3007, 0x4CEE,
	0x18F8, 0xFFC0, 0x4E5E, 0x4E75,
	0x4E56, 0x0000, 0x48E7, 0x1F00,
	0x2A2E, 0x0008, 0x2005, 0x7216,
	0xD081, 0x2040, 0x7000, 0x3010,
	0x2800, 0x5384, 0x2005, 0x741A,
	0xD082, 0x2040, 0x7000, 0x3010,
	0x7608, 0xB680, 0x6630, 0x7000,
	0x3004, 0x2F00, 0x4EBA, 0xF9E0,
	0x2E00, 0x584F, 0x6604, 0x78C8,
	0x601E, 0x2C05, 0x701C, 0xDC80,
	0x7A0B, 0x600A, 0x2047, 0x2246,
	0x3290, 0x5487, 0x5486, 0x5385,
	0x6CF2, 0x4244, 0x6002, 0x78EE,
	0x3004, 0x4CEE, 0x00F8, 0xFFEC,
	0x4E5E, 0x4E75, 0x4E56, 0x0000,
	0x70E8, 0x4E5E, 0x4E75
#endif
};
#endif

#if CurEmu <= kEmu512K
#define Sony_DriverBase 0x1690
#elif CurEmu <= kEmuPlus
#define Sony_DriverBase 0x17D30
#elif CurEmu <= kEmuSE
#define Sony_DriverBase 0x34680
#elif CurEmu <= kEmuClassic
#define Sony_DriverBase 0x34680
#endif

#define kVidMem_Base 0x00540000
#define kROM_Base 0x00400000

#if CurEmu <= kEmuClassic
LOCALPROC Sony_Install(void)
{
	int i;
	ui3p pto = Sony_DriverBase + ROM;
	ui4b *pfrom = (ui4b *)sony_driver;

	for (i = sizeof(sony_driver) / 2; --i >= 0; ) {
		do_put_mem_word(pto, *pfrom);
		pfrom++;
		pto += 2;
	}

#if IncludeVidMem
	{
		ui3p patchp = pto;

#include "SCRNHACK.h"
	}
#endif
}
#endif

LOCALFUNC blnr Check_Checksum(ui5b CheckSum1)
{
	long int i;
	ui5b CheckSum2 = 0;
	ui3p p = 4 + ROM;

	for (i = (kTrueROM_Size - 4) >> 1; --i >= 0; ) {
		CheckSum2 += do_get_mem_word(p);
		p += 2;
	}
	return (CheckSum1 == CheckSum2);
}

GLOBALFUNC blnr ROM_Init(void)
{
	ui5b CheckSum = do_get_mem_long(ROM);

	if (! Check_Checksum(CheckSum)) {
		WarnMsgCorruptedROM();
	} else
#if CurEmu <= kEmu512K
	if (CheckSum == 0x28BA61CE) {
	} else
	if (CheckSum == 0x28BA4E50) {
	} else
#elif CurEmu <= kEmuPlus
	if (CheckSum == 0x4D1EEEE1) {
		/* Mac Plus ROM v 1, 'Lonely Hearts' */
	} else
	if (CheckSum == 0x4D1EEAE1) {
		/* Mac Plus ROM v 2, 'Lonely Heifers' */
	} else
	if (CheckSum == 0x4D1F8172) {
		/* Mac Plus ROM v 3, 'Loud Harmonicas' */
	} else
#elif CurEmu <= kEmuSE
	if (CheckSum == 0xB2E362A8) {
	} else
#elif CurEmu <= kEmuClassic
	if (CheckSum == 0xA49F9914) {
	} else
#endif
	{
		WarnMsgUnsupportedROM();
	}
	/*
		Even if ROM is corrupt or unsupported, go ahead and
		try to run anyway. It shouldn't do any harm.
	*/

/* skip the rom checksum */
#if CurEmu <= kEmu512K
	do_put_mem_word(226 + ROM, 0x6004);
#elif CurEmu <= kEmuPlus
	do_put_mem_word(3450 + ROM, 0x6022);
#elif CurEmu <= kEmuClassic
	do_put_mem_word(7272 + ROM, 0x6008);
#endif

#if CurEmu <= kEmu512K
#elif CurEmu <= kEmuPlus
	do_put_mem_word(3752 + ROM, 0x4E71); /* shorten the ram check read */
	do_put_mem_word(3728 + ROM, 0x4E71); /* shorten the ram check write*/
#elif CurEmu <= kEmuClassic
	do_put_mem_word(134 + ROM, 0x6002);
	do_put_mem_word(286 + ROM, 0x6002);
#endif

	/* do_put_mem_word(862 + ROM, 0x4E71); */ /* shorten set memory*/

#if CurEmu <= kEmuClassic
	Sony_Install();
#endif

#if CurEmu <= kEmu512K
	MyMoveBytes(ROM, kTrueROM_Size + ROM, kTrueROM_Size);
#endif

	return trueblnr;
}
