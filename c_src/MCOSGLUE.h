/*
	MCOSGLUE.h

	Copyright (C) 2002 Philip Cummins, Richard F. Bannister, Paul Pratt

	You can redistribute this file and/or modify it under the terms
	of version 2 of the GNU General Public License as published by
	the Free Software Foundation.  You should have received a copy
	of the license along with with this file; see the file COPYING.

	This file is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	license for more details.
*/

/*
	MaCintosh Operating System GLUE.

	All operating system dependent code for the
	Macintosh platform should go here.

	This code is descended from Richard F. Bannister's Macintosh
	port of vMac, by Philip Cummins.

	The main entry point 'main' is at the end of this file.
*/

#ifndef HaveOSTarget
#error "HaveOSTarget undefined"
#endif

#ifndef UseCarbonLib
#define UseCarbonLib 0
#endif

#if UseCarbonLib
#define TARGET_API_MAC_CARBON 1
#endif

#ifndef NavigationAvail
#define NavigationAvail 0
#endif

#ifndef AppearanceAvail
#define AppearanceAvail 0
#endif

#ifndef DragMgrAvail
#define DragMgrAvail 0
#endif

#include "RESIDMAC.h"

#include <Types.h>
#include <MixedMode.h>
#include <Gestalt.h>
#include <Errors.h>
#include <Memory.h>
#include <OSUtils.h>
#include <QuickdrawText.h>
#include <QuickDraw.h>
#include <SegLoad.h>
#include <IntlResources.h>
#include <Events.h>
#include <Script.h>
#include <Files.h>
#include <Resources.h>
#include <Fonts.h>
#include <TextUtils.h>
#include <FixMath.h>
#include <ToolUtils.h>
#include <Menus.h>
#include <Scrap.h>
#include <Controls.h>
#include <AppleEvents.h>
#include <Processes.h>
#include <EPPC.h>
#include <Windows.h>
#include <TextEdit.h>
#include <Dialogs.h>
#include <Devices.h>
#include <Palettes.h>
#include <StandardFile.h>
#include <Aliases.h>
#include <Folders.h>
#include <Balloons.h>
#include <DiskInit.h>
#include <LowMem.h>
#include <sound.h>
#if AppearanceAvail
#include <Appearance.h>
#endif
#if NavigationAvail
#include <Navigation.h>
#endif
#if CPUfamilyMC68K
#include <Traps.h>
#endif

#ifndef CALL_NOT_IN_CARBON
#define CALL_NOT_IN_CARBON 1
#endif /* !defined(CALL_NOT_IN_CARBON) */

/*--- initial initialization ---*/

#if CALL_NOT_IN_CARBON
#if defined(__SC__) || ((defined(powerc) || defined(__powerc)) && ! defined(__MWERKS__))
/* GLOBALVAR */ QDGlobals qd;
#endif
#endif

LOCALFUNC blnr InitMacManagers(void)
{
#if CALL_NOT_IN_CARBON
	MaxApplZone();
#endif

	{
		int i;

		for (i = 7; --i >=0; ) {
			MoreMasters();
		}
	}

#if CALL_NOT_IN_CARBON
	InitGraf(&qd.thePort);
	InitFonts();
	InitWindows();
	InitMenus();
	TEInit();
	InitDialogs(NULL);
#endif
	InitCursor();
	return trueblnr;
}

/*--- some simple utilities ---*/

#define PowOf2(p) ((unsigned long)1 << (p))
#define TestBit(i, p) (((unsigned long)(i) & PowOf2(p)) != 0)

GLOBALPROC MyMoveBytes(anyp srcPtr, anyp destPtr, LONG byteCount)
{
	BlockMove((Ptr)srcPtr, (Ptr)destPtr, byteCount);
}

/* don't want to include c libraries, so: */
LOCALFUNC LONG CStrLen(char *src)
{
	char *p = src;
	while (*p++ != 0) {
	}
	return ((LONG)p) - ((LONG)src) - 1;
}

LOCALPROC CopyC2PStr(ps3p dst, /*CONST*/ char *src)
{
	LONG L;

	L = CStrLen(src);
	if (L > 255) {
		L = 255;
	}
	*dst++ = L;
	MyMoveBytes((anyp)src, (anyp)dst, L);
}

/*--- information about the environment ---*/

LOCALVAR blnr MyEnvrAttrAppleEvtMgrAvail;
#if AppearanceAvail
LOCALVAR blnr gWeHaveAppearance;
#endif
#if NavigationAvail
LOCALVAR blnr gNavServicesExists;
#endif
#if DragMgrAvail
LOCALVAR blnr gHaveDragMgr;
#endif

LOCALFUNC blnr InitCheckMyEnvrn(void)
{
	long result;

	MyEnvrAttrAppleEvtMgrAvail = falseblnr;
#if AppearanceAvail
	gWeHaveAppearance = falseblnr;
#endif
#if NavigationAvail
	gNavServicesExists = falseblnr;
#endif
#if DragMgrAvail
	gHaveDragMgr = falseblnr;
#endif

#if AppearanceAvail
	// Appearance Manager
	if (Gestalt(gestaltAppearanceAttr, &result) == 0)
	{
		gWeHaveAppearance = trueblnr;
	}
#endif

	// Navigation
#if NavigationAvail
	gNavServicesExists=NavServicesAvailable();
#endif

#if DragMgrAvail
	if (Gestalt(gestaltDragMgrAttr, &result) == 0)
	if (TestBit(result, gestaltDragMgrPresent))
	{
		gHaveDragMgr = trueblnr;
	}
#endif

	if (Gestalt(gestaltAppleEventsAttr, &result) == 0)
	if (TestBit(result, gestaltAppleEventsPresent))
	{
		MyEnvrAttrAppleEvtMgrAvail = trueblnr;
	}
	return trueblnr;
}

/* cursor hiding */

LOCALVAR blnr HaveCursorHidden = falseblnr;

LOCALPROC ForceShowCursor(void)
{
	if (HaveCursorHidden) {
		HaveCursorHidden = falseblnr;
		ShowCursor();
	}
}

/*--- basic dialogs ---*/

LOCALVAR blnr gBackgroundFlag = falseblnr;

#define HogCPU CALL_NOT_IN_CARBON

#if HogCPU
LOCALVAR long NoEventsCounter = 0;
#endif

GLOBALPROC MacMsg(char *briefMsg, char *longMsg, blnr fatal)
{
	Str255 briefMsgp;
	Str255 longMsgp;

	if (! gBackgroundFlag) {
		/* dialog during drag and drop hangs if in background */
		ForceShowCursor();
		CopyC2PStr(briefMsgp, briefMsg);
		CopyC2PStr(longMsgp, longMsg);
#if AppearanceAvail
		if (gWeHaveAppearance) {
			AlertStdAlertParamRec param;
			short itemHit;

			param.movable = 0;
			param.filterProc = nil;
			param.defaultText = "\pOK";
			param.cancelText = nil;
			param.otherText = nil;
			param.helpButton = false;
			param.defaultButton = kAlertStdAlertOKButton;
			param.cancelButton = 0;
			param.position = kWindowDefaultPosition;

			StandardAlert((fatal)? kAlertStopAlert : kAlertCautionAlert, briefMsgp, longMsgp, &param, &itemHit);
		} else
#endif
		{
			ParamText(briefMsgp, longMsgp, "\p", "\p");
			if (fatal) {
				while (StopAlert(kMyStandardAlert, NULL) != 1) {
				}
			} else {
				while (CautionAlert(kMyStandardAlert, NULL) != 1) {
				}
			}
			/* Alert (kMyStandardAlert, 0L); */
		}
#if HogCPU
		NoEventsCounter = 0;
#endif
	}
}

GLOBALFUNC blnr OkCancelAlert(char *briefMsg, char *longMsg)
{
	Str255 briefMsgp;
	Str255 longMsgp;

	ForceShowCursor();
	CopyC2PStr(briefMsgp, briefMsg);
	CopyC2PStr(longMsgp, longMsg);
#if AppearanceAvail
	if (gWeHaveAppearance) {
		short itemHit;
		AlertStdAlertParamRec param;

		param.movable = 0;
		param.filterProc = nil;
		param.defaultText = "\pOK";
		param.cancelText = "\pCancel";
		param.otherText = nil;
		param.helpButton = false;
		param.defaultButton = kAlertStdAlertCancelButton;
		param.cancelButton = 0;
		param.position = kWindowDefaultPosition;

		StandardAlert(kAlertCautionAlert, briefMsgp, longMsgp, &param, &itemHit);

		return (itemHit == kAlertStdAlertOKButton);
	} else
#endif
	{
		short itemHit;

		ParamText(briefMsgp, longMsgp, "\p", "\p");
		do {
			itemHit = CautionAlert(kMyOkCancelAlert, NULL);
		} while ((itemHit != 1) && (itemHit != 2));
		return (itemHit == 2);
	}
}

LOCALPROC ShowAboutMessage(void)
{
	ForceShowCursor();
	while (NoteAlert(kMyAboutAlert, NULL) != 1) {
	}
}

/*--- sending debugging info to file ---*/

#define MakeDumpFile 0

#if MakeDumpFile

#include <stdio.h>

LOCALVAR FILE *DumpFile;

LOCALFUNC blnr StartDump(void)
{
	DumpFile = fopen("DumpFile", "w");
	fprintf(DumpFile, "// vMac Dump File\n");
	return trueblnr;
}

LOCALPROC EndDump(void)
{
	fclose(DumpFile);
}

EXPORTPROC DumpAJump(CPTR fromaddr, CPTR toaddr);

GLOBALPROC DumpAJump(CPTR fromaddr, CPTR toaddr)
{
	fprintf(DumpFile, "%d,%d\n", fromaddr, toaddr);
}

EXPORTPROC DumpANote(char *s);

GLOBALPROC DumpANote(char *s)
{
	fprintf(DumpFile, s);
	/* fprintf(DumpFile, "at %d\n", m68k_getpc1() - 0x00400000); */
}

#endif

LOCALVAR WindowPtr gMyMainWindow = NULL;

LOCALFUNC blnr CreateMainWindow(void)
{
	Rect Bounds;
	short leftPos;
	short topPos;
	blnr IsOk = falseblnr;
	Rect *rp;
#if CALL_NOT_IN_CARBON
	rp = &qd.screenBits.bounds;
#else
	BitMap screenBits;

	GetQDGlobalsScreenBits(&screenBits);
	rp = &screenBits.bounds;
#endif

	// Create window rectangle and centre it on the screen
	leftPos=((rp->right - rp->left) - vMacScreenWidth) / 2;
	topPos=((rp->bottom - rp->top) - vMacScreenHeight) / 2;
	SetRect(&Bounds,0,0,vMacScreenWidth,vMacScreenHeight);
	OffsetRect(&Bounds, leftPos, topPos);

	/* SetEventMask(-1); want keyUp events */

	gMyMainWindow = NewWindow(0L,&Bounds,"\pMini vMac",true, noGrowDocProc ,(WindowPtr) -1,true,0);
	if (gMyMainWindow != NULL) {
		IsOk = trueblnr;
	}

	return IsOk;
}

LOCALFUNC blnr AllocateScreenCompare(void)
{
	screencomparebuff = NewPtr (vMacScreenNumBytes);
	if (screencomparebuff == NULL) {
		MacMsg("Not enough memory", "There is not enough memory available to allocate the screencomparebuff.", trueblnr);
		return falseblnr;
	} else {
		return trueblnr;
	}
}

#if CALL_NOT_IN_CARBON
#define SetPortFromWindow(w) SetPort(w)
#else
#define SetPortFromWindow(w) SetPort(GetWindowPort(w))
#endif

LOCALPROC Update_Screen(void)
{
	GrafPtr savePort;
	BitMap src;

	src.baseAddr = screencomparebuff;
	src.rowBytes = vMacScreenByteWidth;
	SetRect(&src.bounds,0,0,vMacScreenWidth,vMacScreenHeight);
	GetPort(&savePort);
	SetPortFromWindow(gMyMainWindow);
#if CALL_NOT_IN_CARBON
	CopyBits(&src, &gMyMainWindow->portBits, &src.bounds, &gMyMainWindow->portRect, srcCopy,NULL);
#else
	{
		Rect pr;
		CGrafPtr wp = GetWindowPort(gMyMainWindow);
		GetPortBounds(wp, &pr);
		CopyBits(&src,
			GetPortBitMapForCopyBits(wp),
			&src.bounds, &pr, srcCopy,NULL);
	}
#endif
	SetPort(savePort);
}

GLOBALPROC HaveChangedScreenBuff(WORD top, WORD left, WORD bottom, WORD right)
{
	GrafPtr savePort;
	BitMap src;
	Rect SrcRect;

	SrcRect.left = left;
	SrcRect.right = right;
	SrcRect.top = top;
	SrcRect.bottom = bottom;

	src.baseAddr = screencomparebuff;
	src.rowBytes = vMacScreenByteWidth;
	SetRect(&src.bounds,0,0,vMacScreenWidth,vMacScreenHeight);
	GetPort(&savePort);
	SetPortFromWindow(gMyMainWindow);
	CopyBits(&src,
#if CALL_NOT_IN_CARBON
		&gMyMainWindow->portBits,
#else
		GetPortBitMapForCopyBits(GetWindowPort(gMyMainWindow)),
#endif
		&SrcRect,&SrcRect,srcCopy,NULL);
	/* FrameRect(&SrcRect); for testing */
	SetPort(savePort);
}

LOCALVAR blnr CurTrueMouseButton = falseblnr;

LOCALPROC CheckMouseState (void)
{
	blnr ShouldHaveCursorHidden;
	UBYTE NewMouseButton;
	Point NewMousePos;
	GrafPtr oldPort;

	GetPort(&oldPort);
	SetPortFromWindow(gMyMainWindow);
	GetMouse(&NewMousePos);
	NewMouseButton = Button();
	SetPort(oldPort);

	ShouldHaveCursorHidden = trueblnr;
	if (NewMousePos.h < 0) {
		NewMousePos.h = 0;
		ShouldHaveCursorHidden = falseblnr;
	} else if (NewMousePos.h >= vMacScreenWidth) {
		NewMousePos.h = vMacScreenWidth - 1;
		ShouldHaveCursorHidden = falseblnr;
	}
	if (NewMousePos.v < 0) {
		NewMousePos.v = 0;
		ShouldHaveCursorHidden = falseblnr;
	} else if (NewMousePos.v >= vMacScreenHeight) {
		NewMousePos.v = vMacScreenHeight - 1;
		ShouldHaveCursorHidden = falseblnr;
	}

	if (CurTrueMouseButton != NewMouseButton) {
		CurTrueMouseButton = NewMouseButton;
		CurMouseButton = CurTrueMouseButton && ShouldHaveCursorHidden;
		/*
			CurMouseButton changes only when the button state changes.
			So if have mouse down outside our window, CurMouseButton will
			stay false even if mouse dragged back over our window.
			and if mouse down inside our window, CurMouseButton will
			stay true even if mouse dragged outside our window.
		*/
	}

	/* if (ShouldHaveCursorHidden || CurMouseButton) */
	/* for a game like arkanoid, would like mouse to still
	move even when outside window in one direction */
	{
		CurMouseV = NewMousePos.v;
		CurMouseH = NewMousePos.h;
	}

	if (HaveCursorHidden != ShouldHaveCursorHidden) {
		HaveCursorHidden = ShouldHaveCursorHidden;
		if (HaveCursorHidden) {
			HideCursor();
		} else {
			ShowCursor();
		}
	}
}

#define NotAfileRef (-1)

LOCALVAR short Drives[NumDrives]; /* open disk image files */

LOCALPROC InitDrives(void)
{
	WORD i;

	for (i = 0; i < NumDrives; ++i) {
		Drives[i] = NotAfileRef;
	}
}

GLOBALFUNC WORD vSonyRead(void *Buffer, UWORD Drive_No, ULONG Sony_Start, ULONG *Sony_Count)
{
	WORD result;

	if (Drive_No < NumDrives) {
		if (Drives[Drive_No] != NotAfileRef) {
			result = SetFPos(Drives[Drive_No], fsFromStart, Sony_Start);
			if (result == 0) {
				result = FSRead(Drives[Drive_No], (long *)Sony_Count, Buffer);
			}
		} else {
			result = 0xFFBF; // Say it's offline (-65)
		}
	} else {
		result = 0xFFC8; // No Such Drive (-56)
	}
	return result;
}

GLOBALFUNC WORD vSonyWrite(void *Buffer, UWORD Drive_No, ULONG Sony_Start, ULONG *Sony_Count)
{
	WORD result;

	if (Drive_No < NumDrives) {
		if (Drives[Drive_No] != NotAfileRef) {
#if 0
			if (Write Protected) {
				result = 0xFFD4; // Write Protected (-44)
			} else
#endif
			{
				result = SetFPos(Drives[Drive_No], fsFromStart, Sony_Start);
				if (result == 0) {
					result = FSWrite(Drives[Drive_No], (long *)Sony_Count, Buffer);
				}
			}
		} else {
			result = 0xFFBF; // Say it's offline (-65)
		}
	} else {
		result = 0xFFC8; // No Such Drive (-56)
	}
	return result;
}

GLOBALFUNC blnr vSonyDiskLocked(UWORD Drive_No)
{
	UnusedParam(Drive_No);
	return falseblnr;
}

GLOBALFUNC WORD vSonyGetSize(UWORD Drive_No, ULONG *Sony_Count)
{
	WORD result;

	if (Drive_No < NumDrives) {
		if (Drives[Drive_No] != NotAfileRef) {
			result = GetEOF(Drives[Drive_No], (long *)Sony_Count);
		} else {
			result = 0xFFBF; // Say it's offline (-65)
		}
	} else {
		result = 0xFFC8; // No Such Drive (-56)
	}
	return result;
}

GLOBALFUNC WORD vSonyEject(UWORD Drive_No)
{
	WORD result;
	short vRefNum;

	if (Drive_No < NumDrives) {
		if (Drives[Drive_No] != NotAfileRef) {
			result = GetVRefNum(Drives[Drive_No], &vRefNum);
			if (result == 0) {
				result = FlushVol(NULL, vRefNum);
			}
			/* should report result if nonzero, but still close in any case */
			result = FSClose(Drives[Drive_No]);
			Drives[Drive_No] = NotAfileRef;
		}
		result = 0x0000;
	} else {
		result = 0xFFC8; // No Such Drive (-56)
	}
	return result;
}

GLOBALFUNC WORD vSonyVerify(UWORD Drive_No)
{
	WORD result;

	if (Drive_No < NumDrives) {
		if (Drives[Drive_No] != NotAfileRef) {
			result = 0x0000; // No Error (0)
		} else {
			result = 0xFFBF; // Say it's offline (-65)
		}
	} else {
		result = 0xFFC8; // No Such Drive (-56)
	}
	return result;
}

GLOBALFUNC WORD vSonyFormat(UWORD Drive_No)
{
	WORD result;

	if (Drive_No < NumDrives) {
		if (Drives[Drive_No] != NotAfileRef) {
			result = 0xFFD4; // Write Protected (-44)
		} else {
			result = 0xFFBF; // Say it's offline (-65)
		}
	} else {
		result = 0xFFC8; // No Such Drive (-56)
	}
	return result;
}

GLOBALFUNC blnr vSonyInserted (UWORD Drive_No)
{
	if (Drive_No >= NumDrives) {
		return falseblnr;
	} else {
		return (Drives[Drive_No] != NotAfileRef);
	}
}

LOCALFUNC blnr FirstFreeDisk(UWORD *Drive_No)
{
	WORD i;

	for (i = 0; i < NumDrives; ++i) {
		if (Drives[i] == NotAfileRef) {
			*Drive_No = i;
			return trueblnr;
		}
	}
	return falseblnr;
}

GLOBALFUNC blnr AnyDiskInserted(void)
{
	WORD i;

	for (i = 0; i < NumDrives; ++i) {
		if (Drives[i] != NotAfileRef) {
			return trueblnr;
		}
	}
	return falseblnr;
}

LOCALFUNC blnr Sony_Insert0(short refnum)
{
	UWORD Drive_No;

	if (! FirstFreeDisk(&Drive_No)) {
		(void) FSClose(refnum);
		MacMsg(kStrTooManyImagesTitle, kStrTooManyImagesMessage, falseblnr);
		return falseblnr;
	} else {
		Drives[Drive_No] = refnum;
		MountPending |= ((ULONG)1 << Drive_No);
		return trueblnr;
	}
}

LOCALFUNC blnr InsertADiskFromFileRef(FSSpec *spec)
{
	short refnum;
	OSErr err;

	err = FSpOpenDF(spec, fsRdWrPerm, &refnum);
	if (err != 0) {
		/* report this */
#if 1
		if (opWrErr == err) {
			MacMsg(kStrImageInUseTitle, kStrImageInUseMessage, falseblnr);
		}
#endif
		return falseblnr;
	} else {
		return Sony_Insert0(refnum);
	}
}

LOCALFUNC blnr InsertADiskFromNameEtc(short vRefNum, long dirID, ConstStr255Param fileName)
{
	FSSpec spec;
	Boolean isFolder;
	Boolean isAlias;

	if (0 == FSMakeFSSpec(vRefNum, dirID, fileName, &spec))
	if (0 == ResolveAliasFile(&spec, trueblnr, &isFolder, &isAlias))
	if (InsertADiskFromFileRef(&spec))
	{
		return trueblnr;
	}
	return falseblnr;
}

LOCALFUNC blnr LoadInitialImages(void)
{
	FCBPBRec pb;
	Str255 fileName;

	pb.ioNamePtr = fileName;
	pb.ioVRefNum = 0;
	pb.ioRefNum = CurResFile();
	pb.ioFCBIndx = 0;
	if (0 == PBGetFCBInfoSync(&pb)) {
		/* stop on first error (including file not found) */
		if (InsertADiskFromNameEtc(pb.ioFCBVRefNum, pb.ioFCBParID, "\pdisk1.dsk"))
		if (InsertADiskFromNameEtc(pb.ioFCBVRefNum, pb.ioFCBParID, "\pdisk2.dsk"))
		if (InsertADiskFromNameEtc(pb.ioFCBVRefNum, pb.ioFCBParID, "\pdisk3.dsk"))
		{
		}
	}
	return trueblnr;
}

#if NavigationAvail
pascal Boolean NavigationFilterProc(AEDesc* theItem, void* info, void* NavCallBackUserData, NavFilterModes theNavFilterModes);
pascal Boolean NavigationFilterProc(AEDesc* theItem, void* info, void* NavCallBackUserData, NavFilterModes theNavFilterModes)
{
	OSErr theErr = noErr;
	Boolean display = true;
	NavFileOrFolderInfo* theInfo = (NavFileOrFolderInfo*)info;
	UnusedParam(theNavFilterModes);
	UnusedParam(NavCallBackUserData);

	if ( theItem->descriptorType == typeFSS )
		if ( !theInfo->isFolder )
			{
			// use:
			// 'theInfo->fileAndFolder.fileInfo.finderInfo.fdType'
			// to check for the file type you want to filter.
			}
	return display;
}
#endif


#if NavigationAvail
pascal void NavigationEventProc(NavEventCallbackMessage callBackSelector, NavCBRecPtr callBackParms, void *NavCallBackUserData);
pascal void NavigationEventProc(NavEventCallbackMessage callBackSelector, NavCBRecPtr callBackParms, void *NavCallBackUserData)
{
	UnusedParam(NavCallBackUserData);

	if (callBackSelector == kNavCBEvent) {
		switch (callBackParms->eventData./**/eventDataParms.event->what) {
			case updateEvt:
				{
					WindowPtr which = (WindowPtr)callBackParms->eventData./**/eventDataParms.event->message;

					BeginUpdate(which);

					if (which == gMyMainWindow) {
						Update_Screen();
					}

					EndUpdate(which);
				}
				break;
		}
	}
}
#endif

LOCALPROC InsertADisk(void)
{
#if NavigationAvail
#if CALL_NOT_IN_CARBON
#define MyDisposeNavEventUPP(userUPP) DisposeRoutineDescriptor(userUPP)
#define MyDisposeNavObjectFilterUPP(userUPP) DisposeRoutineDescriptor(userUPP)
#define MyNewNavObjectFilterUPP NewNavObjectFilterProc
#define MyNewNavEventUPP NewNavEventProc
#else
#define MyDisposeNavEventUPP DisposeNavEventUPP
#define MyDisposeNavObjectFilterUPP DisposeNavObjectFilterUPP
#define MyNewNavObjectFilterUPP NewNavObjectFilterUPP
#define MyNewNavEventUPP NewNavEventUPP
#endif

	FSSpec spec;

	if (gNavServicesExists)
	{
		NavReplyRecord theReply;
		NavDialogOptions dialogOptions;
		OSErr theErr = noErr;
		NavTypeListHandle openList = NULL;
		long count = 0;
		NavObjectFilterUPP filterUPP = MyNewNavObjectFilterUPP(/* (NavObjectFilterProcPtr) */NavigationFilterProc);
		NavEventUPP eventUPP = MyNewNavEventUPP(/* (NavEventProcPtr) */NavigationEventProc);

		theErr = NavGetDefaultDialogOptions(&dialogOptions);

		/* GetIndString((unsigned char*)&dialogOptions.clientName,130,1); */

		dialogOptions.dialogOptionFlags += kNavDontAutoTranslate;
		/* dialogOptions.dialogOptionFlags -= kNavAllowMultipleFiles; */
		dialogOptions.dialogOptionFlags -= kNavAllowPreviews;

		theErr = NavGetFile(NULL,
						&theReply,
						&dialogOptions,
						/* NULL */eventUPP,
						NULL,
						filterUPP,
						(NavTypeListHandle)openList,
						NULL);

		MyDisposeNavObjectFilterUPP(filterUPP);
		MyDisposeNavEventUPP(eventUPP);

		if (theErr == noErr)
		{
			// grab the target FSSpec from the AEDesc for opening:
			if (theReply.validRecord) {
				AEKeyword keyword;
				DescType typeCode;
				Size actualSize;
				long index;
				long itemsInList;

				theErr = AECountItems(&theReply.selection, &itemsInList);
				if (theErr == noErr) {
					for (index = 1; index <= itemsInList; ++index) { /*Get each descriptor from the list, get the alias record, open the file, maybe print it.*/
						theErr = AEGetNthPtr(&theReply.selection, index, typeFSS, &keyword, &typeCode,
											(Ptr)&spec, sizeof(FSSpec), &actualSize);
						if (theErr == noErr) {
							if (! InsertADiskFromFileRef(&spec)) {
								break;
							}
						}
					}
				}
			}

			NavDisposeReply(&theReply);
		}

	} else
#endif
	{
#if CALL_NOT_IN_CARBON
		StandardFileReply reply;

		StandardGetFile(0L, -1, 0L, &reply);
		if (reply.sfGood) {
			(void) InsertADiskFromFileRef(&reply.sfFile);
		}
#endif
	}
}

LOCALFUNC blnr AllocateMacROM(void)
{
	ROM = (UWORD *)NewPtr(kROM_Size);
	if (ROM == NULL) {
		MacMsg("Not enough Memory.", "Unable to allocate ROM.", trueblnr);
		return falseblnr;
	} else {
		return trueblnr;
	}
}

LOCALFUNC blnr LoadMacRom(void)
{
	FCBPBRec pb;
	Str255 fileName;
	OSErr err;
	FSSpec spec;
	short refnum;
	Boolean isFolder;
	Boolean isAlias;
	long count = kROM_Size;

	pb.ioNamePtr = fileName;
	pb.ioVRefNum = 0;
	pb.ioRefNum = CurResFile();
	pb.ioFCBIndx = 0;
	err = PBGetFCBInfoSync(&pb);
	if (err == 0) {
		err = FSMakeFSSpec(pb.ioFCBVRefNum, pb.ioFCBParID, "\pvMac.ROM", &spec);
		if (err == fnfErr) {
			MacMsg("Unable to locate ROM image.", "The file vMac.ROM could not be found. Please read the manual for instructions on where to get this file.", trueblnr);
		} else if (err == 0) {
			if (0 == ResolveAliasFile(&spec, trueblnr, &isFolder, &isAlias)) {
				err = FSpOpenDF(&spec, fsRdPerm, &refnum);
				if (err == 0) {
					err = FSRead(refnum, &count, ROM);
					(void) FSClose(refnum);
				}
			}
		}
	}
	return (err == 0);
}

LOCALFUNC blnr AllocateMacRAM (void)
{
#define MemLeaveInMacHeap (128 * 1024L)
	kRAM_Size = FreeMem() - MemLeaveInMacHeap - RAMSafetyMarginFudge;
	if (kRAM_Size < 0) {
		kRAM_Size = 0;
	} else {
		long contig = MaxBlock();

		if (kRAM_Size > contig) {
			kRAM_Size = contig;
		}
	}
	if (kRAM_Size > 0x00400000) {
		kRAM_Size = 0x00400000;
	} else if (kRAM_Size > 0x00200000) {
		kRAM_Size = 0x00200000;
	} else if (kRAM_Size > 0x00100000) {
		kRAM_Size = 0x00100000;
	} else {
		return falseblnr;
	}

	RAM = (UWORD *)NewPtr(kRAM_Size + RAMSafetyMarginFudge);

	return (RAM != NULL);
}

GLOBALFUNC ULONG GetMacDateInSecond(void)
{
	unsigned long secs;

	GetDateTime(&secs);
	return secs;
}

#define openOnly 1
#define openPrint 2

LOCALFUNC blnr GotRequiredParams(AppleEvent *theAppleEvent)
{
	DescType typeCode;
	Size actualSize;
	OSErr theErr;

	theErr = AEGetAttributePtr(theAppleEvent, keyMissedKeywordAttr,
				typeWildCard, &typeCode, NULL, 0, &actualSize);
	if (theErr == errAEDescNotFound) { /*No more required params.*/
		return trueblnr;
	} else if (theErr == noErr) { /*More required params!*/
		return /* CheckSysCode(errAEEventNotHandled) */ falseblnr;
	} else { /*Unexpected Error!*/
		return /* CheckSysCode(theErr) */ falseblnr;
	}
}

LOCALFUNC blnr GotRequiredParams0(AppleEvent *theAppleEvent)
{
	DescType typeCode;
	Size actualSize;
	OSErr theErr;

	theErr = AEGetAttributePtr(theAppleEvent, keyMissedKeywordAttr,
				typeWildCard, &typeCode, NULL, 0, &actualSize);
	if (theErr == errAEDescNotFound) { /*No more required params.*/
		return trueblnr;
	} else if (theErr == noErr) { /*More required params!*/
		return trueblnr; /* errAEEventNotHandled; */ /*^*/
	} else { /*Unexpected Error!*/
		return /* CheckSysCode(theErr) */falseblnr;
	}
}

/* call back */ static pascal OSErr OpenOrPrintFiles(AppleEvent *theAppleEvent, AppleEvent *reply, long aRefCon)
{
	/*Adapted from IM VI: AppleEvent Manager: Handling Required AppleEvents*/
	FSSpec myFSS;
	AEDescList docList;
	long index;
	long itemsInList;
	Size actualSize;
	AEKeyword keywd;
	DescType typeCode;

	UnusedParam(reply);
	UnusedParam(aRefCon);
	/*put the direct parameter (a list of descriptors) into docList*/
	if (0 ==(AEGetParamDesc(theAppleEvent, keyDirectObject, typeAEList, &docList))) {
		if (GotRequiredParams0(theAppleEvent)) { /*Check for missing required parameters*/
			if (0 ==(AECountItems(&docList, &itemsInList))) {
				for (index = 1; index <= itemsInList; ++index) { /*Get each descriptor from the list, get the alias record, open the file, maybe print it.*/
					if (0 ==(AEGetNthPtr(&docList, index, typeFSS, &keywd, &typeCode,
										(Ptr)&myFSS, sizeof(FSSpec), &actualSize))) {
						/* printIt = (aRefCon == openPrint) */
						/* DoGetAliasFileRef(&myFSS); */
						if (! InsertADiskFromFileRef(&myFSS)) {
							break;
						}
					}
					if (/* errCode != 0 */ false) {
						break;
					}
				}
			}
		}
		/* vCheckSysCode */ (void) (AEDisposeDesc(&docList));
	}
	return /* GetASysResultCode() */0;
}

/* call back */ static pascal OSErr DoOpenEvent(AppleEvent *theAppleEvent, AppleEvent *reply, long aRefCon)
/*This is the alternative to getting an open document event on startup.*/
{
	UnusedParam(reply);
	UnusedParam(aRefCon);
	if (GotRequiredParams0(theAppleEvent)) {
	}
	return /* GetASysResultCode() */0; /*Make sure there are no additional "required" parameters.*/
}


/* call back */ static pascal OSErr DoQuitEvent(AppleEvent *theAppleEvent, AppleEvent *reply, long aRefCon)
{
	UnusedParam(reply);
	UnusedParam(aRefCon);
	if (GotRequiredParams(theAppleEvent)) {
		RequestMacOff = trueblnr;
	}
	return /* GetASysResultCode() */ 0;
}

#if CALL_NOT_IN_CARBON
#define MyNewAEEventHandlerUPP NewAEEventHandlerProc
#else
#define MyNewAEEventHandlerUPP NewAEEventHandlerUPP
#endif

LOCALFUNC blnr MyInstallEventHandler(AEEventClass theAEEventClass, AEEventID theAEEventID,
						ProcPtr p, long handlerRefcon, blnr isSysHandler)
{
	return 0 == (AEInstallEventHandler(theAEEventClass, theAEEventID,
#if /* useUPP */1
			MyNewAEEventHandlerUPP((AEEventHandlerProcPtr)p),
#else
			(AEEventHandlerUPP)p,
#endif
			handlerRefcon, isSysHandler));
}

#if DragMgrAvail
static pascal OSErr GlobalTrackingHandler(short message, WindowRef pWindow, void *handlerRefCon, DragReference theDragRef)
{
	RgnHandle hilightRgn;
	Rect Bounds;

	UnusedParam(pWindow);
	UnusedParam(handlerRefCon);
	switch(message) {
		case kDragTrackingEnterWindow:
			SetRect(&Bounds,0,0,vMacScreenWidth,vMacScreenHeight);
			hilightRgn = NewRgn();
			if (hilightRgn != NULL) {
				RectRgn(hilightRgn, &Bounds);
				ShowDragHilite(theDragRef, hilightRgn, true);
				DisposeRgn(hilightRgn);
			}
			break;
		case kDragTrackingLeaveWindow:
			HideDragHilite(theDragRef);
			break;
	}

	return noErr;

}
#endif

#if DragMgrAvail
static DragTrackingHandlerUPP gGlobalTrackingHandler = NULL;
#endif

#if DragMgrAvail
static pascal OSErr GlobalReceiveHandler(WindowRef pWindow, void *handlerRefCon, DragReference theDragRef)
{
	unsigned short items;
	unsigned short index;
	ItemReference theItem;
	Size SentSize;
	HFSFlavor r;

	UnusedParam(pWindow);
	UnusedParam(handlerRefCon);

	CountDragItems(theDragRef, &items);
	for (index = 1; index <= items; index++) {
		GetDragItemReferenceNumber(theDragRef, index, &theItem);
		if (GetFlavorDataSize(theDragRef, theItem, flavorTypeHFS, &SentSize) == noErr) {
			if (SentSize == sizeof(HFSFlavor)) {
				GetFlavorData(theDragRef, theItem, flavorTypeHFS, (Ptr)&r, &SentSize, 0);
				if (! InsertADiskFromFileRef(&r.fileSpec)) {
				}
			}
		}
	}

	return noErr;
}
#endif

#if DragMgrAvail
static DragReceiveHandlerUPP gGlobalReceiveHandler = NULL;
#endif

#if DragMgrAvail
#if CALL_NOT_IN_CARBON
#define MyNewDragTrackingHandlerUPP NewDragTrackingHandlerProc
#define MyNewDragReceiveHandlerUPP NewDragReceiveHandlerProc
#else
#define MyNewDragTrackingHandlerUPP NewDragTrackingHandlerUPP
#define MyNewDragReceiveHandlerUPP NewDragReceiveHandlerUPP
#endif
#if !OPAQUE_UPP_TYPES
#define MyDisposeDragReceiveHandlerUPP(userUPP) DisposeRoutineDescriptor(userUPP)
#define MyDisposeDragTrackingHandlerUPP(userUPP) DisposeRoutineDescriptor(userUPP)
#else
#define MyDisposeDragReceiveHandlerUPP DisposeDragReceiveHandlerUPP
#define MyDisposeDragTrackingHandlerUPP DisposeDragTrackingHandlerUPP
#endif
#endif

#if DragMgrAvail
LOCALFUNC blnr PrepareForDragging(void)
{
	gGlobalTrackingHandler = MyNewDragTrackingHandlerUPP(GlobalTrackingHandler);
	if (gGlobalTrackingHandler != NULL) {
		gGlobalReceiveHandler = MyNewDragReceiveHandlerUPP(GlobalReceiveHandler);
		if (gGlobalReceiveHandler != NULL) {
			if (InstallTrackingHandler(gGlobalTrackingHandler, nil, nil) == 0) {
				if (InstallReceiveHandler(gGlobalReceiveHandler, nil, nil) == 0) {
					return trueblnr;
					/* RemoveReceiveHandler(gGlobalReceiveHandler, nil); */
				}
				RemoveTrackingHandler(gGlobalTrackingHandler, nil);
			}
			MyDisposeDragReceiveHandlerUPP(gGlobalReceiveHandler);
		}
		MyDisposeDragTrackingHandlerUPP(gGlobalTrackingHandler);
	}
	return falseblnr;
}
#endif

LOCALFUNC blnr InstallOurEventHandlers(void)
{
	if (MyEnvrAttrAppleEvtMgrAvail) {
		if (AESetInteractionAllowed(kAEInteractWithLocal) == 0)
		if (MyInstallEventHandler(kCoreEventClass, kAEOpenApplication, (ProcPtr)DoOpenEvent, 0, falseblnr))
		if (MyInstallEventHandler(kCoreEventClass, kAEOpenDocuments, (ProcPtr)OpenOrPrintFiles, openOnly, falseblnr))
		if (MyInstallEventHandler(kCoreEventClass, kAEPrintDocuments, (ProcPtr)OpenOrPrintFiles, openPrint, falseblnr))
		if (MyInstallEventHandler(kCoreEventClass, kAEQuitApplication, (ProcPtr)DoQuitEvent, 0, falseblnr))
		{
		}
	}
#if DragMgrAvail
	if (gHaveDragMgr) {
		gHaveDragMgr = PrepareForDragging();
	}
#endif
	return trueblnr;
}

LOCALVAR blnr SpeedLimit = falseblnr;

#if ! CALL_NOT_IN_CARBON
#define CheckItem CheckMenuItem
#endif

LOCALPROC MacOS_UpdateMenus(void)
{
	MenuHandle hHardware;

	hHardware = GetMenuHandle(kSpecialMenu);
	CheckItem(hHardware, kSpecialLimitSpeedItem, SpeedLimit);
}

LOCALPROC MacOS_HandleMenu (short menuID, short menuItem)
{
	switch (menuID) {
		case kAppleMenu:
			if (menuItem == kAppleAboutItem) {
				ShowAboutMessage();
			} else {
#if CALL_NOT_IN_CARBON
				Str32 name;
				GrafPtr savePort;

				GetPort(&savePort);
				GetMenuItemText(GetMenuHandle(kAppleMenu), menuItem, name);
				OpenDeskAcc(name);
				SystemTask();
				SetPort(savePort);
#endif
			}
			break;

		case kFileMenu:
			switch (menuItem) {
				case kFileOpenDiskImage:
					InsertADisk();
					break;

				case kFileQuitItem:
					RequestMacOff = trueblnr;
					break;
			}
			break;

		case kSpecialMenu:
			switch (menuItem) {
				case kSpecialLimitSpeedItem:
					SpeedLimit = ! SpeedLimit;
					break;
				case kSpecialResetItem:
					RequestMacReset = trueblnr;
					break;
				case kSpecialInterruptItem:
					RequestMacInterrupt = trueblnr;
					break;
			}
			break;

		default:
			/* if menuID == 0, then no command chosen from menu */
			/* do nothing */
			break;
	}
}

LOCALPROC HandleMacEvent(EventRecord *theEvent)
{
	WindowPtr whichWindow;
	GrafPtr savePort;

	switch(theEvent->what) {
		case mouseDown:
			switch (FindWindow(theEvent->where, &whichWindow)) {
				case inSysWindow:
#if CALL_NOT_IN_CARBON
					SystemClick(theEvent, whichWindow);
#endif
					break;
				case inMenuBar:
					MacOS_UpdateMenus();
					ForceShowCursor();
					{
						long menuSelection = MenuSelect(theEvent->where);
						MacOS_HandleMenu(HiWord(menuSelection), LoWord(menuSelection));
					}
					HiliteMenu(0);
					break;

				case inDrag:
					{
						Rect *rp;
#if CALL_NOT_IN_CARBON
						rp = &qd.screenBits.bounds;
#else
						BitMap screenBits;

						GetQDGlobalsScreenBits(&screenBits);
						rp = &screenBits.bounds;
#endif

						DragWindow(whichWindow, theEvent->where, rp);
					}
					break;

				case inContent:
					if (FrontWindow() != whichWindow) {
						SelectWindow(whichWindow);
					}
					break;

				case inGoAway:
					if (TrackGoAway(whichWindow, theEvent->where)) {
						RequestMacOff = trueblnr;
					}
					break;

				case inZoomIn:
				case inZoomOut:
					// Zoom Boxes
					break;
			}
			break;

		case updateEvt:
			GetPort(&savePort);
			BeginUpdate( (WindowPtr) theEvent->message );

			if ((WindowPtr)theEvent->message == gMyMainWindow) {
				Update_Screen();
			}

			EndUpdate((WindowPtr) theEvent->message);
			SetPort(savePort);
			break;

		case keyDown:
		case keyUp:
		case autoKey:
			/* ignore it */
			break;
		case osEvt:
			if ((theEvent->message >> 24) & suspendResumeMessage) {
				if (theEvent->message & 1) {
					gBackgroundFlag = falseblnr;
				} else {
					gBackgroundFlag = trueblnr;
				}
			}
			break;
		case kHighLevelEvent:
			if ((AEEventClass)theEvent->message == kCoreEventClass) {
				if (/* CheckSysCode */0 == (AEProcessAppleEvent(theEvent))) {
				}
			} else {
				/* vCheckSysCode(errAENotAppleEvent); */
			}
			break;
	}
}

LOCALPROC WaitInBackground(void)
{
	EventRecord theEvent;

	ForceShowCursor();

	do {
		/* we're not doing anything, let system do as it pleases */
		if (WaitNextEvent(everyEvent, &theEvent, 5*60*60, NULL)) {
			HandleMacEvent(&theEvent);
		}
	} while (gBackgroundFlag);

#if HogCPU
	NoEventsCounter = 0;
#endif

#if CALL_NOT_IN_CARBON
	SetCursor(&qd.arrow);
#else
	{
		Cursor c;

		GetQDGlobalsArrow(&c);
		SetCursor(&c);
	}
#endif
}

LOCALPROC DontWaitForEvent(EventRecord *theEvent)
{
	/* we're busy, but see what system wants */

#if 0 /* this seems to cause crashes on some machines */

	if (EventAvail(everyEvent, theEvent)) {
		/*
			Have an Event, so reset NoEventsCounter, no matter what.
			WaitNextEvent can return false, even if it did handle an
			event. Such as a click in the collapse box. In this case
			we need to look out for update events.
		*/
		NoEventsCounter = 0;
#endif

		if (WaitNextEvent(everyEvent, theEvent, 0, NULL)) {
			HandleMacEvent(theEvent);
#if HogCPU
			NoEventsCounter = 0;
#endif
			if (gBackgroundFlag) {
				WaitInBackground();
			}
		}
#if 0
	}
#endif
}

#define PrivateEventMask (mDownMask | mUpMask | keyDownMask | keyUpMask | autoKeyMask)

LOCALPROC DoOnEachSixtieth(void)
{
	EventRecord theEvent;

#if HogCPU
	/* can't hog cpu in carbon. OSEventAvail and GetOSEvent not available. */
	if (! OSEventAvail(everyEvent, &theEvent)) {
		++NoEventsCounter;
		if (NoEventsCounter >= 120) {
			/*
				if no OSEvent now, and not looking for aftermath of
				event, assume there is no event of any kind we need to look at
			*/
		} else {
			DontWaitForEvent(&theEvent);
		}
	} else {
		WindowPtr whichWindow;

		blnr PrivateEvent = falseblnr;
		switch (theEvent.what) {
			case keyDown:
			case autoKey:
			case keyUp:
			case mouseUp:
				PrivateEvent = trueblnr;
				break;
			case mouseDown:
				if ((FindWindow(theEvent.where, &whichWindow) == inContent) && (whichWindow == gMyMainWindow)) {
					PrivateEvent = trueblnr;
				}
				break;
		}
		if (PrivateEvent) {
			/*
				if event can effect only us, and not looking out for aftermath
				of another event, then hog the cpu
			*/
			if (GetOSEvent(PrivateEventMask, &theEvent)) {
				HandleMacEvent(&theEvent);
			}
		} else {
			NoEventsCounter = 0;
			/*
				Have an Event, so reset NoEventsCounter, no matter what.
				WaitNextEvent can return false, even if it did handle an
				event. Such as a click in the collapse box. In this case
				we need to look out for update events.
			*/
			DontWaitForEvent(&theEvent);
		}
	}
#else
	DontWaitForEvent(&theEvent);
#endif

	CheckMouseState();
	GetKeys(*(KeyMap *)theKeys);
}

/*
	only look at when TickCount changes, rather than otherwise
	using its value, so as to avoid getting confused if it
	overflows and wraps.
*/

LOCALVAR long int LastTime;

LOCALFUNC blnr Init60thCheck(void)
{
	LastTime = TickCount();
	return trueblnr;
}

GLOBALFUNC blnr CheckIntSixtieth(blnr overdue)
{
	long int LatestTime;

	do {
		LatestTime = TickCount();
		if (LatestTime != LastTime) {
			DoOnEachSixtieth();
			LastTime = LatestTime;
			return trueblnr;
		}
	} while (SpeedLimit && overdue);
	return falseblnr;
}

LOCALPROC ZapOSGLUVars(void)
{
	InitDrives();
}

LOCALFUNC blnr InstallOurMenus(void)
{
	Handle menuBar;

	menuBar = GetNewMBar(kMyMenuBar);
	SetMenuBar(menuBar);
#if CALL_NOT_IN_CARBON
	AppendResMenu(GetMenuHandle(kAppleMenu), 'DRVR');
#else
	{
		MenuRef menu;
		long response;

		// see if we should modify quit in accordance with the Aqua HI guidelines
		if ((Gestalt(gestaltMenuMgrAttr, &response) == noErr) && (response & gestaltMenuMgrAquaLayoutMask))
		{
			menu = GetMenuHandle(kFileMenu);
			DeleteMenuItem(menu, kFileQuitItem);
			DeleteMenuItem(menu, kFileQuitItem-1); /* seperator */
		}
	}
#endif
	DrawMenuBar();

	return trueblnr;
}

LOCALFUNC blnr InstallOurAppearanceClient(void)
{
#if AppearanceAvail
	if (gWeHaveAppearance) {
		RegisterAppearanceClient();
	}
#endif
	return trueblnr;
}

LOCALFUNC blnr InitOSGLU(void)
{
	if (InitMacManagers())
	if (InitCheckMyEnvrn())
#if AppearanceAvail
	if (InstallOurAppearanceClient())
#endif
	if (InstallOurEventHandlers())
	if (InstallOurMenus())
	if (AllocateScreenCompare())
	if (CreateMainWindow())
	if (LoadInitialImages())
	if (AllocateMacROM())
	if (LoadMacRom())
#if MakeDumpFile
	if (StartDump())
#endif
	if (AllocateMacRAM())
	if (Init60thCheck())
	{
		return trueblnr;
	}
	return falseblnr;
}

LOCALPROC UnInitOSGLU(void)
{
#if MakeDumpFile
	EndDump();
#endif

#if DragMgrAvail
	if (gHaveDragMgr) {
		RemoveReceiveHandler(gGlobalReceiveHandler, nil);
		RemoveTrackingHandler(gGlobalTrackingHandler, nil);
	}
#endif

	ForceShowCursor();

/*
	we're relying on the operating
	system to take care of disposing
	our window, and any memory allocated
	should disappear with the applications
	heap.
*/
}

void main(void)
{
	ZapOSGLUVars();
	if (InitOSGLU()) {
		ProgramMain();
	}
	UnInitOSGLU();
}