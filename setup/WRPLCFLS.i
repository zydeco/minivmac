/*
	WRPLCFLS.i
	Copyright (C) 2010 Paul C. Pratt

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
	WRite Pelles C Compiler specific FiLeS
*/


LOCALPROC DoSrcFilePLCAddFile(void)
{
	WriteBlankLineToDestFile();
	WriteDestFileLn("# ");

	WriteBgnDestFileLn();
	WriteCStrToDestFile("# Build ");
	WriteSrcFileObjName();
	WriteCStrToDestFile(".");
	WriteEndDestFileLn();

	WriteDestFileLn("# ");

	WriteBgnDestFileLn();
	WriteSrcFileObjPath();
	WriteCStrToDestFile(": \\");
	WriteEndDestFileLn();

	++DestFileIndent;

		WriteBgnDestFileLn();
		WriteSrcFileFilePath();
		if ((DoSrcFile_gd()->Flgm & kCSrcFlgmNoHeader) == 0) {
			WriteCStrToDestFile(" \\");
			WriteEndDestFileLn();

			WriteBgnDestFileLn();
			WriteSrcFileHeaderPath();
		}
		WriteEndDestFileLn();

		WriteDestFileLn("$(CC) $(CCFLAGS) \"$!\" -Fo\"$@\"");

	--DestFileIndent;
}


LOCALPROC WritePLC_CCFLAGS(void)
{
	WriteCStrToDestFile(" -Tx86-coff");
	if (gbk_dbg_on == gbo_dbg) {
		WriteCStrToDestFile(" -Zi");
	}
	WriteCStrToDestFile(" -Ob1 -fp:precise -W1 -Gd -Ze");
}

LOCALPROC WritePLC_LINKFLAGS(void)
{
	if (gbk_dbg_on == gbo_dbg) {
		WriteCStrToDestFile(" -debug -debugtype:cv");
	}
	WriteCStrToDestFile(" -subsystem:windows -machine:x86");
}

LOCALPROC WritePLCProjectFile(void)
{
	WriteDestFileLn("# ");
	WriteDestFileLn(
		"# PROJECT FILE generated by \"Pelles C for Windows,"
		" version 6.00\".");
	WriteDestFileLn("# WARNING! DO NOT EDIT THIS FILE.");
	WriteDestFileLn("# ");
	WriteBlankLineToDestFile();
	WriteDestFileLn("POC_PROJECT_VERSION = 6.00#");
	WriteDestFileLn("POC_PROJECT_TYPE = 0#");
	WriteDestFileLn("POC_PROJECT_OUTPUTDIR = bld#");
	WriteDestFileLn("POC_PROJECT_RESULTDIR = .#");
	WriteDestFileLn("POC_PROJECT_ARGUMENTS = #");
	WriteDestFileLn("POC_PROJECT_WORKPATH = #");
	WriteDestFileLn("POC_PROJECT_EXECUTOR = #");
	WriteDestFileLn("CC = pocc.exe#");
	WriteDestFileLn("AS = poasm.exe#");
	WriteDestFileLn("RC = porc.exe#");
	WriteDestFileLn("LINK = polink.exe#");
	WriteDestFileLn("SIGN = posign.exe#");

	WriteBgnDestFileLn();
	WriteCStrToDestFile("CCFLAGS =");
	WritePLC_CCFLAGS();
	WriteCStrToDestFile(" #");
	WriteEndDestFileLn();

	WriteDestFileLn("ASFLAGS = -AIA32 -Gz #");
	WriteDestFileLn("RCFLAGS = #");

	WriteBgnDestFileLn();
	WriteCStrToDestFile("LINKFLAGS = ");
	WritePLC_LINKFLAGS();
	WriteCStrToDestFile(
		"  shell32.lib winmm.lib ole32.lib uuid.lib kernel32.lib"
		" user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib"
		" delayimp.lib#");
	WriteEndDestFileLn();

	WriteDestFileLn(
		"SIGNFLAGS = -timeurl:http://"
		"timestamp.verisign.com/scripts/timstamp.dll"
		" -location:CU -store:MY -errkill#");
	WriteDestFileLn(
		"INCLUDE = $(PellesCDir)\\Include\\Win;"
		"$(PellesCDir)\\Include#");
	WriteDestFileLn(
		"LIB = $(PellesCDir)\\Lib\\Win;$(PellesCDir)\\Lib#");
	WriteDestFileLn("WizCreator = Pelle Orinius#");
	WriteBlankLineToDestFile();
	WriteDestFileLn("# ");

	WriteBgnDestFileLn();
	WriteCStrToDestFile("# Build ");
	WriteAppNamePath();
	WriteCStrToDestFile(".");
	WriteEndDestFileLn();

	WriteDestFileLn("# ");

	WriteBgnDestFileLn();
	WriteAppNamePath();
	WriteCStrToDestFile(": \\");
	WriteEndDestFileLn();

	++DestFileIndent;
		DoAllSrcFilesStandardMakeObjects();

		WriteBgnDestFileLn();
		WriteMainRsrcObjPath();
		WriteEndDestFileLn();
	--DestFileIndent;

	WriteDestFileLn("\t$(LINK) $(LINKFLAGS) -out:\"$@\" $**");

	DoAllSrcFilesWithSetup(DoSrcFilePLCAddFile);

	WriteBlankLineToDestFile();
	WriteDestFileLn("# ");

	WriteBgnDestFileLn();
	WriteCStrToDestFile("# Build ");
	WriteMainRsrcObjName();
	WriteCStrToDestFile(".");
	WriteEndDestFileLn();

	WriteDestFileLn("# ");

	WriteBgnDestFileLn();
	WriteMainRsrcObjPath();
	WriteCStrToDestFile(": \\");
	WriteEndDestFileLn();

	++DestFileIndent;
		WriteBgnDestFileLn();
		WriteMainRsrcSrcPath();
		WriteEndDestFileLn();

		WriteDestFileLn("$(RC) $(RCFLAGS) \"$!\" -Fo\"$@\"");
	--DestFileIndent;

	WriteBlankLineToDestFile();
	WriteDestFileLn(".SILENT:");
	WriteBlankLineToDestFile();
	WriteDestFileLn(".EXCLUDEDFILES:");
}

LOCALPROC WritePLCSpecificFiles(void)
{
	WriteADstFile1("my_project_d",
		vStrAppAbbrev, ".ppj", "Project file",
		WritePLCProjectFile);
}

LOCALPROC WriteMainRsrcObjPLCbuild(void)
{
	WriteBgnDestFileLn();
	WriteCStrToDestFile("porc.exe ");
	WriteMainRsrcSrcPath();
	WriteCStrToDestFile(" -Fo\"");
	WriteMainRsrcObjPath();
	WriteCStrToDestFile("\"");
	WriteEndDestFileLn();
}

LOCALPROC WritePLCclMakeFile(void)
{
	WriteDestFileLn("# make file generated by gryphel build system");
	WriteBlankLineToDestFile();

	WriteBgnDestFileLn();
	WriteCStrToDestFile("mk_COptions =");
	WritePLC_CCFLAGS();
	WriteEndDestFileLn();

	WriteBlankLineToDestFile();
	WriteDestFileLn(".phony: TheDefaultOutput clean");

	WriteBlankLineToDestFile();
	WriteBgnDestFileLn();
	WriteCStrToDestFile("TheDefaultOutput:");
	WriteMakeDependFile(WriteAppNamePath);
	WriteEndDestFileLn();

	WriteBlankLineToDestFile();
	WriteBlankLineToDestFile();
	DoAllSrcFilesWithSetup(DoSrcFileMakeCompile);

	WriteBlankLineToDestFile();
	WriteDestFileLn("OBJFILES = \\");
	++DestFileIndent;
		DoAllSrcFilesStandardMakeObjects();
		WriteBlankLineToDestFile();
	--DestFileIndent;
	WriteBlankLineToDestFile();

	WriteBlankLineToDestFile();
	WriteMakeRule(WriteMainRsrcObjPath,
		WriteMainRsrcObjMSCdeps, WriteMainRsrcObjPLCbuild);

	WriteBlankLineToDestFile();
	WriteBgnDestFileLn();
	WriteAppNamePath();
	WriteCStrToDestFile(": $(OBJFILES) ");
	WriteMainRsrcObjPath();
	WriteEndDestFileLn();

	++DestFileIndent;

		WriteBgnDestFileLn();
		WriteCStrToDestFile("polink.exe -out:\"");
		WriteAppNamePath();
		WriteCStrToDestFile("\"");
		WritePLC_LINKFLAGS();
		WriteCStrToDestFile(" \\");
		WriteEndDestFileLn();

		WriteBgnDestFileLn();
		WriteCStrToDestFile("$(OBJFILES) ");
		WriteMainRsrcObjPath();
		WriteCStrToDestFile(" \\");
		WriteEndDestFileLn();

		WriteDestFileLn(
			"user32.lib winmm.lib ole32.lib uuid.lib comdlg32.lib"
			" shell32.lib gdi32.lib");

	--DestFileIndent;

	WriteBlankLineToDestFile();
	WriteDestFileLn("clean:");
	++DestFileIndent;
		DoAllSrcFilesStandardErase();
		WriteRmFile(WriteMainRsrcObjPath);
		WriteRmFile(WriteAppNamePath);
	--DestFileIndent;
}

LOCALPROC WritePLCclSpecificFiles(void)
{
	WriteADstFile1("my_project_d",
		"Makefile", "", "Make file",
		WritePLCclMakeFile);
}