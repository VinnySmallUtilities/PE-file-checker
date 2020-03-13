using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Threading;

namespace DllValidator
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }


        private void ALine(bool isSuppressWarnings = true)
        {
            if (!isSuppressWarnings || (isSuppressWarnings && !OnlyErrorsAndWarnings.Checked))
                sb.AppendLine("\\par");
        }

        void AL(string rtfString, string prePrefix = "", string prefix = " +  ")
        {
            if (!OnlyErrorsAndWarnings.Checked)
                sb.AppendLine(prePrefix + prefix + rtfString + "\\par");
        }

        void ALi(string rtfString, string prePrefix = "", string prefix = "    ")
        {
            AL(rtfString, prePrefix, prefix + " i  ");
        }

        void Alert(string rtfString, string prePrefix = "")
        {
            sb.AppendLine(prePrefix + "{\\b \\cf3  -  " + rtfString + "}\\par");
            errorCount++;
        }

        void ALW(string rtfString, string prePrefix = "")
        {
            sb.AppendLine(prePrefix + "{\\cf4  |  " + rtfString + "}\\par");
        }

        // string VRP = "Vinogradov Sergey Vasilievich";
        static readonly string VRPR = "hciveilisaVyegreSvodargoniV";
        static readonly string VRPS = "L_de]hWZelI[h][oLWi_b_[l_Y^";
        static          string VRPT;

        static Form1()
        {
            var sb  = new StringBuilder();
            var sb2 = new StringBuilder();
            for (int i = 0; i < VRPS.Length; i++)
                sb.Append((char) ((byte)VRPS[i] + 10));

            for (int i = VRPS.Length - 1; i >= 0; i--)
                sb2.Append(VRPR[i]);

            sb .Insert(10, " ");
            sb .Insert(17, " ");
            sb2.Insert(10, " ");
            sb2.Insert(17, " ");

            VRPT = sb.ToString();
            if (VRPT != sb2.ToString() || VRPT.Length != 29)
                VRPT = VRPT + " (?" +  sb2.ToString() + "?)";
        }

        SortedList<int, StringBuilder> sbs = new SortedList<int, StringBuilder>(Environment.ProcessorCount * 2);
        StringBuilder sb
        {
            get
            {
                lock (sbs)
                {
                    if (!sbs.ContainsKey(Thread.CurrentThread.ManagedThreadId))
                        sbs.Add(Thread.CurrentThread.ManagedThreadId, new StringBuilder());

                    return sbs[Thread.CurrentThread.ManagedThreadId];
                }
            }
        }

        SortedList<int, int> _errorCount = new SortedList<int, int>(Environment.ProcessorCount * 2);
        int errorCount
        {
            get
            {
                lock (_errorCount)
                {
                    if (!_errorCount.ContainsKey(Thread.CurrentThread.ManagedThreadId))
                        _errorCount.Add(Thread.CurrentThread.ManagedThreadId, 0);

                    return _errorCount[Thread.CurrentThread.ManagedThreadId];
                }
            }
            set
            {
                lock (_errorCount)
                {
                    if (!_errorCount.ContainsKey(Thread.CurrentThread.ManagedThreadId))
                        _errorCount.Add(Thread.CurrentThread.ManagedThreadId, 0);

                    _errorCount[Thread.CurrentThread.ManagedThreadId] = value;
                }
            }
        }

        StringBuilder global_sb = new StringBuilder();
        volatile int filesCheckedCount = 0;
        List<string> filesToChecked = new List<string>();
        object mainSync = new object();
        volatile int syncCounter = 0;
        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                return;

            button2.Enabled = true;
            result.Clear();
            global_sb.Clear();
            ext.Clear();
            filesToChecked.Clear();
            progressBar1.Value = 0;
            filesCheckedCount  = 0;

            Application.DoEvents();

            global_sb.AppendLine("{\\rtf1 \\ansicpg" + Encoding.Default.CodePage.ToString("D4"));
            global_sb.AppendLine("{\\colortbl;\\red0\\green0\\blue0;\\red255\\green255\\blue255;\\red160\\green0\\blue0;\\red128\\green80\\blue0;\\red0\\green128\\blue0;\\red80\\green80\\blue80;\\red0\\green0\\blue128;}");
            global_sb.AppendLine("{\\cf6");
            global_sb.AppendLine("PE-validator by " + VRPT + "\\par");
            global_sb.AppendLine("see PE file specification in http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx and http://msdn.microsoft.com/en-us/library/ms809762.aspx");
            global_sb.AppendLine("\\par addresses prefix in program output: fp - file pointer, rva - relative image address when load in memory, va - virtual address with image base address");
            global_sb.AppendLine("\\par + - correct file fact, - - incorrect file fact, | - warning, is partially correct or is not standard, i - information");
            global_sb.AppendLine("}");

            terminate = false;
            if (!AllDirectoriesFiles.Checked)
            {
                filesToChecked.AddRange(openFileDialog1.FileNames);
            }
            else
            {
                // var FileNames = Directory.EnumerateFiles(Path.GetDirectoryName(openFileDialog1.FileName));

                var wi  = WindowsIdentity.GetCurrent().User.ToString().ToLowerInvariant();
                var wig = WindowsIdentity.GetCurrent().Groups;
                var Dir = new DirectoryInfo(Path.GetDirectoryName(openFileDialog1.FileName));

                DirectoryAllChecking(Dir, wi, wig);
            }

            progressBar1.Maximum = filesToChecked.Count + 2;
            Application.DoEvents();

            foreach (var FileName in filesToChecked)
            {
                if (onlyPE.Checked && !isPE_Extension(FileName))
                {
                    lock (mainSync)
                    {
                        filesCheckedCount++;
                    }
                    continue;
                }

                lock (mainSync)
                {
                    syncCounter++;
                }

                ThreadPool.QueueUserWorkItem
                (
                    delegate
                    {
                        try
                        {
                            checkSingleFileWithReadCheck(FileName);
                        }
                        finally
                        {
                            lock (mainSync)
                            {
                                syncCounter--;
                                Monitor.Pulse(mainSync);
                            }
                        }
                    }
                );

                while (syncCounter > Environment.ProcessorCount)
                lock (mainSync)
                {
                    Monitor.Wait(mainSync);

                    progressBar1.Value = filesCheckedCount + 1;
                    progressBar1.Value = filesCheckedCount;

                    progressBar1.Refresh();
                    Application.DoEvents();
                }

                lock (mainSync)
                {
                    progressBar1.Value = filesCheckedCount + 1;
                    progressBar1.Value = filesCheckedCount;
                }

                progressBar1.Refresh();
                Application.DoEvents();

                if (terminate)
                {
                    break;
                }
            }

            while (syncCounter > 0)
            lock (mainSync)
            {
                Monitor.Wait(mainSync, 500);

                progressBar1.Value = filesCheckedCount + 1;
                progressBar1.Value = filesCheckedCount;

                progressBar1.Refresh();
                Application.DoEvents();
            }

            progressBar1.Value = filesCheckedCount + 1;
            progressBar1.Value = filesCheckedCount;
            progressBar1.Refresh();
            Application.DoEvents();

            if (terminate)
            {
                global_sb.AppendLine("\\par \\par cf3 checking terminated \\par \\par");
            }

            progressBar1.Value = filesCheckedCount + 2;
            progressBar1.Value = filesCheckedCount + 1;
            progressBar1.Refresh();
            Application.DoEvents();

            if (AllDirectoriesFiles.Checked || openFileDialog1.FileNames.Length > 1)
            {
                global_sb.AppendLine("\\par\\par File checked: " + filesCheckedCount);
                global_sb.AppendLine("\\par\\par File with extensions has been checked successed: ");

                foreach (var extension in ext)
                {
                    global_sb.Append(extension.Key + " ");
                }
                global_sb.AppendLine("\\par\\par Last scan result in 'lastCheck.rtf' in DLLValidator directory");
            }

            button2.Enabled = false;

            global_sb.AppendLine("\\par}");

            string resultStr = global_sb.ToString();

            File.WriteAllText("lastCheck.rtf", resultStr);

            progressBar1.Value = filesCheckedCount + 2;
            progressBar1.Refresh();
            Application.DoEvents();

            if (terminate && resultStr.Length > 64 * 1024)
                result.Text = "Check process have been terminated. Last scan result is large and have been saved in 'lastCheck.rtf' in DLLValidator directory";
            else
                result.Rtf = resultStr;

            progressBar1.Value = 0;
        }

        private static bool isPE_Extension(string FileName)
        {
            return ".acm.amd64.ax.com.cpl.css_x86.dat.dll.dll_amd64.dll_fxcop.dll_gac.dll_x86.dll1.dll2.dll5.dll6.drv.ds.efi.exe.exe_0001.exe_amd64.exe_x86.exe1.flt.flt1.html_x86.iec.ime.lrc.msstyles.mui.ocx.olb.rll.rs.scr.sys.tlb.tmp.tsp.x86"
                                .Contains(Path.GetExtension(FileName).ToLowerInvariant());
        }

        private void DirectoryAllChecking(DirectoryInfo Dir, string wi, IdentityReferenceCollection wig)
        {
            if (terminate)
            {
                return;
            }

            var DirNames  = Dir.GetDirectories();
            var FileNames = Dir.GetFiles();
            foreach (var file in FileNames)
            {
                if (terminate)
                {
                    return;
                }

                if (onlyPE.Checked && !isPE_Extension(file.FullName))
                    continue;

                filesToChecked.Add(file.FullName);
            }

            foreach (var dir in DirNames)
            {
                if (terminate)
                {
                    return;
                }

                try
                {
                    var di  = new DirectoryInfo(dir.FullName).GetAccessControl();
                    var dss = di.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    var allowed = 0;
                    for (int i = 0; i < dss.Count; i++)
                    {
                        var s = dss[i] as FileSystemAccessRule;
                        if (s == null)
                            continue;

                        if (wi != s.IdentityReference.Value.ToLowerInvariant() && !wig.Contains(s.IdentityReference))
                            continue;

                        if (s.FileSystemRights == FileSystemRights.ListDirectory && s.AccessControlType == AccessControlType.Allow)
                        {
                            allowed = 1;
                            break;
                        }
                        else
                        if (s.FileSystemRights == FileSystemRights.ListDirectory && s.AccessControlType == AccessControlType.Deny)
                        {
                            allowed = -1;
                            break;
                        }
                    }

                    if (allowed < 0)
                        global_sb.AppendLine("\\par directory " + dir.FullName.Replace("\\", "\\\\") + " skipped as access not allowed\\par");
                    else
                        DirectoryAllChecking(dir, wi, wig);
                }
                catch (Exception ex)
                {
                    global_sb.AppendLine("\\par directory " + dir.FullName.Replace("\\", "\\\\") + " skipped as raise error on checking " + ex.Message.Replace("\\", "\\\\") + "\\par");
                }
            }
        }

        SortedList<string, int> ext = new SortedList<string,int>(16);
        private void checkSingleFileWithReadCheck(string FileName)
        {
            try
            {
                var hFile = CreateFile(FileName, 0x80000000, 0x00000001, 0, 3, 0x80, 0);
                CloseHandle(hFile);

                if (hFile != 0)
                {
                    checkPEFile(FileName);
                }
                else
                    sb.AppendLine("file " + FileName + " skipped with read system error " + GetLastError());
            }
            catch (Exception ex)
            {
                sb.AppendLine("file " + FileName + " raise error on checking " + ex.Message);
            }

            lock (mainSync)
                filesCheckedCount++;
        }


        // ---------------------------------------------------------------------------------------------------------------------------------------------------------
        // ----------------------------------------------------- File checking -------------------------------------------------------------------------------------
        // ---------------------------------------------------------------------------------------------------------------------------------------------------------


        private bool checkPEFile(string FileName)
        {
            sb.Clear();

            baseAddresses.Clear();
            baseAddressesOfDirectory.Clear();
            errorCount = 0;

            vars.DllName = null;

            vars.rvaExportDirectory  = 0;
            vars.rvaImportDirectory  = 0;
            vars.rvaResDirectory     = 0;
            vars.rvaCLRDirectory     = 0;
            vars.rvaRelocationDirectory  = 0;

            vars.rvaExportDirectoryS = 0;
            vars.rvaImportDirectoryS = 0;
            vars.rvaResDirectoryS    = 0;
            vars.rvaCLRDirectoryS    = 0;
            vars.rvaRelocationDirectoryS  = 0;
            vars.SizeOfHeadersAdd    = 0;

            vars.isDelayedImportDeclared = false;

            var fileContent = File.ReadAllBytes(FileName);

            sb.AppendLine("\\par \\par checking file " + FileName.Replace("\\", "\\\\"));
            sb.AppendLine("\\par {RESULT_CHECKING}\\par");
            sb.AppendLine("\\par \\par");

            try
            {

            if (fileContent.LongLength < 1024)
            {
                ALW(" -  File length < 1024 bytes");
                goto EndOfValidate;
            }
            AL("File length >= 1024 bytes. " + this.A16(fileContent.LongLength));

            if (fileContent[0] != (byte)'M' || fileContent[1] != (byte)'Z')
            {
                Alert("MZ signature not found");
                goto EndOfValidate;
            }
            AL("MZ signature found (do not check wether correct MZ-file)");

            ushort a;
            ByteToShort(out a, fileContent, 0x18);
            if (a != 0x40)
                ALW("fp 0x40 do have not in fp 0x18 in MZ stub (have not in PE file specification)");

            AL("fp 0x40 do have in fp 0x18 in MZ stub (have not in PE file specification)");

            long fp = (long)GetInt(fileContent, 0x3c);

            if (fp + 3 >= fileContent.LongLength)
            {
                Alert("fp 0x3c > file length - 3");
                goto EndOfValidate;
            }
            AL("fp 0x3c contains address for PE signature: " + A16S(fp));

            vars.addressOfPESignature = fp;
            if (fileContent[fp] != (byte)'P' || fileContent[fp + 1] != (byte)'E' || fileContent[fp + 2] != 0 || fileContent[fp + 3] != 0)
            {
                Alert("PE signature not found");
                goto EndOfValidate;
            }
            AL("PE signature found");

            fp += 4;
            var machine = GetShort(fileContent, fp);
            if (machine != 0x8664 && machine != 0x14c)
                Alert("Unknown machine (may be correct, if not x64 or x86): " + A16(machine));
            ALi("machine " + A16(machine) + " (0x8664 - AMD64, 0x14c - Intel x86 and compatible, 0x200 - Intel Itanium)");
            fp += 2;

            vars.sectionCount = GetShort(fileContent, fp); // NumberOfSections
            ALi("section count " + A16(vars.sectionCount));
            fp += 2;

            var fileTimeStamp = GetInt(fileContent, fp);
            ALi("file creation time " + printDateTimeString(fileTimeStamp));
            fp += 4;

            fp += 8;

            vars.sizeOfOptionalHeader = GetShort(fileContent, fp);
            ALi("optional header size " + A16(vars.sizeOfOptionalHeader));
            fp += 2;

            vars.fileCharacteristics = GetShort(fileContent, fp);
            printFileCharacteristics(vars.fileCharacteristics);
            fp += 2;

            vars.optionalHeaderOffset = (uint) fp;
            var PE_Magic = GetShort(fileContent, fp);
            if (PE_Magic == 0x020b)
            {
                vars.PE32Format = false;
                AL("PE Magic number of file in Optional Header is correct. {\\b \\cf7 PE32+ (64 bit) format file. " + (vars.isDLL ? " Is dll" : "Is exe") + "}");
            }
            else
            if (PE_Magic == 0x010b)
            {
                vars.PE32Format = true;
                AL("PE Magic number of file in Optional Header is correct. {\\b \\cf7 PE32 (32 bit) format file. " + (vars.isDLL ? " Is dll" : "Is exe") + "}");
            }
            else
            {
                Alert("PE Magic number of file in Optional Header is incorrect: " + PE_Magic);
                goto EndOfValidate;
            }
            fp += 2;

            // Alert(A16(fp - vars.addressOfPESignature));
            vars.SizeOfImage = ByteToSizedInteger(fileContent, vars.addressOfPESignature + 0x50, 4);

            if (vars.PE32Format)
            {
                if (vars.sizeOfOptionalHeader < 0x60)
                {
                    Alert("Optional header size is incorrect (very small)");
                    goto EndOfValidate;
                }
            }
            else
            if (vars.sizeOfOptionalHeader < 0x70)
            {
                Alert("Optional header size is incorrect (very small)");
                goto EndOfValidate;
            }
            AL("Optional header size is not very small (minimum 0x60 for PE32 or 0x70 for PE32+)");

            var majLinkerVersion = fileContent[fp++];
            var minLinkerVersion = fileContent[fp++];
            ALi("Major and minor linker version " + majLinkerVersion + "." + minLinkerVersion);

            vars.sizeOfCode = GetInt(fileContent, fp);
            fp += 4;
            ALi("size of code " + printSize(vars.sizeOfCode));
            if (vars.sizeOfCode <= 0 && !vars.isDLL || vars.sizeOfCode > vars.SizeOfImage)
                Alert("size of code <= 0 || > file length: " + vars.sizeOfCode + " of " + vars.SizeOfImage);

            vars.sizeOfIData = GetInt(fileContent, fp);
            fp += 4;
            ALi("size of initialized data " + printSize(vars.sizeOfIData));

            vars.sizeOfUData = GetInt(fileContent, fp);
            fp += 4;
            ALi("size of uninitialized data " + printSize(vars.sizeOfUData));


            var aoep = A16S(GetInt(fileContent, fp), -1, AddressType.rva);
            vars.AddressOfEntryPoint = (uint)aoep.a;
            fp += 4;
            ALi("Address of entry point " + aoep.sa);
            if (vars.AddressOfEntryPoint > vars.SizeOfImage)
                Alert("AddressOfEntryPoint > SizeOfImage: " + vars.AddressOfEntryPoint + " of " + vars.SizeOfImage);

            if (vars.AddressOfEntryPoint == 0 && !vars.isDLL)
                Alert("Address of entry point is null, but file is not DLL. " + A16(vars.AddressOfEntryPoint));
            else
                AL("Address of entry point is not null and/or file is DLL. " + A16(vars.AddressOfEntryPoint));

            var boc = A16S(GetInt(fileContent, fp), -1, AddressType.rva);
            vars.BaseOfCode = (uint)boc.a;
            fp += 4;
            ALi("Base of code " + boc.sa);
            if (vars.BaseOfCode <= 0 && !vars.isDLL || vars.BaseOfCode > vars.SizeOfImage)
                Alert("BaseOfCode <= 0 || > SizeOfImage: " + vars.BaseOfCode + " of " + vars.SizeOfImage);

            if (vars.PE32Format)
            {
                var bod = A16S(GetInt(fileContent, fp), -1, AddressType.rva);
                vars.BaseOfData = (uint)bod.a;
                fp += 4;
                ALi("Base of data " + bod.sa);

                if (vars.BaseOfData <= 0 && !vars.isDLL || vars.BaseOfData > vars.SizeOfImage)
                    Alert("BaseOfData <= 0 || > SizeOfImage: " + vars.BaseOfData + " of " + vars.SizeOfImage);
            }

            var size4 = vars.PE32Format ? 4 : 8;
            vars.ImageBase = ByteToSizedInteger(fileContent, fp, size4); fp += size4;
            if (vars.ImageBase == 0x10000000 && vars.isDLL)
                AL("Program have standard image base for DLL " + A16(vars.ImageBase));
            else
            if (vars.ImageBase == 0x00010000 && !vars.isDLL)
                AL("Program have standard image base for Windows CE exe " + A16(vars.ImageBase));
            else
            if (vars.ImageBase == 0x00400000 && !vars.isDLL)
                AL("Program have standard image base for exe Windows NT/98 and later " + A16(vars.ImageBase));
            else
            if (vars.ImageBase % (1024 * 64) == 0)
                ALW("Image base is not standard address " + A16(vars.ImageBase));
            else
                Alert("Image base is incorrect, alignment 64k violate: " + A16(vars.ImageBase));


            vars.SectionAlignment = (uint) ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            vars.FileAlignment    = (uint) ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            if (vars.SectionAlignment >= vars.FileAlignment)
                AL("Section alignment >= FileAlignment: " + A16(vars.SectionAlignment) + " >= " + A16(vars.FileAlignment));
            else
                Alert("Section alignment < FileAlignment: " + A16(vars.SectionAlignment) + " >= " + A16(vars.FileAlignment));

            if (vars.SectionAlignment % 512 == 0)
                AL("Section alignment % 512 == 0");
            else
                Alert("Section alignment % 512 != 0");

            if (vars.FileAlignment % 512 == 0)
                AL("File alignment % 512 == 0");
            else
                Alert("File alignment % 512 != 0");

            if (vars.FileAlignment >= 512)
                AL("FileAlignment >= 512");
            else
                Alert("FileAlignment < 512");

            if (vars.FileAlignment <= 64 * 1024)
                AL("FileAlignment <= 64 kb");
            else
                Alert("FileAlignment > 64 kb");

            if (vars.SectionAlignment < 4096 && vars.FileAlignment != vars.SectionAlignment)
                ALW("MAY BE ERROR: If section alignment < page size, then FileAlignment == SectionAlignment");
            else
                AL("SectionAlignment >= page size or FileAlignment == SectionAlignment");

            var majver = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            var minver = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            ALi("Version of required operating system " + majver + "." + minver + " (6.0 - Windows Vista, 6.1 - Windows 7)");

            majver = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            minver = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            ALi("Version of program " + majver + "." + minver);

            majver = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            minver = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            ALi("Version of subsystem " + majver + "." + minver + " (NT version)");


            var Win32VersionValue = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            if (Win32VersionValue != 0)
                Alert("Win32 version reserved and must be null - not satisfied: " + Win32VersionValue);
            else
                AL("Win32 version reserved and must be null");
            /*Alert(A16(fp - vars.addressOfPESignature));
            vars.SizeOfImage = ByteToSizedInteger(fileContent, fp, 4); fp += 4;*/
            fp += 4;
            if (vars.SizeOfImage == 0 || vars.SizeOfImage % vars.SectionAlignment != 0)
                Alert("Size of image field does not multiple of section alignment: " + A16(vars.SizeOfImage) + " (SizeOfImage == 0 || SizeOfImage % SectionAlignment != 0)");
            else
                AL("Size of image field does multiple of section alignment (" + A16(vars.SizeOfImage) + ")");

            vars.SizeOfHeaders = (uint) ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            if (vars.SizeOfHeaders == 0 || vars.SizeOfHeaders % vars.FileAlignment != 0)
                Alert("Size of headers field does not multiple of file alignment: " + A16(vars.SizeOfHeaders) + " (SizeOfHeaders == 0 || SizeOfHeaders % FileAlignment != 0)");
            else
                AL("Size of headers field does multiple of file alignment (" + A16(vars.SizeOfHeaders) + ")");

            vars.CheckSum = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            if (vars.CheckSum == 0)
                ALW("Check sum of file has not been calculated");
            else
            {
                var t = CalculateCRC32(FileName, fileContent.Length);
                if (t == -1)
                    ALW("Unable to verify the checksum");
                else
                    if (t == (UInt32) vars.CheckSum)
                        AL("File check sum correct: " + A16(vars.CheckSum));
                    else
                        Alert("File check sum incorrect: calculated " + A16(t) + ", in file " + A16(vars.CheckSum));
            }

            var subSystem            = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            var DllCharacteristics   = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            var SizeOfStackReserve   = ByteToSizedInteger(fileContent, fp, size4); fp += size4;
            var SizeOfStackCommit    = ByteToSizedInteger(fileContent, fp, size4); fp += size4;
            var SizeOfHeapReserve    = ByteToSizedInteger(fileContent, fp, size4); fp += size4;
            var SizeOfHeapCommit     = ByteToSizedInteger(fileContent, fp, size4); fp += size4;
            var LoaderFlags          = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            vars.NumberOfRvaAndSizes = ByteToSizedInteger(fileContent, fp, 4); fp += 4;

            string[] subsystemsNames = {"unknown", "driver", "GUI", "console", "ERROR", "ERROR", "ERROR", "POSIX console", "ERROR", "Windows CE", "EFI application", "An EFI driver with boot services", "An EFI driver with run-time services", "An EFI ROM image", "XBOX"};

            if (subSystem > 14 || (subSystem >= 4 && subSystem < 7) || subSystem == 8)
                Alert("Windows Subsystem number incorrect: " + subSystem + " (" + ((int) subSystem < subsystemsNames.Length ? subsystemsNames[subSystem] : "ERROR") + ")");
            else
                if (subSystem == 1 || subSystem == 2 || subSystem == 3 || subSystem == 9)
                    AL("Windows Subsystem number correct: " + subSystem + " (" + subsystemsNames[subSystem] + ")");
                else
                    ALW("Windows Subsystem number correct, but not describes driver, GUI or console: " + subSystem + " (" + subsystemsNames[subSystem] + ")");

            if (subSystem == 1 && vars.CheckSum == 0)
                Alert("Sheck sum of driver image must be calculated");
            else
                if (subSystem == 1)
                    AL("Sheck sum of driver image has been calculated");

            if (vars.isDLL || DllCharacteristics != 0)
                printDLLCharacteristics((ushort)DllCharacteristics);

            if (!vars.isDLL && DllCharacteristics != 0)
                ALW("DLL characteristics flags setted, but file is not DLL");
            else if (!vars.isDLL)
                AL("DLL characteristics flags all in reset state");

            if (SizeOfStackCommit > SizeOfStackReserve)
                Alert("Size of stack commit must be <= size of stack reserve: " + A16(SizeOfStackCommit) + " > " + A16(SizeOfStackReserve));
            else
                AL("Size of stack commit is <= size of stack reserve: " + A16(SizeOfStackCommit) + " <= " + A16(SizeOfStackReserve));

            if (SizeOfHeapCommit > SizeOfHeapReserve)
                Alert("Size of heap commit must be <= size of heap reserve: " + A16(SizeOfHeapCommit) + " > " + A16(SizeOfHeapReserve));
            else
                AL("Size of heap commit is <= size of heap reserve: " + A16(SizeOfHeapCommit) + " <= " + A16(SizeOfHeapReserve));

            if (LoaderFlags != 0)
                Alert("Loader flags must be null, but " + A16(LoaderFlags));
            else
                AL("Loader flags is be null");

            if (vars.NumberOfRvaAndSizes > 16)
                Alert("NumberOfRvaAndSizes (directory entries) must be 16 or less: " + A16(vars.NumberOfRvaAndSizes));
            else
                AL("NumberOfRvaAndSizes (directory entries) is 16 or less: " + A16(vars.NumberOfRvaAndSizes));

            if (vars.NumberOfRvaAndSizes == 0)
                ALW("0 directory entries - very simple file. MAY BE ERROR");
            else
            {
                ALine();
                for (int i = 0; i < (int) vars.NumberOfRvaAndSizes; i++)
                {
                    ALine();
                    printDirectoryEntries(fileContent, ref fp, i);
                }
                ALine();ALine();
            }
                /* Всё-таки непонятно, что это за IAT
            if (vars.rvaImportDirectory > 0)
            {
                if (vars.rvaIATDirectory == 0)
                    Alert("IAT directory enrty not found, but import declared");
                else
                    AL("Import declared and IAT directory enrty found");
            }
                */
            // --------------------
            // Здесь закончился optional header
            // Заголовки PE-файла заканчиваются после таблицы секций

            uint sectionTableSize  = 40U * vars.sectionCount;
            uint endOfHeadersNA    = (uint) (fp + sectionTableSize);
            uint endOfHeadersAlign = endOfHeadersNA;
            vars.endOfHeadersAD    = vars.SizeOfHeadersAdd;
            uint endOfOptHeaders   = (uint) fp;

            vars.headerFactEnd = endOfHeadersNA;

            if (endOfHeadersAlign % vars.FileAlignment != 0)
            {
                endOfHeadersAlign = endOfHeadersNA + vars.FileAlignment - (endOfHeadersNA % vars.FileAlignment);
            }

            if (vars.endOfHeadersAD % vars.FileAlignment != 0)
            {
                vars.endOfHeadersAD = vars.endOfHeadersAD + vars.FileAlignment - (vars.endOfHeadersAD % vars.FileAlignment);
            }

            if (vars.SizeOfHeaders != endOfHeadersAlign)
            {
                if (vars.SizeOfHeaders != vars.endOfHeadersAD)
                    Alert("Size of headers is incorrect: writed in file " + A16(vars.SizeOfHeaders) + ", calculated with align " + A16(endOfHeadersAlign) + ", calculated without align " + A16(endOfHeadersNA) + ", file alignment " + A16(vars.FileAlignment) + ", with not-header info " + A16(vars.endOfHeadersAD));
                else
                    ALW("Size of header may be correct, but header section contain not header information: size of headers, writed in file " + A16(vars.SizeOfHeaders) + ", calculated with align " + A16(endOfHeadersAlign) + ", calculated without align " + A16(endOfHeadersNA) + ", file alignment " + A16(vars.FileAlignment) + ", with not header info " + A16(vars.endOfHeadersAD));
            }
            else
                AL("Size of headers is correct with file alignmet: " + A16(vars.SizeOfHeaders) + ", file alignment " + A16(vars.FileAlignment) + ", unalignment size " + A16(endOfHeadersNA));

            if (endOfOptHeaders != vars.optionalHeaderOffset + vars.sizeOfOptionalHeader)
                Alert("Size of optional header in PE header is incorrect: calculated " + A16(endOfOptHeaders - vars.optionalHeaderOffset) + ", in file by sizeOfOptionalHeader and opt. header offset " + A16(vars.sizeOfOptionalHeader));
            else
                AL("Size of optional header in PE header is correct. End of headers in fp " + A16(endOfOptHeaders) + ", size of opt. headers " + A16(endOfOptHeaders - vars.optionalHeaderOffset));


            var headerSection = new section(null);
            headerSection.rawDataFilePointer = 0;
            headerSection.rva           = 0;
            headerSection.va            = vars.ImageBase;
            headerSection.VirtualSize   = vars.endOfHeadersAD + endOfHeadersAlign;
            headerSection.sizeOfRawData = vars.endOfHeadersAD + endOfHeadersAlign;
            baseAddresses.Add(-1, headerSection);

            vars.ImageContainsExecutableSection = false;
            for (int i = 0; i < vars.sectionCount; i++)
            {
                var section = printSection(fileContent, ref fp, i);
                if (section != null && (section.CanBeExecute || section.ContainsExecutable))
                    vars.ImageContainsExecutableSection = true;
            }

                
            SortedList<ulong, ulong> sortedRVA = new SortedList<ulong, ulong>();
            SortedList<ulong, ulong> sortedFP  = new SortedList<ulong, ulong>();
            bool errorFlag = false;

            for (int i = 0; i < baseAddresses.Count - 2; i++)   // номера секций идут по порядку, но есть секция -1 (кажется, это я о заголовке)
            {
                if (baseAddresses[i+1].rva < baseAddresses[i+0].rva)
                    Alert("Sections with incorrect sequence: " + baseAddresses[i+0].sectionName + " -> " + baseAddresses[i+1].sectionName + " " + A16(baseAddresses[i+0].rva) + "->" + A16(baseAddresses[i+1].rva));
            }

            for (int i = -1; i < baseAddresses.Count - 1; i++)   // номера секций идут по порядку, но есть секция -1
            {
                var cur1 = baseAddresses[i];
                for (int j = i + 1; j < baseAddresses.Count - 1; j++)
                {
                    var  cur2 = baseAddresses[j];
                    ulong c1b = cur1.rva, c1e = Math.Max(cur1.rva + cur1.sizeOfRawData, cur1.rva + cur1.VirtualSize);
                    ulong c2b = cur2.rva, c2e = Math.Max(cur2.rva + cur2.sizeOfRawData, cur2.rva + cur2.VirtualSize);

                    if (c1b <= c2b)
                    {
                        if (c1e > c2b || c1b == c2b)
                        {
                            errorFlag = true;
                            Alert("Section " + i + " " + cur1.sectionName + " and section " + j + " " + cur2.sectionName + " intersect. " + cur1.rva + "->" + cur1.sizeOfRawData + " " + cur2.rva + "->" + cur2.sizeOfRawData);
                        }
                    }
                    else
                    {
                        if (c2e > c1b)
                        {
                            errorFlag = true;
                            Alert("Section " + i + " " + cur1.sectionName + " and section " + j + " " + cur2.sectionName + " intersect. " + cur1.rva + "->" + cur1.sizeOfRawData + " " + cur2.rva + "->" + cur2.sizeOfRawData);
                        }
                    }
                }

                if (!sortedRVA.ContainsKey(cur1.rva))
                    sortedRVA.Add(cur1.rva, AlignmentSA(cur1.rva + cur1.VirtualSize, vars.SectionAlignment));
                else
                    Alert("Section " + cur1.sectionName + " (relative address) equals with other section");

                if (!sortedFP.ContainsKey(cur1.filePointer))
                    sortedFP.Add(cur1.filePointer, AlignmentSA(cur1.filePointer + cur1.sizeOfRawData, vars.FileAlignment));
                else
                    Alert("Section " + cur1.sectionName + " (filePointer) equals with other section");
            }
            if (!errorFlag)
                AL("Section do not intersect");

           bool unusedPagesFound   = false;
           bool unusedSectorsFound = false;
           for (int i = 0; i < sortedRVA.Count - 1; i++)
           {
               if (sortedRVA.Values[i] - sortedRVA.Keys[i + 1] != 0)
               {
                    ALW("Unused pages found at addresses " + A16(sortedRVA.Values[i]) + " " + A16(sortedRVA.Keys[i + 1]));
                   unusedPagesFound = true;
               }
           }
           // Например, в AIMP так бывает, что sortedRVA и sortedFP содержат разное количество значений
           for (int i = 0; i < sortedFP.Count - 1; i++)
           {
               if (sortedFP.Values[i] - sortedFP.Keys[i + 1] != 0)
               {
                    ALW("Unused sectors found at addresses " + A16(sortedFP.Values[i]) + " " + A16(sortedRVA.Keys[i + 1]));
                   unusedSectorsFound = true;
               }
           }

           if (!unusedPagesFound)
               AL("Unused pages (in image) not found");
            if (!unusedSectorsFound)
               AL("Unused sectors (in file) not found");


            if (vars.ImageContainsExecutableSection)
            {
                if (
                    ( (DllCharacteristics & 0x0040) > 1 || (vars.fileCharacteristics & 1) == 0 )
                   && (vars.rvaRelocationDirectory == 0 || vars.rvaRelocationDirectoryS == 0)
                    )
                    ALW("File or dll characteristics declare to relocation information contains, but base relocation table is not found");
                else
                    AL("File or dll characteristics not declare to relocation information contains or base relocation table is found");
            }

            byte[] image = getImage(fileContent);
            checkImport(fileContent);
            checkExport(image, FileName);

            }
            catch (Exception e)
            {
                Alert("In checking process raise error " + e.Message.Replace("\\", "\\\\"));
            }


        EndOfValidate:

            if (errorCount > 0)
            {
                sb.Replace("{RESULT_CHECKING}", "\\par {\\b \\cf3 Incorrect file, " + errorCount + " errors found}");
                lock (global_sb)
                    global_sb.Append(sb.ToString());

                return false;
            }
            else
            {
                var str = Path.GetExtension(FileName).ToLowerInvariant();
                lock (ext)
                {
                    if (str.Length < 12 && !ext.ContainsKey(str))
                        ext.Add(Path.GetExtension(FileName).ToLowerInvariant(), 0);
                }

                sb.Replace("{RESULT_CHECKING}", "\\par {\\b \\cf5 File is correct}");

                lock (global_sb)
                    global_sb.Append(sb.ToString());

                return true;
            }
        }

        private ulong AlignmentSA(ulong address, uint alignment)
        {
            if (address % alignment == 0)
                return address;

            return (address + alignment - (address % alignment));
        }

        private byte[] getImage(byte[] fileContent)
        {
            var result = new byte[vars.SizeOfImage];

            CopyTo(fileContent, result, 0, vars.endOfHeadersAD);

            for (int i = 0; i < baseAddresses.Count - 1; i++) // Секции в baseAddresses начинаются с -1-ой
            {
                section  s = baseAddresses[i];
                var maxLen = Math.Max(s.sizeOfRawData, s.VirtualSize);
                var minLen = Math.Min(s.sizeOfRawData, s.VirtualSize);


                if (s.rawDataFilePointer + minLen > (ulong) fileContent.LongLength)
                {
                    Alert(String.Format("Checking for section {0} {1} abort, end of data section declared out of file place {2} > {3}", i, s.sectionName, A16(s.rva + minLen), A16(fileContent.LongLength)));
                    continue;
                }
                CopyTo(fileContent, result, (long) s.rva, (long) minLen, (long) s.rawDataFilePointer);

                if (s.VirtualSize < s.sizeOfRawData)
                {
                    if (s.rawDataFilePointer + s.sizeOfRawData > (ulong) fileContent.LongLength)
                        ALW(String.Format("File must be alignet to File alignment, but section {0} {1} padding out of file place ({2} > {3})", i, s.sectionName, A16(s.rawDataFilePointer + s.sizeOfRawData), A16(fileContent.LongLength)));
                    else
                    {
                        bool isZeroPadded = true;
                        for (ulong j = s.rawDataFilePointer + minLen; j < s.rawDataFilePointer + s.sizeOfRawData; j++)
                            if (fileContent[j] != 0)
                                isZeroPadded = false;

                        if (isZeroPadded)
                            AL(String.Format("Section {0} {1}\tis well zero padded (check for only VirtualSize < sizeOfRawData sections)", i, s.sectionName));
                        else
                        if (s.ResourceDirectoryContains && (long) (maxLen - minLen) >= "PADDINGXX".Length)
                        {
                            var paddings = new byte[maxLen-minLen];
                            CopyTo(fileContent, paddings, 0, paddings.Length, (long) s.sizeOfRawData + (long) minLen);
                            var strpaddings = Encoding.UTF8.GetString(paddings);
                            var rg = new System.Text.RegularExpressions.Regex("^(PADDINGXX){1,*}P?A?D?D?I?N?G?X?$");

                            if (rg.IsMatch(strpaddings))
                                ALW(String.Format("Section {0} {1}\tis not zero padded. Non standard padding detected by resource padding 'PADDINGXX'", i, s.sectionName));
                            else
                            {
                                string strPaddingsTrunc = BitConverter.ToString(paddings);
                                if (strPaddingsTrunc.Length > 47)
                                    strPaddingsTrunc = strPaddingsTrunc.Substring(0, 47);

                                Alert(String.Format("Section {0} {1} have virtual size {2} < size of raw data {3} and must be zero padded, but not is it and resource padding 'PADDINGXX' not detected too; in address {4} bytes (max 16 bytes in hex): {5}", i, s.sectionName, A16(s.VirtualSize), A16(s.sizeOfRawData), A16(s.rawDataFilePointer + minLen),  strPaddingsTrunc));
                            }
                        }
                        else
                        {
                            var paddings = new byte[maxLen-minLen];
                            CopyTo(fileContent, paddings, 0, paddings.Length, (long) s.sizeOfRawData + (long) minLen);
                            string strPaddingsTrunc = BitConverter.ToString(paddings);
                                if (strPaddingsTrunc.Length > 47)
                                    strPaddingsTrunc = strPaddingsTrunc.Substring(0, 47);

                            Alert(String.Format("Section {0} {1} have virtual size {2} < size of raw data {3} and must be zero padded, but not is it; in address {4} bytes (max 16 bytes in hex): {5}", i, s.sectionName, A16(s.VirtualSize), A16(s.sizeOfRawData), A16(s.rawDataFilePointer + minLen),  strPaddingsTrunc));
                        }
                    }
                }
                else
                if (s.VirtualSize > s.sizeOfRawData)
                {
                    BytesToNull(result, (long) s.rva + (long) maxLen, (long) s.rva + (long) minLen);
                }
            }

            if (vars.rvaCLRDirectory != 0)
            {
                if (vars.rvaCLRDirectory + 4 + 2 > (ulong) result.LongLength)
                    Alert("CLR directory out of image place");
                else
                {
                    var majVerCLR = ByteToSizedInteger(result, (long) vars.rvaCLRDirectory + 4 + 0, 2);
                    var minVerCLR = ByteToSizedInteger(result, (long) vars.rvaCLRDirectory + 4 + 2, 2);
                    ALi("This is program for Microsoft .NET framework for CLR version " + majVerCLR + "." + minVerCLR, "", "");
                    // Возможно, неверно
                }
            }

            return result;
        }

        private void checkExport(byte[] image, string fileName)
        {
            long fp = (long) baseAddressesOfDirectory[0].rva;

            if (fp == 0)
                return;

            ALine();

            var flags = ByteToSizedInteger(image, fp, 4); fp += 4;
            if (flags != 0)
                Alert("Export flags in address " + A16(fp - 4) + " must be 0, but not is it: " + A16(flags));
            else
                AL("Export flags must be 0");

            var timeStamp = ByteToSizedInteger(image, fp, 4); fp += 4;
            ALi("Export directory created at " + printDateTimeString((uint) timeStamp));

            var majVer = ByteToSizedInteger(image, fp, 2); fp += 2;
            var minVer = ByteToSizedInteger(image, fp, 2); fp += 2;
            ALi("Export version " + majVer + "." + minVer);

            var rvaDllName  = ByteToSizedInteger(image, fp, 4); fp += 4;

            ulong endName = rvaDllName;
            endName = getEndName(image, endName);

            var dllNameBytes = new byte[endName - rvaDllName];
            CopyTo(image, dllNameBytes, 0, (long) (rvaDllName - endName), (long) rvaDllName);
            vars.DllName = Encoding.UTF7.GetString(dllNameBytes);

            if (Path.GetFileName(fileName).ToLowerInvariant() != vars.DllName.ToLowerInvariant())
                ALW(String.Format("Dll name do not equals to file name: {0} {1}", Path.GetFileName(fileName).ToLowerInvariant(), vars.DllName.ToLowerInvariant()), "    ");
            else
                AL("Dll name equals to file name: " + vars.DllName, "    ");

            var ordinalBase = ByteToSizedInteger(image, fp, 4); fp += 4;

            var AddressTableEntriesCount = ByteToSizedInteger(image, fp, 4); fp += 4;
            var NamePointersCount        = ByteToSizedInteger(image, fp, 4); fp += 4;
            var ExportAddressTable       = ByteToSizedInteger(image, fp, 4); fp += 4;
            var NamePointers             = ByteToSizedInteger(image, fp, 4); fp += 4;
            var OrdinalTable             = ByteToSizedInteger(image, fp, 4); fp += 4;

            ALi(String.Format("Number of name pointers: {0}, number of address table entries: {1}", NamePointersCount, AddressTableEntriesCount));

            if (!PrintExport.Checked)
            {
                ALi("export table printing disabled: export table print skipped");
            }

            SortedList<uint, procDescriptor> procs = new SortedList<uint, procDescriptor>();

            for (uint i = 0; i < AddressTableEntriesCount; i++)
            {
                procs.Add(i, new procDescriptor());
                procs[i].procRva = (uint) ByteToSizedInteger(image, (long) (ExportAddressTable + 4*i), 4);

                procs[i].procOrdinal = i + (uint) ordinalBase; // TODO: здесь, возможно, неверный ordinal
                procs[i].NameTablePosition = findNameTablePosition(image, OrdinalTable, procs[i].procOrdinal - (uint) ordinalBase, (uint) NamePointersCount, (uint) ordinalBase);

                if (procs[i].NameTablePosition >= 0)
                {
                    procs[i].procNameRva = (uint) ByteToSizedInteger(image, (long) (NamePointers + (ulong) (4 * procs[i].NameTablePosition)), 4);

                    endName = procs[i].procNameRva;
                    endName = getEndName(image, endName);
                    procs[i].procName = getName(image, procs[i].procNameRva, endName);
                }
                else
                    procs[i].procName = null;

                if (baseAddressesOfDirectory[0].rva < procs[i].procRva && baseAddressesOfDirectory[0].rva + baseAddressesOfDirectory[0].size > procs[i].procRva)
                {
                    procs[i].iprocName = getName(image, procs[i].procRva, getEndName(image, procs[i].procRva));
                }

                if (PrintExport.Checked)
                {
                    // File.AppendAllText("tmp.txt", procs[i].procName + "\r\n");
                    if (procs[i].iprocName == null)
                        ALi(String.Format("А {0,-65:G} nm {1,-51:G} ord. {2,-4:G} nm№ {3,-4:G}", A16(procs[i].procRva), procs[i].procName, procs[i].procOrdinal, procs[i].NameTablePosition, procs[i].procOrdinal - (uint) ordinalBase), "    ");
                    else
                        ALi(String.Format("I {0,-65:G} nm {1,-51:G} ord. {2,-4:G} nm№ {3,-4:G}", procs[i].iprocName, procs[i].procName, procs[i].procOrdinal, procs[i].NameTablePosition, procs[i].procOrdinal - (uint) ordinalBase), "    ");

                    if (i % 5 == 4)
                        ALine(false);
                }
            }

            string lastName = null, curName;
            bool isNameOrderCorrect = true;
            for (uint i = 0; i < NamePointersCount; i++)
            {
                var procNameRva = (uint) ByteToSizedInteger(image, (long) (NamePointers + (ulong) (4 * procs[i].NameTablePosition)), 4);

                endName = procNameRva;
                endName = getEndName(image, endName);
                curName = getName(image, procNameRva, endName);
                if (lastName != null)
                {
                    if (curName.CompareTo(lastName) <= 0)
                    {
                        isNameOrderCorrect = false;
                        Alert("Export name order is incorrect in position " + i + " and names " + lastName + ", " + curName);
                    }
                }
            }

            if (isNameOrderCorrect)
                AL("Export name order is correct");
        }

        public class procDescriptor
        {
            public string procName     = null;
            public string iprocName    = null;
            public uint   procNameRva  = 0;
            public uint   procRva      = 0;
            public uint   procOrdinal  = 0;
            public int    NameTablePosition;
        }

        private ulong getEndName(byte[] fileContent, ulong endName)
        {
            for (; endName < vars.SizeOfImage; endName++)
            {
                if (fileContent[endName] == 0)
                    break;
            }
            return endName;
        }

        private string getName(byte[] fileContent, ulong startName, ulong endName)
        {
            var NameBytes = new byte[endName - startName];
            CopyTo(fileContent, NameBytes, 0, (long) (endName - startName), (long) startName);
            return Encoding.UTF7.GetString(NameBytes);
        }

        private int findNameTablePosition(byte[] fileContent, ulong ordinalTableRva, uint functionOrdinal, uint numbersOfNamesCount, uint ordinalBase)
        {
            for (int i = 0; i < numbersOfNamesCount; i++)
            {
                uint curNumber = (uint) ByteToSizedInteger(fileContent, (long) (ordinalTableRva + (ulong) (2*i)), 2);
                if (curNumber == functionOrdinal)
                    return i;
            }

            return -1;
        }

        private void checkImport(byte[] fileContent)
        {
            if (!PrintImport.Checked)
                AL("Import tables skipped (set 'print import flag for print')");

            AL("Import tables");
            long addr = (long) vars.rvaImportDirectory;
            long size = (long) vars.rvaImportDirectoryS;

            do
            {
                if (size < 0)
                {
                    Alert("Import tables end is incorrect with size" + vars.rvaImportDirectoryS, "\t");
                    return;
                }

                var lookupTable = (long)ByteToSizedInteger(fileContent, addr + 0, 4);
                var stamp = (long)ByteToSizedInteger(fileContent, addr + 4, 4);
                var fwchain = (long)ByteToSizedInteger(fileContent, addr + 8, 4);
                var dllname = (long)ByteToSizedInteger(fileContent, addr + 12, 4);
                var lookupTableCopy = (long)ByteToSizedInteger(fileContent, addr + 16, 4);

                if (lookupTable == 0 && stamp == 0 && fwchain == 0 && dllname == 0 && lookupTableCopy == 0)
                {
                    if (size == 5 * 4)
                        AL("Import tables end is correct (with 5x4 null bytes) and it size correct (" + vars.rvaImportDirectoryS + ") - well", "\t");
                    else
                        Alert("Import tables end is correct (with 5x4 null bytes), but size incorrect: " + vars.rvaImportDirectoryS + " | " + size, "\t");

                    return;
                }

                string dllName = "undefined";
                if (dllname != 0)
                {
                    dllName = GetASCIIString(fileContent, dllname, fileContent.Length - (int)dllname);
                    if (PrintImport.Checked)
                    AL("dllName " + dllName, "\t");
                }
                else
                    Alert("dllName == 0", "\t");

                checkImportLookupTables(fileContent, lookupTable, lookupTableCopy, dllName == "kernel32.dll");

                addr += 5 * 4;
                size -= 5 * 4;
            }
            while (true);
        }

        private void checkImportLookupTables(byte[] fileContent, long lookupTable, long lookupTableCopy, bool kernel32)
        {
            int errors = 0;
            if (lookupTable <= 0)
            {
                Alert("lookupTable is null", "\t\t");
                errors++;
            }
            if (lookupTable > (long)vars.SizeOfImage)
            {
                Alert("lookupTable out from file", "\t\t");
                errors++;
            }
            if (lookupTableCopy <= 0)
            {
                Alert("lookupTableCopy is null", "\t\t");
                errors++;
            }
            if (lookupTableCopy > (long)vars.SizeOfImage)
            {
                Alert("lookupTableCopy out from file", "\t\t");
                errors++;
            }
            if (lookupTable == lookupTableCopy)
            {
                Alert("lookupTableCopy == lookupTable", "\t\t");
                errors++;
            }

            if (errors == 0)
                if (PrintImport.Checked)
                    AL("lookupTable != lookupTableCopy != null", "\t\t");

            string[] funcs = null;
            List<string> lst = null;
            if (kernel32)
            {
                try
                {
                    funcs = File.ReadAllLines("kernel32.txt");
                    lst = new List<string>(funcs);
                }
                catch
                {
                    kernel32 = false;
                }
            }

            int errorsK = 0;
            var lt = lookupTable;
            while (true)
            {
                if (vars.PE32Format)
                {
                    var nameOrOrdinal = ByteToSizedInteger(fileContent, lt, 4);
                    if (nameOrOrdinal == 0)
                    {
                        if (errorsK > 0)
                            Alert("may be incorrect: kernel32 functions have strange names", "\t\t");
                        break;
                    }

                    if ((nameOrOrdinal & 0x80000000) > 0)
                    {
                        ulong ord = (nameOrOrdinal & ~0x80000000);
                        if (ord > 0 && ord < (ulong) short.MaxValue)
                        {
                            if (PrintImport.Checked)
                            AL("import by ordinal " + ord + " (in 1-32767 range)", "\t\t");
                        }
                        else
                            Alert("import by ordinal without 1-32767: " + ord, "\t\t");
                    }
                    else
                    {
                        if (nameOrOrdinal > vars.SizeOfImage)
                        {
                            Alert("Address of importing function name out from file", "\t\t");
                            lt += 4;
                            continue;
                        }

                        if ((nameOrOrdinal & 1) > 0)
                            Alert("Address of importing function name must be % 2 == 0: " + nameOrOrdinal, "\t\t");

                        var funcName = GetASCIIString(fileContent, (long) nameOrOrdinal + 2, fileContent.Length - (int)nameOrOrdinal);
                        if (funcName.Length > 0)
                        {
                            if (PrintImport.Checked)
                            AL("Import function by name " + funcName, "\t\t");

                            if (kernel32 && !lst.Contains(funcName))
                                errorsK++;
                            else
                                errorsK--;

                        }
                        else
                            Alert("Import function by name incorrect (name is null)", "\t\t");
                    }

                    lt += 4;
                }
                else
                {
                    var nameOrOrdinal = ByteToSizedInteger(fileContent, lt, 8);
                    if (nameOrOrdinal == 0)
                        break;

                    if ((nameOrOrdinal & 0x8000000000000000) > 0)
                    {
                        ulong ord = (nameOrOrdinal & ~0x8000000000000000);
                        if (ord > 0 && ord < (ulong) short.MaxValue)
                        {
                            if (PrintImport.Checked)
                            AL("import by ordinal " + ord + " (in 1-32767 range)", "\t\t");
                        }
                        else
                            Alert("import by ordinal without 1-32767 range: " + ord, "\t\t");
                    }
                    else
                    {
                        if (nameOrOrdinal > vars.SizeOfImage)
                        {
                            Alert("Address of importing function name out from file", "\t\t");
                            lt += 8;
                            continue;
                        }

                        if ((nameOrOrdinal & 1) > 0)
                            Alert("Address of importing function name must be % 2 == 0: " + nameOrOrdinal, "\t\t");

                        var funcName = GetASCIIString(fileContent, (long) nameOrOrdinal + 2, fileContent.Length - (int)nameOrOrdinal);
                        if (funcName.Length > 0)
                        {
                            if (PrintImport.Checked)
                            AL("Import function by name " + funcName, "\t\t");
                        }
                        else
                            Alert("Import function by name incorrect (name is null)", "\t\t");
                    }

                    lt += 8;
                }

                if ((ulong) lt > vars.SizeOfImage)
                    Alert("Import table end is incorrect: must null terminated");
            }
        }

        public class DirectoryEntry
        {
            public string description;
            public ulong  rva;
            public ulong  size;

            public bool   isExport;
            public bool   isImport;
            public bool   isRelocation;
            public bool   isResource;
        }

        public class section
        {
            public ulong rva;
            public ulong va;
            public ulong filePointer
            {
                get
                {
                    return rawDataFilePointer;
                }
            }

            public ulong VirtualSize;

            public ulong sizeOfRawData;
            public ulong rawDataFilePointer;
            public ulong pointerToRelocations;
            public ulong ch;

            public readonly string sectionName;

            public bool ContainsExecutable, CanBeExecute, ContainsInitializedData, ContainsUninitializedData, ContainsExtendedRelocation, CanBeRead, CanBeWritten, CanBeDiscarded;
            public bool ImportDirectoryContains;
            public bool ExportDirectoryContains;
            public bool ResourceDirectoryContains;
            public bool RelocationContains;
            public bool IATContains;

            public section(string name)
            {
                sectionName = name;
            }
        }

        private section printSection(byte[] fileContent, ref long fp, int i)
        {
            if (fp + 40 > fileContent.Length)
            {
                Alert("In section headers must be section header, but file is ended");
                return null;
            }

            var sectionName = GetASCIIString(fileContent, fp, 8); fp += 8;
            ALi("section name " + sectionName, "", "");

            var section = new section(sectionName);
            baseAddresses.Add(i, section);

            section.VirtualSize = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            ALi("section virtual size " + A16(section.VirtualSize));

            section.rva = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            section.va  = section.rva + vars.ImageBase;
            ALi("section virtual address " + A16(section.rva));

            if (section.rva % vars.SectionAlignment != 0)
                Alert("Section address with no alignment to Section Alignment", "    ");
            else
                AL("Section address with alignment to Section Alignment", "    ");

            section.sizeOfRawData = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            ALi("size of raw data " + A16(section.sizeOfRawData));

            if (section.sizeOfRawData % vars.FileAlignment != 0)
                Alert("Size of raw data must be multiple of File Alignment, but do not: " + A16(section.sizeOfRawData) + ", FA " + A16(vars.FileAlignment), "    ");
            else
                AL("Size of raw data has be multiple of File Alignment: " + A16(section.sizeOfRawData) + ", FA " + A16(vars.FileAlignment), "    ");

            section.rawDataFilePointer = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            if (section.rawDataFilePointer % vars.FileAlignment != 0)
                Alert("File pointer to raw data must be multiple of File Alignment, but do not: " + A16(section.rawDataFilePointer), "    ");
            else
                AL("File pointer to raw data has be multiple of File Alignment: " + A16(section.rawDataFilePointer), "    ");

            if (section.rawDataFilePointer != 0)
            {
                if (section.rawDataFilePointer >= vars.headerFactEnd)
                    AL("File pointer to raw data out of optional header", "    ");
                else
                    Alert("File pointer to raw data in optional header", "    ");

                if (section.rawDataFilePointer + section.sizeOfRawData <= (ulong) fileContent.LongLength)
                    AL("Raw data in file boundaries " + A16(section.rawDataFilePointer + section.sizeOfRawData) + " <= " + A16(fileContent.LongLength), "    ");
                else
                    Alert("Raw data out of file boundaries " + A16(section.rawDataFilePointer + section.sizeOfRawData) + " > " + A16(fileContent.LongLength), "    ");
            }

            section.pointerToRelocations = ByteToSizedInteger(fileContent, fp, 4); fp += 4;

            if (section.pointerToRelocations != 0)
                Alert("Relocations is declared, but this must be zero", "    ");
            else
                AL("Relocations not declared", "    ");


            var fpToLineNumbers = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            if (fpToLineNumbers > 0)
                ALW("Pointer to line numbers deprecated and must be null, but not is it: " + A16(fpToLineNumbers));
            else
                ALi("Pointer to line numbers deprecated and must be null - well done");

            var NumberOfRelocations = ByteToSizedInteger(fileContent, fp, 2); fp += 2;
            var NumberOfLinenumbers = ByteToSizedInteger(fileContent, fp, 2); fp += 2;

            if (NumberOfRelocations > 0)
                ALW("Number of relocations must be 0, but " + A16(NumberOfRelocations));
            else
                ALi("Number of relocations must be 0 - well done");

            if (NumberOfLinenumbers > 0)
                ALW("Number of relocations must be 0, but " + A16(NumberOfLinenumbers));
            else
                ALi("Number of relocations must be 0 - well done");


            section.ch = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            printSectionCharacteristics(section);

            return section;
        }

        int[] sectionFlagsValuesMask = 
                                    {
                                        0, // 0x00000001
                                        0,
                                        0,
                                        0,
                                        0,  // 0x00000010
                                        2,
                                        2,  // 0x00000040
                                        2,
                                        0,  // 0x00000100
                                        0,
                                        0,
                                        0,  // 0x00000800
                                        0,
                                        0,
                                        0,  // 0x00004000
                                        2,
                                        0,
                                        0,  // 0x00020000
                                        0,
                                        0,
                                        0,
                                        0,
                                        0,
                                        0,  // 0x00800000
                                        2,
                                        2,  // 0x02000000
                                        2,
                                        2,  // 0x08000000
                                        2,
                                        2,  // 0x20000000
                                        2,
                                        2
                                    };
        uint[] sectionFlagsValues = {
                                         0x00000001,
                                         0x00000002,
                                         0x00000004,
                                         0x00000008,
                                         0x00000010,
                                         0x00000020,
                                         0x00000040,
                                         0x00000080,
                                         0x00000100,
                                         0x00000200,
                                         0x00000400,
                                         0x00000800,
                                         0x00001000,
                                         0x00002000,
                                         0x00004000,
                                         0x00008000,
                                         0x00010000,
                                         0x00020000,
                                         0x00040000,
                                         0x00080000,
                                         0x00100000,
                                         0x00200000,
                                         0x00400000,
                                         0x00800000,
                                         0x01000000,
                                         0x02000000,
                                         0x04000000,
                                         0x08000000,
                                         0x10000000,
                                         0x20000000,
                                         0x40000000,
                                         0x80000000
                                     };
        string[] sectionFlagsNames = {
                                         "0x00000001 Reserved",
                                         "0x00000002 Reserved",
                                         "0x00000004 Reserved",
                                         "0x00000008 The section should not be padded to the next boundary. Must be null in executable images",
                                         "0x00000010 Reserved",
                                         "0x00000020 The section contains executable code",
                                         "0x00000040 The section contains initialized data",
                                         "0x00000080 The section contains uninitialized data",
                                         "0x00000100 Reserved",
                                         "0x00000200 The section contains comments or other information. This is valid for object files only",
                                         "0x00000400 Reserved",
                                         "0x00000800 This is valid only for object files (link remove)",
                                         "0x00001000 The section contains COMDAT data. This is valid only for object files",
                                         "0x00002000 Not declared in PE-specification",
                                         "0x00004000 Not declared in PE-specification",
                                         "0x00008000 The section contains data referenced through the global pointer (GP)",
                                         "0x00010000 Not declared in PE-specification",
                                         "0x00020000 Reserved",
                                         "0x00040000 Reserved",
                                         "0x00080000 Reserved",
                                         "0x00100000 Align data on a 1-byte boundary. Valid only for object files",
                                         "0x00200000 Align data on a 2-byte boundary. Valid only for object files",
                                         "0x00400000 Align data on a 8-byte boundary. Valid only for object files",
                                         "0x00800000 Align data on a 128-byte boundary. Valid only for object files",
                                         "0x01000000 The section contains extended relocations",
                                         "0x02000000 The section can be discarded as needed",
                                         "0x04000000 The section cannot be cached",
                                         "0x08000000 The section is not pageable",
                                         "0x10000000 The section can be shared in memory",
                                         "0x20000000 The section can be executed as code",
                                         "0x40000000 The section can be read",
                                         "0x80000000 The section can be written to"
                                     };
        private void printSectionCharacteristics(section section)
        {
            if (sectionFlagsValues.Length != sectionFlagsNames.Length || sectionFlagsValuesMask.Length != sectionFlagsValues.Length)
                throw new Exception();

            for (int i = 0; i < sectionFlagsValues.Length; i++)
            {
                if ((section.ch & sectionFlagsValues[i]) > 0)
                {
                    if (sectionFlagsValuesMask[i] == 0)
                        Alert(sectionFlagsNames[i], "        ");
                    else
                        ALi(sectionFlagsNames[i], "        ");
                }
            }

            section.CanBeExecute                = (section.ch & 0x20000000) > 0;
            section.ContainsExecutable          = (section.ch & 0x00000020) > 0;
            section.CanBeDiscarded              = (section.ch & 0x02000000) > 0;
            section.CanBeRead                   = (section.ch & 0x40000000) > 0;
            section.CanBeWritten                = (section.ch & 0x80000000) > 0;
            section.ContainsInitializedData     = (section.ch & 0x00000040) > 0;
            section.ContainsUninitializedData   = (section.ch & 0x00000080) > 0;
            section.ContainsExtendedRelocation  = (section.ch & 0x01000000) > 0;

            if (!section.CanBeRead)
                Alert("Section can not be read", "        ");
            else
                AL("Section can be read", "        ");

            if (vars.rvaImportDirectory >= section.rva && vars.rvaImportDirectory < section.rva + section.sizeOfRawData)
            {
                ALi("section contains import directory: id rva " + A16(vars.rvaImportDirectory) + ", end id rva " + A16(vars.rvaImportDirectory + vars.rvaImportDirectoryS) + ", section rva " + A16(section.rva) + ", section end rva " + A16(section.rva + section.sizeOfRawData), "    ");
                section.ImportDirectoryContains = true;

                if (vars.rvaImportDirectory + vars.rvaImportDirectoryS <= section.rva + section.sizeOfRawData)
                    AL("Import directory in section boundaries", "        ");
                else
                    Alert("Import directory out of section boundaries", "        ");
                /*
                if (section.CanBeWritten)
                    AL("Section with import data marked as can be written", "        ");
                else
                if (vars.isDelayedImportDeclared && (section.CanBeExecute || section.ContainsExecutable))
                    ALW("Section with import data must be marked as can be written, but not is it. Usually it is with bound import section declared (is it)", "        ");
                else
                    Alert("Section with import data must be marked as can be written, but not is it", "        ");
                *//*
                if (section.CanBeDiscarded)
                    Alert("Section with import data must not be discarded", "        ");
                else
                    AL("Section with import data must not be discarded", "        ");
                */
                if (section.ContainsInitializedData)
                    AL("Section with import data marked as initializaed data contains", "        ");
                else
                if (/*vars.isDelayedImportDeclared && */section.ContainsExecutable)
                    ALW("Section with import data not marked as initializaed data (Usually it is in exececute section; is it)", "        ");
                else
                    Alert("Section with import data must be marked as initializaed data contains, but not is it", "        ");
            }

            if (vars.rvaIATDirectory >= section.rva && vars.rvaIATDirectory < section.rva + section.sizeOfRawData)
            {
                ALi("section contains import address table: IAT rva " + A16(vars.rvaIATDirectory) + ", end IAT rva " + A16(vars.rvaIATDirectory + vars.rvaIATDirectoryS) + ", section rva " + A16(section.rva) + ", section end rva " + A16(section.rva + section.sizeOfRawData), "    ");
                section.IATContains = true;

                if (vars.rvaIATDirectory + vars.rvaIATDirectoryS <= section.rva + section.sizeOfRawData)
                    AL("IAT in section boundaries", "        ");
                else
                    Alert("IAT out of section boundaries", "        ");

                // В том же notepad.exe секция rdata содержит IAT, но секция только для чтения. Она же содержит и import directory
                if (section.CanBeWritten)
                    AL("Section with IAT marked as can be written", "        ");
                else
                //if (vars.isDelayedImportDeclared && (section.CanBeExecute || section.ContainsExecutable))
                    ALW("Section with IAT not marked as writable (in Microsoft PE-specification .idata writable, but such Microsoft programs as notepad.exe contains not writable IAT tables; don't known)", "        ");
                /*else
                    Alert("Section with IAT must be marked as can be written, but not is it", "        ");
                *//*
                if (section.CanBeDiscarded)
                    Alert("Section with IAT must not be discarded", "        ");
                else
                    AL("Section with IAT must not be discarded", "        ");
                */
                if (section.ContainsInitializedData)
                    AL("Section with IAT marked as initializaed data contains", "        ");
                else
                if (/*vars.isDelayedImportDeclared && */section.ContainsExecutable)
                    ALW("Section with IAT not marked as initializaed data (Usually it is in exececute section; is it)", "        ");
                else
                    Alert("Section with IAT must be marked as initializaed data contains, but not is it", "        ");
            }

            if (vars.rvaExportDirectory >= section.rva && vars.rvaExportDirectory < section.rva + section.sizeOfRawData)
            {
                ALi("section contains export directory: dir rva " + A16(vars.rvaExportDirectory) + ", end dir rva " + A16(vars.rvaExportDirectory + vars.rvaExportDirectoryS) + ", section rva " + A16(section.rva) + ", section end rva " + A16(section.rva + section.sizeOfRawData), "    ");
                section.ExportDirectoryContains = true;

                if (vars.rvaExportDirectory + vars.rvaExportDirectoryS <= section.rva + section.sizeOfRawData)
                    AL("Export directory in section boundaries", "        ");
                else
                    Alert("Export directory out of section boundaries", "        ");
                /*
                if (section.CanBeDiscarded)
                    Alert("Section with export data must not be discarded", "        ");
                else
                    AL("Section with export data must not be discarded", "        ");
                */
                if (section.ContainsInitializedData)
                    AL("Section with export data marked as initializaed data contains", "        ");
                else
                if (section.ContainsExecutable)
                    ALW("Section with export data not marked as initializaed data (Usually it is in exececute section; is it)", "        ");
                else
                    Alert("Section with export data must be marked as initializaed data contains, but not is it", "        ");
            }

            if (vars.rvaResDirectory >= section.rva && vars.rvaResDirectory < section.rva + section.sizeOfRawData)
            {
                ALi("section contains resource directory: dir rva " + A16(vars.rvaResDirectory) + ", end dir rva " + A16(vars.rvaResDirectory + vars.rvaResDirectoryS) + ", section rva " + A16(section.rva) + ", section end rva " + A16(section.rva + section.sizeOfRawData), "    ");
                section.ResourceDirectoryContains = true;

                if (vars.rvaResDirectory + vars.rvaResDirectoryS <= section.rva + section.sizeOfRawData)
                    AL("Export resource in section boundaries", "        ");
                else
                    Alert("Export resource out of section boundaries", "        ");
                /*
                if (section.CanBeDiscarded)
                    Alert("Section with resource data must not be discarded", "        ");
                else
                    AL("Section with resource data must not be discarded", "        ");
                */
                if (section.ContainsInitializedData)
                    AL("Section with resource data marked as initializaed data contains", "        ");
                else
                if (section.ContainsExecutable)
                    ALW("Section with resource data not marked as initializaed data (Usually it is in exececute section; is it)", "        ");
                else
                    Alert("Section with resource data must be marked as initializaed data contains, but not is it", "        ");
            }

            if (vars.rvaRelocationDirectory >= section.rva && vars.rvaRelocationDirectory < section.rva + section.sizeOfRawData)
            {
                ALi("section contains relocation directory: dir rva " + A16(vars.rvaRelocationDirectory) + ", end dir rva " + A16(vars.rvaRelocationDirectory + vars.rvaRelocationDirectoryS) + ", section rva " + A16(section.rva) + ", section end rva " + A16(section.rva + section.sizeOfRawData), "    ");
                section.RelocationContains = true;

                if (vars.rvaRelocationDirectory + vars.rvaRelocationDirectoryS <= section.rva + section.sizeOfRawData)
                    AL("Export relocation in section boundaries", "        ");
                else
                    Alert("Export relocation out of section boundaries", "        ");

                if (!section.CanBeDiscarded && !section.CanBeExecute && !section.ContainsExecutable && !section.ExportDirectoryContains && !section.ImportDirectoryContains && !section.ResourceDirectoryContains)
                    ALW("Section with relocation data usually can be discarded, but not marked", "        ");
                else
                if (section.CanBeDiscarded)
                    AL("Section with relocation data usually can be discarded", "        ");

                if (section.ContainsInitializedData)
                    AL("Section with relocation data marked as initializaed data contains", "        ");
                else
                if (section.ContainsExecutable)
                    ALW("Section with relocation data not marked as initializaed data (Usually it is in exececute section; is it)", "        ");
                else
                    Alert("Section with relocation data must be marked as initializaed data contains, but not is it", "        ");
            }

            for (int i = 3; i < baseAddressesOfDirectory.Count; i++)
            {
                if (i == 5 || i == 12)
                    continue;

                var de = baseAddressesOfDirectory[i];

                if (!(de.rva >= section.rva && de.rva < section.rva + section.sizeOfRawData))
                    continue;

                ALi("section contains " + de.description + " directory: dir rva " + A16(de.rva) + ", end dir rva " + A16(de.rva + de.size) + ", section rva " + A16(section.rva) + ", section end rva " + A16(section.rva + section.sizeOfRawData), "    ");
                section.RelocationContains = true;

                if (de.rva + de.size <= section.rva + section.sizeOfRawData)
                    AL("Directory in section boundaries", "        ");
                else
                    Alert("Directory out of section boundaries", "        ");
            }
        }

        protected class Vars
        {
            public ushort sectionCount = 0;
            public ushort sizeOfOptionalHeader = 0;
            public uint   optionalHeaderOffset = 0;
            public uint   headerFactEnd = 0;
            public ushort fileCharacteristics  = 0;
            public bool   PE32Format = false;
            public bool   isDLL      = false;
            public uint   sizeOfCode = 0;
            public uint   sizeOfIData = 0;
            public uint   sizeOfUData = 0;
            public uint   AddressOfEntryPoint = 0;
            public uint   BaseOfCode  = 0;
            public uint   BaseOfData  = 0;
            public ulong  ImageBase   = 0;
            public uint   SectionAlignment = 0;
            public uint   FileAlignment    = 0;
            public ulong  SizeOfImage      = 0;
            public uint   SizeOfHeaders    = 0;
            public uint   SizeOfHeadersAdd = 0;
            public ulong  CheckSum         = 0;
            public ulong  DllCharacteristics  = 0;
            public ulong  NumberOfRvaAndSizes = 0;

            public ulong  rvaExportDirectory  = 0;
            public ulong  rvaImportDirectory  = 0;
            public ulong  rvaIATDirectory     = 0;
            public ulong  rvaResDirectory     = 0;
            public ulong  rvaCLRDirectory     = 0;
            public ulong  rvaRelocationDirectory  = 0;

            public ulong  rvaExportDirectoryS = 0;
            public ulong  rvaImportDirectoryS = 0;
            public ulong  rvaIATDirectoryS    = 0;
            public ulong  rvaResDirectoryS    = 0;
            public ulong  rvaCLRDirectoryS    = 0;
            public ulong  rvaRelocationDirectoryS  = 0;
            public uint   endOfHeadersAD      = 0;

            public  bool isDelayedImportDeclared = false;
            public  bool ImageContainsExecutableSection;
            public  string DllName;
            internal long addressOfPESignature;
        }

        protected SortedList<int, Vars> _vars = new SortedList<int, Vars>(Environment.ProcessorCount * 2);
        protected Vars vars
        {
            get
            {
                lock (_vars)
                {
                    if (!_vars.ContainsKey(Thread.CurrentThread.ManagedThreadId))
                        _vars.Add(Thread.CurrentThread.ManagedThreadId, new Vars());

                    return _vars[Thread.CurrentThread.ManagedThreadId];
                }
            }
        }

        string[] DirectoryEntriesNames = {
                                             "Export Table",
                                             "Import Table",
                                             "Resource Table",
                                             "Exception Table",
                                             "Certificate Table",
                                             "Base Relocation Table", // 5
                                             "Debug",
                                             "Architecture",
                                             "Global Ptr",
                                             "TLS Table",
                                             "Load Config Table", // 10
                                             "Bound Import",
                                             "IAT",
                                             "Delay Import Descriptor",
                                             "CLR Runtime Header",
                                             "Reserved, must be zero"
                                         };
        private void printDirectoryEntries(byte[] fileContent, ref long fp, int i)
        {
            if (i > DirectoryEntriesNames.Length)
            {
                Alert("ERROR: not enought of directory entries");
                return;
            }

            var dirVA   = ByteToSizedInteger(fileContent, fp, 4); fp += 4;
            var dirSize = ByteToSizedInteger(fileContent, fp, 4); fp += 4;

            var de          = new DirectoryEntry();
            de.description  = DirectoryEntriesNames[i];
            de.rva          = dirVA;
            de.size         = dirSize;
            de.isExport     = i == 0;
            de.isImport     = i == 1;
            de.isResource   = i == 2;
            de.isRelocation = i == 5;
            baseAddressesOfDirectory.Add(i, de);


            if (dirVA != 0)
            {
                AL(DirectoryEntriesNames[i] + " directory entry declared");
                if (dirSize == 0 && i != 8)
                    ALW(DirectoryEntriesNames[i] + " directory entry declared, but it size is null");
            }
            else
            {
                if (dirSize != 0)
                    ALW(DirectoryEntriesNames[i] + " directory entry not declared, but it size is not null");
                else
                    AL(DirectoryEntriesNames[i] + " directory entry skipped");
            }

            if (i == 7 || i == 15)
            {
                if (dirSize != 0 || dirVA != 0)
                    Alert("Reserved Directory entry must be null, but it declared");
                else
                    AL("Reserved Directory entry has be null");
            }

            if (i == 8)
            {
                if (dirSize != 0)
                    Alert("Global Ptr directory entry must be null size, but declared " + A16(dirSize) + " size");
                else
                    AL("Global Ptr directory entry has be null size");
            }

            if (dirVA > 0)
            {
                if (dirVA + dirSize > vars.SizeOfImage)
                    Alert("Directory entry virtual address + size > size of image: rva " + A16(dirVA) + ", size " + A16(dirSize) + ", image size " + A16(vars.SizeOfImage));
                else
                    AL("Directory entry virtual address + size <= size of image: rva " + A16(dirVA) + ", size " + A16(dirSize) + ", image size " + A16(vars.SizeOfImage));

                var SectionAlignedSizeOfHeaders = vars.SizeOfHeaders;
                if (vars.SizeOfHeaders % vars.SectionAlignment != 0)
                {
                    SectionAlignedSizeOfHeaders += vars.SectionAlignment - (vars.SizeOfHeaders % vars.SectionAlignment);
                }

                if (i == 11)
                    vars.isDelayedImportDeclared = true;

                if (dirVA < SectionAlignedSizeOfHeaders && dirSize > 0)
                {
                    if (i != 11)
                    {
                        ALW("Directory entry usually do pointing to not header section, but do pointing to header section");
                    }

                    if (vars.SizeOfHeadersAdd < dirVA + dirSize)
                        vars.SizeOfHeadersAdd = (uint) (dirVA + dirSize);
                }
                else
                    AL("Directory entry usually do pointing to not header section (exclude bound import directory)");
            }

            switch (i)
            {
                case 0: 
                    vars.rvaExportDirectory  = dirVA;
                    vars.rvaExportDirectoryS = dirSize;
                    break;
                case 1:
                    vars.rvaImportDirectory  = dirVA;
                    vars.rvaImportDirectoryS = dirSize;
                    break;
                case 2:
                    vars.rvaResDirectory     = dirVA;
                    vars.rvaResDirectoryS    = dirSize;
                    break;
                case 5:
                    vars.rvaRelocationDirectory  = dirVA;
                    vars.rvaRelocationDirectoryS = dirSize;
                    break;
                case 12:
                    vars.rvaIATDirectory  = dirVA;
                    vars.rvaIATDirectoryS = dirSize;
                    break;
                case 14:
                    vars.rvaCLRDirectory  = dirVA;
                    vars.rvaCLRDirectoryS = dirSize;
                    break;
                default:
                    break;
            }

            if (vars.isDLL && (i == 14 || (i == 0 && vars.NumberOfRvaAndSizes < 3) || (i == 2 && vars.NumberOfRvaAndSizes < 15)  ))
            {
                if (   (vars.rvaExportDirectory == 0 || vars.rvaExportDirectoryS == 0)
                    && (vars.rvaResDirectory    == 0 || vars.rvaResDirectoryS    == 0)
                    && (vars.rvaCLRDirectory    == 0 || vars.rvaCLRDirectoryS    == 0)
                    )
                {
                    Alert("Export directory entry or resource directory entry or CLR must be not null, but no (PE file is DLL)");
                }
                else
                    AL("Export directory entry or resource directory entry or CLR have be not null (PE file is DLL)");
            }
        }


        [DllImport("Kernel32.dll")]
        static extern Int32 CreateFileMapping(Int32 hFile, Int32 lpAttributes, 
                                              Int32 flProtect /* PAGE_READONLY 0x02 SEC_IMAGE 0x1000000 */,
                                              Int32 dwMaximumSizeHigh, Int32 dwMaximumSizeLow, string FileName);

        [DllImport("Kernel32.dll")]
        static extern Int32 MapViewOfFile(Int32 hFileMappingObject, UInt32 dwDesiredAccess, 
                                          Int32 dwFileOffsetHigh,   Int32 dwFileOffsetLow, Int32 dwNumberOfBytesToMap);

        [DllImport("Kernel32.dll")]
        static extern Int32 UnmapViewOfFile(Int32 lpBaseAddress);

        [DllImport("Imagehlp.dll")]
        static extern Int32 CheckSumMappedFile(Int32 BaseAddress, Int32 FileLength, out Int32 HeaderSum, out Int32 CheckSum);

        [DllImport("Kernel32.dll")]
        static extern Int32 CreateFile(string lpFileName, UInt32 dwDesiredAccess, Int32 dwShareMode, Int32 lpSecurityAttributes,
                                                                Int32 dwCreationDisposition, Int32 dwFlagsAndAttributes, Int32 hTemplateFile);

        [DllImport("Kernel32.dll")]
        static extern Int32 CloseHandle(Int32 lpBaseAddress);

        [DllImport("Kernel32.dll")]
        static extern Int32 GetLastError();

        [DllImport("Imagehlp.dll")]
        static extern Int32 MapFileAndCheckSum(string FileName, out Int32 HeaderSum, out Int32 CheckSum);

        object syncCheckSum = new object();
        public long CalculateCRC32(string FileName, Int32 sizeOfFile)
        {
            long CRC32 = -1; Int32 a;
            Int32 CRCPointer = 0;
            /*
            try
            {
                var hFile = CreateFile(FileName, 0x80000000, 0x00000001, 0, 3, 0x80, 0);
                if (hFile == 0)
                    return -1;

                var hFileMapping = CreateFileMapping(hFile, 0, 0x02, 0, sizeOfFile, null);
                if (hFileMapping == 0)
                {
                    CloseHandle(hFile);
                    return -1;
                }

                var hMapVF = MapViewOfFile(hFileMapping, 4, 0, 0, sizeOfFile);
                if (hFileMapping == 0)
                {
                    CloseHandle(hFileMapping);
                    CloseHandle(hFile);
                    return -1;
                }

                if (CheckSumMappedFile(hMapVF, sizeOfFile, out a, out CRCPointer) == 0)
                {
                    CRC32 = -1;
                }
                else
                    CRC32 = a;

                UnmapViewOfFile(hMapVF);
                CloseHandle(hFileMapping);
                CloseHandle(hFile);
            }
            catch
            {}*/

            int r;
            lock (syncCheckSum)
            {
                r = MapFileAndCheckSum(FileName, out CRCPointer, out a);
            }

            if (r != 0)
                ALW("Check sum function during error: " + r);

            if (r == 0)
                CRC32 = a;

            return CRC32;
        }

        public enum AddressType {filePointer = 0, rva = 1, va = 2};
        readonly string[] AddressTypePrefix = new string[] {"fp", "rva", "va"};

        SortedList<int, SortedList<int, section>> _baseAddresses = new SortedList<int, SortedList<int, section>>(Environment.ProcessorCount * 2);

        SortedList<int, section> baseAddresses
        {
            get
            {
                lock (_baseAddresses)
                {
                    if (!_baseAddresses.ContainsKey(Thread.CurrentThread.ManagedThreadId))
                        _baseAddresses.Add(Thread.CurrentThread.ManagedThreadId, new SortedList<int, section>(32));

                    return _baseAddresses[Thread.CurrentThread.ManagedThreadId];
                }
            }
        }

        SortedList<int, SortedList<int, DirectoryEntry>> _baseAddressesOfDirectory = new SortedList<int, SortedList<int, DirectoryEntry>>(Environment.ProcessorCount * 2);

        SortedList<int, DirectoryEntry> baseAddressesOfDirectory
        {
            get
            {
                lock (_baseAddressesOfDirectory)
                {
                    if (!_baseAddressesOfDirectory.ContainsKey(Thread.CurrentThread.ManagedThreadId))
                        _baseAddressesOfDirectory.Add(Thread.CurrentThread.ManagedThreadId, new SortedList<int, DirectoryEntry>(32));

                    return _baseAddressesOfDirectory[Thread.CurrentThread.ManagedThreadId];
                }
            }
        }

        public string printSize(ulong size)
        {
            return "" + size + "\t(" + (size > 1024*1024 ? "" + size / (1024*1024) + " Mb)" : "" + size / 1024 + " kb)");
        }

        public DateTime fromUnixTime(int TimeStamp)
        {
            DateTime UnixDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return UnixDateTime.AddSeconds(TimeStamp);
        }

        public string printDateTimeString(uint TimeStamp)
        {
            if (TimeStamp == 0)
                return "0 (unspecified)";

            var dt = fromUnixTime((int) TimeStamp);
            return getHumanTime(dt);
        }

        static System.Globalization.CultureInfo dtfi = System.Globalization.CultureInfo.CurrentUICulture;
        private static string getHumanTime(DateTime dt)
        {
            return dt.ToString("yyyy.MM.dd HH':'mm':'ss K", dtfi);
        }

        ushort[] DLLCharacteristicsFlagsValues = {0x0001, 0x0002, 0x0004, 0x0008, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x8000};
        string[] DLLCharacteristicsFlagsNames  = { "0x0001 {\\b \\cf3 ERROR! is reserved flag}",
                                                   "0x0002 {\\b \\cf3 ERROR! is reserved flag}",
                                                   "0x0004 {\\b \\cf3 ERROR! is reserved flag}",
                                                   "0x0008 {\\b \\cf3 ERROR! is reserved flag}",
                                                   "IMAGE_FILE_LARGE_ADDRESS_ AWARE",
                                                   "0x0040 DLL can be relocated at load time",
                                                   "0x0080 Code Integrity checks are enforced",
                                                   "0x0100 Image is NX compatible",
                                                   "0x0200 Isolation aware, but do not isolate the image",
                                                   "0x0400 Does not use structured exception (SE) handling. No SE handler may be called in this image",
                                                   "0x0800 Do not bind the image",
                                                   "0x1000 {\\b \\cf3 ERROR! is reserved flag}",
                                                   "0x2000 A WDM driver",
                                                   "0x8000 Terminal Server aware"
                                                 };

        public void printDLLCharacteristics(ushort ch)
        {
            if (DLLCharacteristicsFlagsValues.Length != DLLCharacteristicsFlagsNames.Length)
                throw new Exception();

            if ((15 & ch) != 0 || (0x1000 & ch) != 0)
            {
                Alert("DLL characteristics reserved flags in set state");
            }
            else
                AL("DLL characteristics reserved flags in reset state");

            ushort t = ch;
            for (int i = 0; i < DLLCharacteristicsFlagsValues.Length; i++)
                if ((t & DLLCharacteristicsFlagsValues[i]) > 0)
                    t &= (ushort) ~DLLCharacteristicsFlagsValues[i];

            // ~AFC0 = FFFF503F
            if (t != 0)
            {
                Alert("DLL characteristics unknown flags in set state " + t);
            }
            else
                AL("DLL characteristics unknown flags in reset state");


            if (ch == 0)
                ALi("DLL characteristics flags all in reset state");
            else
            for (int i = 0; i < DLLCharacteristicsFlagsValues.Length; i++)
            {
                if ((DLLCharacteristicsFlagsValues[i] & ch) != 0)
                    ALi(DLLCharacteristicsFlagsNames[i]);
            }
        }

        const ushort IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        const ushort IMAGE_FILE_FLAG_RESERVED   = 0x0040;
        ushort[] FileCharacteristicsFlagsValues = {0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000};
        string[] FileCharacteristicsFlagsNames  = {"0x0001 The file does not contain base relocations and must therefore be loaded at its preferred base address",
                                                   "0x0002 The image file is valid and can be run",
                                                   "0x0004 {\\b \\cf4 DEPRECATED! COFF line numbers have been removed}",
                                                   "0x0008 {\\b \\cf4 DEPRECATED! COFF symbol table entries for local symbols have been removed}",
                                                   "0x0010 {\\b \\cf4 OBSOLETE! Aggressively trim working set}",
                                                   "0x0020 Application can handle > 2 GB addresses",
                                                   "0x0040 {\\b \\cf3 ERROR! 0x0040 is reserved flag}",
                                                   "0x0080 {\\b \\cf4 DEPRECATED! Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory}",
                                                   "0x0100 Machine is based on a 32-bit-word architecture",
                                                   "0x0200 Debugging information is removed from the image file",
                                                   "0x0400 If the image is on removable media, fully load it and copy it to the swap file",
                                                   "0x0800 If the image is on network media, fully load it and copy it to the swap file",
                                                   "0x1000 The image file is a system file, not a user program",
                                                   "0x2000 The image file is a dynamic-link library (DLL)",
                                                   "0x4000 The file should be run only on a uniprocessor machine",
                                                   "0x8000 {\\b \\cf4 DEPRECATED! Big endian: the MSB precedes the LSB in memory}"};

        public void printFileCharacteristics(ushort ch)
        {
            if (FileCharacteristicsFlagsValues.Length != FileCharacteristicsFlagsNames.Length)
                throw new Exception();

            if ((IMAGE_FILE_EXECUTABLE_IMAGE & ch) == 0)
            {
                Alert("File do not marked as executable (must be both for dll and exe)");
            }
            else
                AL("File marked as executable");

            if ((IMAGE_FILE_FLAG_RESERVED & ch) != 0)
            {
                Alert("Reserved file flag characteristics 0x0040 is setted");
            }
            else
                AL("Reserved file flag characteristics 0x0040 is reset");

            vars.isDLL = (0x2000 & (int) ch) != 0;

            for (int i = 0; i < FileCharacteristicsFlagsValues.Length; i++)
            {
                if ((FileCharacteristicsFlagsValues[i] & ch) != 0)
                    ALi(FileCharacteristicsFlagsNames[i]);
            }
        }

        public struct A16S_struct
        {
            public string sa;
            public ulong   a;

            public override string ToString()
            {
                return sa;
            }
        }

        public A16S_struct A16S(long a, int sectionName = -1, AddressType addressType = AddressType.filePointer)
        {
            // Если нужно вернуть указатель на место в файле или rva относительно внесекционной информации - просто возвращаем указатель на место в файле
            if (addressType == AddressType.filePointer || (addressType == AddressType.rva && sectionName == -1))
                return new A16S_struct {sa = AddressTypePrefix[(int) addressType] + " " + A16(a), a = (ulong) a};

            throw new NotImplementedException();
            /*
            ulong correctedA;

            if (addressType == AddressType.rva)
            {
                if (baseAddresses.ContainsKey(sectionName))
                    correctedA = (ulong) a + baseAddresses[sectionName].rva - baseAddresses[sectionName].filePointer;
                else
                {
                    correctedA = 0;
                    Alert("- section for address not found: may be VALIDATOR ERROR"); // скорее всего - ошибка валидатора
                }
            }
            else
            {
                if (sectionName == -1)
                    correctedA = baseAddresses[sectionName].va;
                else
                    correctedA = baseAddresses[sectionName].rva - baseAddresses[sectionName].filePointer + baseAddresses[-1].va;
            }

            return new A16S_struct {sa = AddressTypePrefix[(int) addressType] + " " + A16(correctedA), a = correctedA};*/
        }

        public string A16(long a)
        {
            return "0x" + a.ToString("X");
        }
        
        public string A16(ulong a)
        {
            return "0x" + a.ToString("X");
        }

        public unsafe static void ByteToULong(out ulong data, byte[] target, long start)
        {
            data = 0;
            if (start < 0 || target.LongLength < start + 8)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + 8 - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }
        }

        public unsafe static ulong ByteToULong(byte[] target, long start)
        {
            ulong data = 0;
            if (start < 0 || target.LongLength < start + 8)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + 8 - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }

            return data;
        }

        public unsafe static ulong ByteToSizedInteger(byte[] target, long start, long size)
        {
            ulong data = 0;
            if (start < 0 || target.LongLength < start + size)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + size - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }

            return data;
        }

        public unsafe static void ByteToInt(out UInt32 data, byte[] target, long start)
        {
            data = 0;
            if (start < 0 || target.LongLength < start + 4)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + 4 - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }
        }

        public unsafe static UInt32 GetInt(byte[] target, long start)
        {
            UInt32 data = 0;
            if (start < 0 || target.LongLength < start + 4)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + 4 - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }

            return data;
        }

        public unsafe static void ByteToShort(out UInt16 data, byte[] target, long start)
        {
            data = 0;
            if (start < 0 || target.LongLength < start + 2)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + 2 - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }
        }

        public unsafe static UInt16 GetShort(byte[] target, long start)
        {
            UInt16 data = 0;
            if (start < 0 || target.LongLength < start + 2)
                throw new IndexOutOfRangeException();

            fixed (byte * t = target)
            {
                for (long i = start + 2 - 1; i >= start; i--)
                {
                    data <<= 8;
                    data += *(t + i);
                }
            }

            return data;
        }

        public static string GetASCIIString(byte[] source, long index, long size)
        {
            long len = size;
            for (int i = 0; i < size; i++)
            {
                if (source[i + index] == 0)
                {
                    len = i;
                    break;
                }
            }

            return Encoding.ASCII.GetString(GetBytes(source, index, len));
        }

        public static byte[] GetBytes(byte[] source, long index, long size)
        {
            byte[] result = new byte[size];

            CopyTo(source, result, 0, size, index);

            return result;
        }

        public unsafe static long CopyTo(byte[] source, byte[] target, long targetIndex = 0, long count = -1, long index = 0)
        {
            if (count < 0)
                count = source.LongLength;

            /*
            long firstUncopied = index + count;
            if (firstUncopied > source.Length)
                firstUncopied = source.Length;*/

            fixed (byte * s = source, t = target)
            {
                byte * se = s + source.LongLength;
                byte * te = t + target.LongLength;

                byte * sec = s + index       + count;
                byte * tec = t + targetIndex + count;

                byte * sbc = s + index;
                byte * tbc = t + targetIndex;

                if (sec > se)
                {
                    tec -= sec - se;
                    sec  = se;
                }

                if (tec > te)
                {
                    sec -= tec - te;
                    tec  = te;
                }

                if (tbc < t)
                    throw new ArgumentOutOfRangeException();

                if (sbc < s)
                    throw new ArgumentOutOfRangeException();

                if (sec - sbc != tec - tbc)
                    throw new OverflowException("BytesBuilder.CopyTo: fatal algorithmic error");


                ulong * sbw = (ulong *) sbc;
                ulong * tbw = (ulong *) tbc;

                ulong * sew = sbw + ((sec - sbc) >> 3);

                for (; sbw < sew; sbw++, tbw++)
                    *tbw = *sbw;

                byte toEnd = (byte) (  ((int) (sec - sbc)) & 0x7  );

                byte * sbcb = (byte *) sbw;
                byte * tbcb = (byte *) tbw;
                byte * sbce = sbcb + toEnd;

                for (; sbcb < sbce; sbcb++, tbcb++)
                    *tbcb = *sbcb;


                return sec - sbc;
            }

            /*
            for (long i = index; i < firstUncopied && (i + targetIndex) < target.LongLength; i++)
                target[i + targetIndex] = source[i];
            return 0;*/
        }

        volatile bool terminate = false;
        private void button2_Click(object sender, EventArgs e)
        {
            terminate = true;
        }

        public unsafe static void BytesToNull(byte[] bytes, long firstNotNull = long.MaxValue, long start = 0)
        {
            if (firstNotNull >= bytes.LongLength)
                firstNotNull = bytes.LongLength - 1;

            if (start < 0)
                start = 0;

            fixed (byte * b = bytes)
            {
                ulong * lb = (ulong *) (b + start);

                ulong * le = lb + ((firstNotNull - start) >> 3);

                for (; lb < le; lb++)
                    *lb = 0;

                byte toEnd = (byte) (  ((int) (firstNotNull - start)) & 0x7  );

                byte * bb = (byte *) lb;
                byte * be = bb + toEnd;

                for (; bb < be; bb++)
                    *bb = 0;
            }
        }
    }
}
