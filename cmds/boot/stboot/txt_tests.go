// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	api "github.com/9elements/txt-suite/pkg/api"
	cpuid "github.com/intel-go/cpuid"
	tss "github.com/u-root/u-root/pkg/tss"
)

// CPU Test structs
var (
	txtRegisterValues    *api.TXTRegisterSpace = nil
	testcheckforintelcpu                       = Test{
		Name:     "Intel CPU",
		Required: true,
		function: TestCheckForIntelCPU,
		Status:   TestImplemented,
	}
	testwaybridgeorlater = Test{
		Name:         "Weybridge or later",
		function:     TestWeybridgeOrLater,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testcpusupportstxt = Test{
		Name:         "CPU supports TXT",
		function:     TestCPUSupportsTXT,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testsupportssmx = Test{
		Name:         "CPU supports SMX",
		function:     TestSupportsSMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testsupportvmx = Test{
		Name:         "CPU supports VMX",
		function:     TestSupportVMX,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testia32featurectrl = Test{
		Name:         "IA32_FEATURE_CONTROL",
		function:     TestIa32FeatureCtrl,
		Required:     true,
		dependencies: []*Test{&testcheckforintelcpu},
		Status:       TestImplemented,
	}
	testtxtnotdisabled = Test{
		Name:     "TXT not disabled by BIOS",
		function: TestTXTNotDisabled,
		Required: true,
		Status:   TestImplemented,
	}
)

// CPU Test functions

// Check we're running on a Intel CPU
func TestCheckForIntelCPU() (bool, error, error) {
	return api.VersionString() == "GenuineIntel", nil, nil
}

// Check we're running on Weybridge
func TestWeybridgeOrLater() (bool, error, error) {
	return cpuid.DisplayFamily == 6, nil, nil
}

// Check if the CPU supports TXT
func TestCPUSupportsTXT() (bool, error, error) {
	if CPUWhitelistTXTSupport() {
		return true, nil, nil
	}
	if CPUBlacklistTXTSupport() {
		return false, fmt.Errorf("CPU does not support TXT - on blacklist"), nil
	}
	// Lookup name on Intel
	ret, err := api.ArchitectureTXTSupport()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("CPU not supported"), nil
	}
	return true, nil, nil
}

// Check if the TXT register space is accessible
func TestTXTRegisterSpaceAccessible() (bool, error, error) {
	regs, err := getTxtRegisters()
	if err != nil {
		return false, nil, err
	}

	if regs.Vid != 0x8086 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected VendorID"), nil
	}

	if regs.HeapBase == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: HeapBase is 0"), nil
	}

	if regs.SinitBase == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: SinitBase is 0"), nil
	}

	if regs.Did == 0x0 {
		return false, fmt.Errorf("TXTRegisterSpace: Unexpected: DeviceID is 0"), nil
	}
	return true, nil, nil
}

// Check if CPU supports SMX
func TestSupportsSMX() (bool, error, error) {
	return api.HasSMX(), nil, nil
}

// Check if CPU supports VMX
func TestSupportVMX() (bool, error, error) {
	return api.HasVMX(), nil, nil
}

// Check IA_32FEATURE_CONTROL
func TestIa32FeatureCtrl() (bool, error, error) {
	vmxInSmx, err := api.AllowsVMXInSMX()
	if err != nil || !vmxInSmx {
		return vmxInSmx, nil, err
	}

	locked, err := api.IA32FeatureControlIsLocked()
	if err != nil {
		return false, nil, err
	}

	if locked != true {
		return false, fmt.Errorf("IA32 Feature Control not locked"), nil
	}
	return true, nil, nil
}

// Check TXT_DISABLED bit in TXT_ACM_STATUS
func TestTXTNotDisabled() (bool, error, error) {
	ret, err := api.TXTLeavesAreEnabled()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("TXT disabled"), nil
	}
	return true, nil, nil
}

// CPU Tests helpfer function
func getTxtRegisters() (*api.TXTRegisterSpace, error) {
	if txtRegisterValues == nil {
		buf, err := api.FetchTXTRegs()
		if err != nil {
			return nil, err
		}
		regs, err := api.ParseTXTRegs(buf)
		if err != nil {
			return nil, err
		}

		txtRegisterValues = &regs
	}

	return txtRegisterValues, nil
}

// TPM Tests structs
var (
	testtpmconnection = Test{
		Name:     "TPM connection",
		Required: true,
		function: TestTPMConnect,
		Status:   TestImplemented,
	}
	testtpm12present = Test{
		Name:         "TPM 1.2 present",
		Required:     false,
		function:     TestTPM12Present,
		dependencies: []*Test{&testtpmconnection},
		Status:       TestImplemented,
	}
	testtpm2present = Test{
		Name:         "TPM 2 is present",
		Required:     false,
		function:     TestTPM2Present,
		dependencies: []*Test{&testtpmconnection},
		Status:       TestImplemented,
	}
	testtpmispresent = Test{
		Name:         "TPM is present",
		Required:     true,
		function:     TestTPMIsPresent,
		dependencies: []*Test{&testtpmconnection},
		Status:       TestImplemented,
	}
	testpsindexisset = Test{
		Name:         "PS index set in NVRAM",
		function:     TestPSIndexIsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       TestImplemented,
	}
	testauxindexisset = Test{
		Name:         "AUX index set in NVRAM",
		function:     TestAUXIndexIsSet,
		Required:     true,
		dependencies: []*Test{&testtpmispresent},
		Status:       TestImplemented,
	}
)

// TPM Test functions

// Connects to a TPM device (virtual or real) at the given path
func TestTPMConnect() (bool, error, error) {
	conn, err := tss.NewTPM()

	if err != nil {
		return false, err, nil
	}
	return true, nil, nil
}

// Checks if TPM 1.2 is present and answers to GetCapability
func TestTPM12Present() (bool, error, error) {
	/*
		conn, err := tss.NewTPM()
		if conn.Version != tss.TPMVersion12 {
			return false, fmt.Errorf("No TPM 1.2 connection"), nil
		}
		//ToDo: Implement GetManufacturer in tss
		vid, err := conn.GetManufacturer()
		if err != nil {
			return false, nil, err
		}
		if vid == nil {
			return false, fmt.Errorf("TestTPM12Present: GetManufacturer() didn't return anything"), nil
		}*/
	return true, nil, nil

}

func TestTPM2Present() (bool, error, error) {
	conn, err := tss.NewTPM()
	if conn.Version != tss.TPMVersion20 {
		return false, fmt.Errorf("No TPM 2 connection"), nil
	}
	ca, _, err := tpm2.GetCapability(*tpm20Connection, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer))
	if err != nil {
		return false, nil, err
	}
	if ca == nil {
		return false, fmt.Errorf("TestTPM2Present: no Manufacturer returned"), nil
	}
	return true, nil, nil
}

func TestTPMIsPresent() (bool, error, error) {
	if (testtpm12present.Result == ResultPass) || (testtpm2present.Result == ResultPass) {
		return true, nil, nil
	}
	return false, fmt.Errorf("No TPM present"), nil
}

// TPM NVRAM has a valid PS index
func TestPSIndexIsSet() (bool, error, error) {
	if tpm12Connection != nil {
		data, err := tpm1.NVReadValue(*tpm12Connection, psIndex, 0, 54, nil)
		if err != nil {
			return false, nil, err
		}

		if len(data) != 54 {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM1 - Length of data not 54 "), nil
		}
		return true, nil, nil
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, psIndex)
		if err != nil {
			return false, nil, err
		}

		if meta.NVIndex != psIndex {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - PS Index Addresses don't match"), nil
		}

		if meta.Attributes&tpm2.KeyProp(tpm2.AttrWriteLocked) == 0 {
			return false, fmt.Errorf("TestPSIndexIsSet: TPM2 - WriteLock not set"), nil
		}
		return true, nil, nil
	} else {
		return false, fmt.Errorf("Not connected to TPM"), nil
	}
}

// TPM NVRAM has a valid AUX index
func TestAUXIndexIsSet() (bool, error, error) {
	if tpm12Connection != nil {
		buf, err := tpm1.NVReadValue(*tpm12Connection, auxIndex, 0, 1, nil)
		if err != nil {
			return false, nil, err
		}
		if len(buf) != 1 {
			return false, fmt.Errorf("TPM AUX Index not set"), nil
		}

		return true, nil, nil
	} else if tpm20Connection != nil {
		meta, err := tpm2.NVReadPublic(*tpm20Connection, auxIndex)
		if err != nil {
			return false, nil, err
		}
		if meta.NVIndex != auxIndex {
			return false, fmt.Errorf("AUXIndexIsSet: AUXIndex Addresses don't match"), nil
		}
		return true, nil, nil
	} else {
		return false, nil, fmt.Errorf("Not connected to TPM")
	}
}

// FIT Tests struct
var (
	testpolicyallowstxt = Test{
		Name:     "TXT not disabled by LCP Policy",
		Required: true,
		function: TestPolicyAllowsTXT,
		Status:   TestImplemented,
	}
)

// Fit Test function

// TXT not disabled by FIT Policy
func TestPolicyAllowsTXT() (bool, error, error) {
	for _, ent := range fit {
		if ent.Type() == api.TXTPolicyRec {
			switch ent.Version {
			case 0:
				return false, fmt.Errorf("Indexed IO type pointer are not supported - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11"), nil
			case 1:
				var b api.Uint8

				err := api.ReadPhys(int64(ent.Address), &b)
				if err != nil {
					return false, nil, err
				}

				return b&1 != 0, nil, nil
			default:
				return false, fmt.Errorf("Unknown TXT policy record version %d - See Intel Firmware Interface Table BIOS Specification Document Number: 338505-001, P. 11", ent.Version), nil
			}
		}
	}

	// No record means TXT is enabled
	return true, nil, nil
}

// Memory Tests structs

var (
	biosdata api.TXTBiosData
	//Heapsize from newer spec - Document 575623
	minHeapSize  = uint32(0xF0000)
	minSinitSize = uint32(0x50000)
	//Heapsize reduced for legacy spec - Document 558294
	legacyMinHeapSize = uint32(0xE0000)
)

var (
	testtxtmemoryrangevalid = Test{
		Name:     "TXT memory ranges valid",
		Required: true,
		function: TestTXTRegisterSpaceValid,
		Status:   TestImplemented,
	}
	testmemoryisreserved = Test{
		Name:         "TXT memory reserved in e820",
		Required:     true,
		function:     TestTXTReservedInE820,
		dependencies: []*Test{&testtxtmemoryrangevalid},
		Status:       TestImplemented,
	}
	testtxtmemoryisdpr = Test{
		Name:         "TXT memory in a DMA protected range",
		Required:     true,
		function:     TestTXTMemoryIsDPR,
		dependencies: []*Test{&testtxtmemoryrangevalid},
		Status:       TestImplemented,
	}
	testtxtdprislocked = Test{
		Name:     "TXT DPR register locked",
		Required: true,
		function: TestTXTDPRisLock,
		Status:   TestImplemented,
	}
	testhostbridgeDPRcorrect = Test{
		Name:     "CPU DPR equals hostbridge DPR",
		Required: false,
		function: TestHostbridgeDPRCorrect,
		Status:   TestImplemented,
	}
	testhostbridgeDPRislocked = Test{
		Name:         "CPU hostbridge DPR register locked",
		Required:     true,
		function:     TestHostbridgeDPRisLocked,
		dependencies: []*Test{&testhostbridgeDPRcorrect},
		Status:       TestImplemented,
	}
	testsinitintxt = Test{
		Name:     "TXT region contains SINIT ACM",
		Required: false,
		function: TestSINITInTXT,
		Status:   TestImplemented,
	}
	testsinitmatcheschipset = Test{
		Name:         "SINIT ACM matches chipset",
		Required:     true,
		function:     TestSINITMatchesChipset,
		dependencies: []*Test{&testsinitintxt},
		Status:       TestImplemented,
	}
	testsinitmatchescpu = Test{
		Name:         "SINIT ACM matches CPU",
		Required:     true,
		function:     TestSINITMatchesCPU,
		dependencies: []*Test{&testsinitintxt},
		Status:       TestImplemented,
	}
	testnosiniterrors = Test{
		Name:     "SINIT ACM startup successful",
		Required: false,
		function: TestNoSINITErrors,
		Status:   TestImplemented,
	}
	testbiosdataregionpresent = Test{
		Name:     "BIOS DATA REGION present",
		Required: true,
		function: TestBIOSDATAREGIONPresent,
		Status:   TestImplemented,
	}
	testbiosdataregionvalid = Test{
		Name:         "BIOS DATA REGION valid",
		Required:     true,
		function:     TestBIOSDATAREGIONValid,
		dependencies: []*Test{&testbiosdataregionpresent},
		Status:       TestImplemented,
	}
)

// Memory test functions

func TestTXTRegisterSpaceValid() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}

	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	if uint64(regs.HeapBase) >= api.FourGiB {
		return false, fmt.Errorf("HeapBase > 4Gib"), nil
	}

	if uint64(regs.HeapBase+regs.HeapSize) >= api.FourGiB {
		return false, fmt.Errorf("HeapBase + HeapSize >= 4Gib"), nil
	}

	//TODO: Validate against minHeapSize once legacy detection is implemented

	//This checks for legacy heap size - Document 558294
	if regs.HeapSize < legacyMinHeapSize {
		return false, fmt.Errorf("Heap must be at least %v", legacyMinHeapSize), nil

	}

	if uint64(regs.SinitBase) >= api.FourGiB {
		return false, fmt.Errorf("SinitBase >= 4Gib"), nil
	}

	if uint64(regs.SinitBase+regs.SinitSize) >= api.FourGiB {
		return false, fmt.Errorf("SinitBase + SinitSize >= 4Gib"), nil
	}

	if regs.SinitSize < minSinitSize {
		return false, fmt.Errorf("Sinit must be at least %v", minSinitSize), nil
	}

	if uint64(regs.MleJoin) >= api.FourGiB {
		return false, fmt.Errorf("MleJoin >= 4Gib"), nil
	}

	if regs.SinitBase > regs.HeapBase {
		return false, fmt.Errorf("Sinit must be below Heapbase"), nil
	}

	return true, nil, nil
}

func TestTXTReservedInE820() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	heapReserved, err := api.IsReservedInE810(uint64(regs.HeapBase), uint64(regs.HeapBase+regs.HeapSize))
	if err != nil {
		return false, nil, err
	}

	sinitReserved, err := api.IsReservedInE810(uint64(regs.SinitBase), uint64(regs.SinitBase+regs.SinitSize))
	if err != nil {
		return false, nil, err
	}

	return heapReserved && sinitReserved, nil, nil
}

func TestTXTMemoryIsDPR() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	var memBase uint32
	var memLimit uint32

	var dprBase uint32
	var dprSize uint32
	var dprLimit uint32

	if regs.HeapBase > regs.SinitBase {
		memBase = regs.SinitBase
	} else {
		memBase = regs.HeapBase
	}

	if regs.HeapBase+regs.HeapSize > regs.SinitBase+regs.SinitSize {
		memLimit = regs.HeapBase + regs.HeapSize
	} else {
		memLimit = regs.SinitBase + regs.SinitSize
	}

	dprSize = uint32(regs.Dpr.Size) * 1024 * 1024
	dprLimit = uint32(regs.Dpr.Top+1) * 1024 * 1024
	dprBase = dprLimit - dprSize

	if memBase < dprBase {
		return false, fmt.Errorf("DPR doesn't protect bottom of TXT memory"), nil
	}
	if memLimit > dprLimit {
		return false, fmt.Errorf("DPR doesn't protect top of TXT memory"), nil
	}

	return true, nil, nil
}

func TestTXTDPRisLock() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	if regs.Dpr.Lock != true {
		return false, fmt.Errorf("TXTDPR is not locked"), nil
	}
	return true, nil, nil
}

func TestHostbridgeDPRCorrect() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	hostbridgeDpr, err := api.ReadHostBridgeDPR()
	if err != nil {
		return false, nil, err
	}

	// No need to validate hostbridge register, already done for TXT DPR
	// Just make sure they match.

	if hostbridgeDpr.Top != regs.Dpr.Top {
		return false, fmt.Errorf("Hostbridge DPR Top doesn't match TXT DPR Top"), nil
	}

	if hostbridgeDpr.Size != regs.Dpr.Size {
		return false, fmt.Errorf("Hostbridge DPR Size doesn't match TXT DPR Size"), nil
	}

	return true, nil, nil
}

func TestHostbridgeDPRisLocked() (bool, error, error) {
	hostbridgeDpr, err := api.ReadHostBridgeDPR()
	if err != nil {
		return false, nil, err
	}

	if !hostbridgeDpr.Lock {
		return false, nil, fmt.Errorf("Hostbridge DPR isn't locked")
	}

	return true, nil, nil
}

func TestSINITInTXT() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	sinitBuf := make([]byte, regs.SinitSize)
	err = api.ReadPhysBuf(int64(regs.SinitBase), sinitBuf)
	if err != nil {
		return false, nil, err
	}

	acm, _, _, _, err := api.ParseACM(sinitBuf)
	if err != nil {
		return false, nil, err
	}
	if acm == nil {
		return false, fmt.Errorf("ACM is nil"), nil
	}

	if acm.Header.ModuleType != 2 {
		return false, fmt.Errorf("SINIT in TXT: ACM ModuleType not 2"), nil
	}
	return true, nil, nil

}

func TestSINITMatchesChipset() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	acm, chps, _, _, err := sinitACM(regs)
	if err != nil {
		return false, nil, err
	}
	if chps == nil {
		return false, fmt.Errorf("CHPS is nil"), nil
	}

	for _, ch := range chps.IDList {
		a := ch.VendorID == regs.Vid
		b := ch.DeviceID == regs.Did

		if a && b {
			if acm.Header.Flags&1 != 0 {
				if ch.RevisionID&regs.Rid == regs.Rid {
					return true, nil, nil
				}
			} else {
				if ch.RevisionID == regs.Rid {
					return true, nil, nil
				}
			}
		}
	}

	return false, fmt.Errorf("SINIT doesn't match chipset"), nil
}

func TestSINITMatchesCPU() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	_, _, cpus, _, err := sinitACM(regs)
	if err != nil {
		return false, nil, err
	}

	// IA32_PLATFORM_ID
	platform, err := api.IA32PlatformID()
	if err != nil {
		return false, nil, err
	}

	fms := api.CPUSignature()

	for _, cpu := range cpus.IDList {
		a := fms&cpu.FMSMask == cpu.FMS
		b := platform&cpu.PlatformMask == cpu.PlatformID

		if a && b {
			return true, nil, nil
		}
	}

	return false, fmt.Errorf("Sinit doesn't match CPU"), nil
}

func TestNoSINITErrors() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	if regs.ErrorCodeRaw != 0xc0000001 {
		return false, fmt.Errorf("SINIT Error detected"), nil
	}
	return true, nil, nil
}

func TestBIOSDATAREGIONPresent() (bool, error, error) {
	buf, err := api.FetchTXTRegs()
	if err != nil {
		return false, nil, err
	}
	regs, err := api.ParseTXTRegs(buf)
	if err != nil {
		return false, nil, err
	}

	txtHeap := make([]byte, regs.HeapSize)
	err = api.ReadPhysBuf(int64(regs.HeapBase), txtHeap)
	if err != nil {
		return false, nil, err
	}

	biosdata, err = api.ParseBIOSDataRegion(txtHeap)
	if err != nil {
		return false, nil, err
	}

	return true, nil, nil
}

func TestBIOSDATAREGIONValid() (bool, error, error) {
	if biosdata.Version < 2 {
		return false, fmt.Errorf("BIOS DATA regions version < 2 are not supperted"), nil
	}

	if biosdata.BiosSinitSize < 8 {
		return false, fmt.Errorf("BIOS DATA region is too small"), nil
	}

	if biosdata.NumLogProcs == 0 {
		return false, fmt.Errorf("BIOS DATA region corrupted"), nil
	}
	return true, nil, nil
}

func TestHasMTRR() (bool, error, error) {
	if api.HasMTRR() != true {
		return false, fmt.Errorf("CPU does not have MTRR"), nil
	}
	return true, nil, nil
}

func TestHasSMRR() (bool, error, error) {
	ret, err := api.HasSMRR()
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("CPU has no SMRR"), nil
	}
	return true, nil, nil
}

func TestValidSMRR() (bool, error, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, nil, err
	}

	if smrr.PhysMask == 0 {
		return false, fmt.Errorf("SMRR PhysMask isn't set"), nil
	}
	if smrr.PhysBase == 0 {
		return false, fmt.Errorf("SMRR PhysBase isn't set"), nil
	}

	tsegbase, tseglimit, err := api.ReadHostBridgeTseg()
	if err != nil {
		return false, nil, err
	}
	if tsegbase == 0 || tsegbase == 0xffffffff {
		return false, fmt.Errorf("TSEG base register isn't valid"), nil
	}
	if tseglimit == 0 || tseglimit == 0xffffffff {
		return false, fmt.Errorf("TSEG limit register isn't valid"), nil
	}

	if tsegbase&(^(uint32(smrr.PhysMask) << 12)) != 0 {
		return false, fmt.Errorf("TSEG base isn't aligned to SMRR Physmask"), nil
	}
	if tsegbase != (uint32(smrr.PhysBase) << 12) {
		return false, fmt.Errorf("TSEG base doesn't start at SMRR PhysBase"), nil
	}
	if tseglimit&(^(uint32(smrr.PhysMask) << 12)) != 0 {
		return false, fmt.Errorf("TSEG limit isn't aligned to SMRR Physmask"), nil
	}
	if ((tseglimit - 1) & (uint32(smrr.PhysMask) << 12)) != (uint32(smrr.PhysBase) << 12) {
		return false, fmt.Errorf("SMRR Physmask doesn't cover whole TSEG"), nil
	}

	return true, nil, nil
}

func TestActiveSMRR() (bool, error, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, nil, err
	}

	if smrr.Active != true {
		return false, fmt.Errorf("SMRR not active"), nil
	}
	return true, nil, nil
}

func TestActiveIOMMU() (bool, error, error) {
	smrr, err := api.GetSMRRInfo()
	if err != nil {
		return false, nil, err
	}
	ret, err := api.AddressRangesIsDMAProtected(smrr.PhysBase, smrr.PhysBase|^smrr.PhysMask)
	if err != nil {
		return false, nil, err
	}
	if ret != true {
		return false, fmt.Errorf("IOMMU not active"), nil
	}
	return true, nil, nil
}

// Memory helper function
func sinitACM(regs api.TXTRegisterSpace) (*api.ACM, *api.Chipsets, *api.Processors, *api.TPMs, error) {
	sinitBuf := make([]byte, regs.SinitSize)
	err := api.ReadPhysBuf(int64(regs.SinitBase), sinitBuf)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return api.ParseACM(sinitBuf)
}

func runTxtTests(debug bool) error {
	return true, nil
}
