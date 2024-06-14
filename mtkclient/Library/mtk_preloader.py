#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023 GPLv3 License
import os
import logging
import time
from enum import Enum
from struct import unpack, pack
from binascii import hexlify

from Cryptodome.Util.number import bytes_to_long, long_to_bytes, ceil_div, size
from Cryptodome.PublicKey import RSA

import mtkclient.Library.settings
from mtkclient.Library.utils import LogBase, logsetup
from mtkclient.Library.error import ErrorHandler
from mtkclient.config.brom_config import damodes

USBDL_BIT_EN = 0x00000001  # 1: download bit enabled
USBDL_BROM = 0x00000002  # 0: usbdl by brom; 1: usbdl by bootloader
USBDL_TIMEOUT_MASK = 0x0000FFFC  # 14-bit timeout: 0x0000~0x3FFE: second; 0x3FFFF: no timeout
USBDL_TIMEOUT_MAX = (USBDL_TIMEOUT_MASK >> 2)  # maximum timeout indicates no timeout
USBDL_MAGIC = 0x444C0000  # Brom will check this magic number
MISC_LOCK_KEY_MAGIC = 0xAD98


def customizedSign(n, e, msg):
    modBits = size(n)
    k = ceil_div(modBits, 8)

    ps = b'\xFF' * (k - len(msg) - 3)
    em = b'\x00\x01' + ps + b'\x00' + msg

    em_int = bytes_to_long(em)
    m_int = pow(em_int, e, n)
    signature = long_to_bytes(m_int, k)

    return signature


def generate_rsa_challenge(n, e, data):
    for i in range(0, len(data), 2):
        data[i], data[i + 1] = data[i + 1], data[i]
    msg = bytearray(customizedSign(n, e, data))
    for i in range(0, len(msg), 2):
        msg[i], msg[i + 1] = msg[i + 1], msg[i]
    return msg


def calc_xflash_checksum(data):
    checksum = 0
    pos = 0
    for i in range(0, len(data) // 4):
        checksum += unpack("<I", data[i * 4:(i * 4) + 4])[0]
        pos += 4
    if len(data) % 4 != 0:
        for i in range(4 - (len(data) % 4)):
            checksum += data[pos]
            pos += 1
    return checksum & 0xFFFFFFFF


class Preloader(metaclass=LogBase):
    class Rsp(Enum):
        NONE = b''
        CONF = b'\x69'
        STOP = b'\x96'
        ACK = b'\x5A'
        NACK = b'\xA5'

    class Cap(Enum):
        PL_CAP0_XFLASH_SUPPORT = (0x1 << 0)
        PL_CAP0_MEID_SUPPORT = (0x1 << 1)
        PL_CAP0_SOCID_SUPPORT = (0x1 << 2)

    class Cmd(Enum):
        # if CFG_PRELOADER_AS_DA
        SEND_PARTITION_DATA = b"\x70"
        JUMP_TO_PARTITION = b"\x71"

        CHECK_USB_CMD = b"\x72"
        STAY_STILL = b"\x80"
        CMD_88 = b"\x88"
        CMD_READ16_A2 = b"\xA2"

        I2C_INIT = b"\xB0"
        I2C_DEINIT = b"\xB1"
        I2C_WRITE8 = b"\xB2"
        I2C_READ8 = b"\xB3"
        I2C_SET_SPEED = b"\xB4"
        I2C_INIT_EX = b"\xB6"
        I2C_DEINIT_EX = b"\xB7"  # JUMP_MAUI
        I2C_WRITE8_EX = b"\xB8"  # READY
        """
        / Boot-loader resposne from BLDR_CMD_READY (0xB8)
        STATUS_READY                0x00        // secure RO is found and ready to serve
        STATUS_SECURE_RO_NOT_FOUND  0x01        // secure RO is not found: first download? => dead end...
        STATUS_SUSBDL_NOT_SUPPORTED 0x02        // BL didn't enable Secure USB DL
        """
        I2C_READ8_EX = b"\xB9"
        I2C_SET_SPEED_EX = b"\xBA"
        GET_MAUI_FW_VER = b"\xBF"

        OLD_SLA_SEND_AUTH = b"\xC1"
        OLD_SLA_GET_RN = b"\xC2"
        OLD_SLA_VERIFY_RN = b"\xC3"
        PWR_INIT = b"\xC4"
        PWR_DEINIT = b"\xC5"
        PWR_READ16 = b"\xC6"
        PWR_WRITE16 = b"\xC7"
        CMD_C8 = b"\xC8"  # Cache control

        READ16 = b"\xD0"
        READ32 = b"\xD1"
        WRITE16 = b"\xD2"
        WRITE16_NO_ECHO = b"\xD3"
        WRITE32 = b"\xD4"
        JUMP_DA = b"\xD5"
        JUMP_BL = b"\xD6"
        SEND_DA = b"\xD7"
        GET_TARGET_CONFIG = b"\xD8"
        SEND_ENV_PREPARE = b"\xD9"
        brom_register_access = b"\xDA"
        UART1_LOG_EN = b"\xDB"
        UART1_SET_BAUDRATE = b"\xDC",  # RE
        BROM_DEBUGLOG = b"\xDD",  # RE
        JUMP_DA64 = b"\xDE",  # RE
        GET_BROM_LOG_NEW = b"\xDF",  # RE

        SEND_CERT = b"\xE0",  # DA_CHK_PC_SEC_INFO_CMD
        GET_ME_ID = b"\xE1"
        SEND_AUTH = b"\xE2"
        SLA = b"\xE3"
        CMD_E4 = b"\xE4"  # returns 0x703A
        CMD_E5 = b"\xE5"  # echo cmd, dword = dword, then returns 0x7054 as status
        CMD_E6 = b"\xE6"  # returns 0x7054
        GET_SOC_ID = b"\xE7"
        CMD_E8 = b"\xE8"  # return 0x100A00 cert content and check similar to SLA
        ZEROIZATION = b"\xF0"
        GET_PL_CAP = b"\xFB"
        CMD_FA = b"\xFA"
        GET_HW_SW_VER = b"\xFC"
        GET_HW_CODE = b"\xFD"
        GET_BL_VER = b"\xFE"
        GET_VERSION = b"\xFF"

    def __init__(self, mtk, loglevel=logging.INFO):
        self.mtk = mtk
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.eh = ErrorHandler()
        self.gcpu = None
        self.config = mtk.config
        self.display = True
        self.rbyte = self.mtk.port.rbyte
        self.rword = self.mtk.port.rword
        self.rdword = self.mtk.port.rdword
        self.usbread = self.mtk.port.usbread
        self.usbwrite = self.mtk.port.usbwrite
        self.echo = self.mtk.port.echo
        self.sendcmd = self.mtk.port.mtk_cmd

    def init(self, maxtries=None, display=True):
        if os.path.exists(os.path.join(self.mtk.config.hwparam_path, ".state")):
            try:
                os.remove(os.path.join(self.mtk.config.hwparam_path, ".state"))
                os.remove(os.path.join(self.mtk.config.hwparam_path, "hwparam.json"))
            except OSError:
                pass
        readsocid = self.config.readsocid
        skipwdt = self.config.skipwdt

        self.info("Status: Waiting for PreLoader VCOM, please reconnect mobile to brom mode")
        self.config.set_gui_status(self.config.tr("Status: Waiting for connection"))
        res = False
        maxtries = 100
        tries = 0
        while not res and tries < 1000:
            if self.mtk.serialportname:
                res = self.mtk.port.serial_handshake(maxtries=maxtries)
            else:
                res = self.mtk.port.handshake(maxtries=maxtries)
            if not res:
                if display:
                    self.error("Status: Handshake failed, retrying...")
                    self.config.set_gui_status(self.config.tr("Status: Handshake failed, retrying..."))
                self.mtk.port.close()
                tries += 1
        if tries == 1000:
            return False

        if self.config.iot:
            self.config.hwver = self.read_a2(0x80000000)
            self.config.hwcode = self.read_a2(0x80000008)
            self.config.hw_sub_code = self.read_a2(0x8000000C)
            self.config.swver = (self.read32(0xA01C0108) & 0xFFFF0000) >> 16
        else:
            if not self.echo(self.Cmd.GET_HW_CODE.value):  # 0xFD
                if not self.echo(self.Cmd.GET_HW_CODE.value):
                    self.error("Sync error. Please power off the device and retry.")
                    self.config.set_gui_status(self.config.tr("Sync error. Please power off the device and retry."))
                return False
            else:
                val = self.rdword()
                self.config.hwcode = (val >> 16) & 0xFFFF
                self.config.hwver = val & 0xFFFF
                self.config.init_hwcode(self.config.hwcode)
        self.config.init_hwcode(self.config.hwcode)

        cpu = self.config.chipconfig.name
        if self.display:
            self.info("\tCPU:\t\t\t" + cpu + "(" + self.config.chipconfig.description + ")")
            self.config.cpu = cpu.replace("/", "_")
            self.info("\tHW version:\t\t" + hex(self.config.hwver))
            self.info("\tWDT:\t\t\t" + hex(self.config.chipconfig.watchdog))
            self.info("\tUart:\t\t\t" + hex(self.config.chipconfig.uart))
            self.info("\tBrom payload addr:\t" + hex(self.config.chipconfig.brom_payload_addr))
            self.info("\tDA payload addr:\t" + hex(self.config.chipconfig.da_payload_addr))
            if self.config.chipconfig.cqdma_base is not None:
                self.info("\tCQ_DMA addr:\t\t" + hex(self.config.chipconfig.cqdma_base))
            self.info("\tVar1:\t\t\t" + hex(self.config.chipconfig.var1))

        if not skipwdt:
            if self.display:
                self.info("Disabling Watchdog...")
            self.setreg_disablewatchdogtimer(self.config.hwcode, self.config.hwver)  # D4
        if self.display:
            self.info("HW code:\t\t\t" + hex(self.config.hwcode))
        self.config.target_config = self.get_target_config(self.display)
        self.info("Get Target info")
        self.get_blver()
        self.get_bromver()
        if not self.config.iot:
            res = self.get_hw_sw_ver()
            self.config.hw_sub_code = 0
            self.config.hwver = 0
            self.config.swver = 0
            if res != -1:
                self.config.hw_sub_code = res[0]
                self.config.hwver = res[1]
                self.config.swver = res[2]
        if self.display:
            self.info("\tHW subcode:\t\t" + hex(self.config.hw_sub_code))
            self.info("\tHW Ver:\t\t\t" + hex(self.config.hwver))
            self.info("\tSW Ver:\t\t\t" + hex(self.config.swver))
        meid = self.get_meid()
        if meid is not None:
            self.config.set_meid(meid)
            if self.display:
                self.info("ME_ID:\t\t\t" + hexlify(meid).decode('utf-8').upper())
            if readsocid or self.config.chipconfig.socid_addr:
                socid = self.get_socid()
                if len(socid) >= 16:
                    self.config.set_socid(socid)
                if self.display:
                    if socid != b"":
                        self.info("SOC_ID:\t\t\t" + hexlify(socid).decode('utf-8').upper())
        if self.config.auth is not None and self.config.is_brom and self.config.target_config["daa"]:
            if os.path.exists(self.config.auth):
                authdata = open(self.config.auth, "rb").read()
                self.send_auth(authdata)
            else:
                self.error(f"Couldn't find auth file {self.config.auth}")
        if self.config.cert is not None and self.config.is_brom and self.config.target_config["daa"]:
            if os.path.exists(self.config.cert):
                certdata = open(self.config.cert, "rb").read()
                self.send_root_cert(certdata)
            else:
                self.error(f"Couldn't find cert file {self.config.cert}")
        if self.config.target_config["sla"] and self.config.chipconfig.damode == damodes.XML:
            self.handle_sla(func=None, isbrom=self.config.is_brom)
        return True

    def read_a2(self, addr, dwords=1) -> list:
        cmd = self.Cmd.CMD_READ16_A2
        if self.echo(cmd.value):
            if self.echo(pack(">I", addr)):
                # ack =
                self.echo(pack(">I", dwords))
                return unpack(">H", self.usbread(2))[0]
        return []

    def read(self, addr, dwords=1, length=32) -> list:
        result = []
        cmd = self.Cmd.READ16 if length == 16 else self.Cmd.READ32
        if self.echo(cmd.value):
            if self.echo(pack(">I", addr)):
                ack = self.echo(pack(">I", dwords))
                status = self.rword()
                if ack and status <= 0xFF:
                    if length == 32:
                        result = self.rdword(dwords)
                    else:
                        result = self.rword(dwords)
                    status2 = unpack(">H", self.usbread(2))[0]
                    if status2 <= 0xFF:
                        return result
                else:
                    self.error(self.eh.status(status))
        return result

    def read32(self, addr, dwords=1) -> (list, int):
        return self.read(addr, dwords, 32)

    def read16(self, addr, dwords=1) -> (list, int):
        return self.read(addr, dwords, 16)

    def write(self, addr, values, length=32) -> bool:
        cmd = self.Cmd.WRITE16 if length == 16 else self.Cmd.WRITE32
        packfmt = ">H" if length == 16 else ">I"

        if isinstance(values, int):
            values = [values]
        if self.echo(cmd.value):
            if self.echo(pack(">I", addr)):
                ack = self.echo(pack(">I", len(values)))
                status = self.rword()
                if status > 0xFF:
                    self.error(f"Error on da_write{length}, addr {hex(addr)}, {self.eh.status(status)}")
                    return False
                if ack and status <= 3:
                    for val in values:
                        if not self.echo(pack(packfmt, val)):
                            break
                    status2 = self.rword()
                    if status2 <= 0xFF:
                        return True
                    else:
                        self.error(f"Error on da_write{length}, addr {hex(addr)}, {self.eh.status(status2)}")
            else:
                self.error(f"Error on da_write{length}, addr {hex(addr)}, write address")
        else:
            self.error(f"Error on da_write{length}, addr {hex(addr)}, send cmd")
        return False

    def write16(self, addr, words) -> bool:
        return self.write(addr, words, 16)

    def write32(self, addr, dwords) -> bool:
        return self.write(addr, dwords, 32)

    def writemem(self, addr, data):
        for i in range(0, len(data), 4):
            value = data[i:i + 4]
            while len(value) < 4:
                value += b"\x00"
            self.write32(addr + i, unpack("<I", value))

    def reset_to_brom(self, en=True, timeout=0):
        usbdlreg = 0

        # if anything is wrong and caused wdt reset, enter bootrom download mode #
        timeout = USBDL_TIMEOUT_MAX if timeout == 0 else timeout // 1000
        timeout <<= 2
        timeout &= USBDL_TIMEOUT_MASK  # usbdl timeout cannot exceed max value

        usbdlreg |= timeout
        if en:
            usbdlreg |= USBDL_BIT_EN
        else:
            usbdlreg &= ~USBDL_BIT_EN

        usbdlreg &= ~USBDL_BROM
        # Add magic number for MT6582
        usbdlreg |= USBDL_MAGIC  # | 0x444C0000

        # set BOOT_MISC0 as watchdog resettable
        RST_CON = self.config.chipconfig.misc_lock + 8
        USBDL_FLAG = self.config.chipconfig.misc_lock - 0x20
        self.write32(self.config.chipconfig.misc_lock, MISC_LOCK_KEY_MAGIC)
        self.write32(RST_CON, 1)
        self.write32(self.config.chipconfig.misc_lock, 0)
        self.write32(USBDL_FLAG, usbdlreg)
        return

    def run_ext_cmd(self, cmd: bytes = b"\xB1"):
        self.usbwrite(self.Cmd.CMD_C8.value)
        assert self.usbread(1) == self.Cmd.CMD_C8.value
        self.usbwrite(cmd)
        assert self.usbread(1) == cmd
        self.usbread(1)
        self.usbread(2)

    def jump_bl(self):
        if self.echo(self.Cmd.JUMP_BL.value):
            status = self.rword()
            if status <= 0xFF:
                status2 = self.rword()
                if status2 <= 0xFF:
                    return True
        return False

    def jump_to_partition(self, partitionname):
        if isinstance(partitionname, str):
            partitionname = bytes(partitionname, 'utf-8')[:64]
        partitionname = partitionname + (64 - len(partitionname)) * b'\x00'
        if self.echo(self.Cmd.JUMP_TO_PARTITION.value):
            self.usbwrite(partitionname)
            status2 = self.rword()
            if status2 <= 0xFF:
                return True

    def send_partition_data(self, partitionname, data):
        checksum = calc_xflash_checksum(data)
        if isinstance(partitionname, str):
            partitionname = bytes(partitionname, 'utf-8')[:64]
        partitionname = partitionname + (64 - len(partitionname)) * b'\x00'
        if self.echo(self.Cmd.SEND_PARTITION_DATA.value):
            self.usbwrite(partitionname)
            self.usbwrite(pack(">I", len(data)))
            status = self.rword()
            if status <= 0xFF:
                length = len(data)
                pos = 0
                while length > 0:
                    dsize = min(length, 0x200)
                    if not self.usbwrite(data[pos:pos + dsize]):
                        break
                    pos += dsize
                    length -= dsize
                # self.usbwrite(data)
                self.usbwrite(pack(">I", checksum))

    def setreg_disablewatchdogtimer(self, hwcode, hwver):
        """
        SetReg_DisableWatchDogTimer; BRom_WriteCmd32(): Reg 0x10007000[1]={ Value 0x22000000 }.
        """
        addr, value = self.config.get_watchdog_addr()

        if hwcode == 0x6261:
            # Disable watchdog timer
            # MT2503
            if hwver == 0xca02:
                # PMU
                # self.write16(0xA0700F00, 0x41)
                # self.write16(0xA0700F00, 0x51)
                # self.write16(0xA0700F00, 0x41)

                # GPIO
                # self.write32(0xA0020318,0x2000)     # GPIO_DOUT1_SET, GPIO45
                # self.write32(0xA0020014, 0x2000)    # GPIO_DIR1_SET, GPIO45
                # self.write32(0xA0020C58, 0x700000)  # GPIO_MODE5_CLR, GPIO45 TESTMODE_D

                # PMU
                # SetReg_MinuteLevelChargerWDT
                # self.write16(0xA0700A24, 0x15)
                # SetReg_DisableBAT_ON_Protection
                # self.write16(0xA0700A14, 0x6001)
                # SetReg_OV_Level
                # self.write16(0xA0700A14, 0x6041)
                # SetReg_USBDL_ChargerCurrent
                # self.write16(0xA0700A08, 0x10B)
                # SetReg_EnableChargeControlToNormalMode
                # self.write16(0xA0700A00, 0xF27A)
                # SetReg_HWAutoFChargeModeToNormalMode
                # self.write16(0xA0700A28, 0x8010)

                # Disable watchdog
                self.write16(0xA0030000, 0x2200)

                # SetLSRSTB
                # self.write16(0xA0020318, 0x2000)
                # self.write16(0xA0020014, 0x2000)
                # self.write32(0xA0020C58, 0x700000)

                # SetupRTC32K
                # self.write16(0xA071004C, 0x1A57)
                # self.write16(0xA071004C, 0x2B68)
                # self.write16(0xA071004C, 0x407)

                # self.write16(0xA0710010, 0x0)
                # self.write16(0xA0710008, 0x0)
                # self.write16(0xA071000C, 0x0)
                # self.write16(0xA0710074, 0x1)

                # RTC Unlock
                # self.write16(0xA0710068, 0x586A)
                # self.write16(0xA0710074, 1)
                # self.write16(0xA0710068, 0x9136)
                # self.write16(0xA0710074, 1)

                # self.write16(0xA0710000, 0x430E)
                # self.write16(0xA0710074, 0x1)

                # SetRemap:
                # BootEngine
                # set external boot , remap control change to Bus
                # Set MB0 to Bank0 and MB1 to Bank1
                self.write32(0xA0510000, self.read32(0xA0510000, 1) | 2)
            else:
                self.write16(0xA0030000, 0x2200)
            res = True

        elif hwcode in [0x6575, 0x6577]:
            """
            SoCs which share the same watchdog IP as mt6577 must use 16-bit I/O.
            For example: mt6575, mt8317 and mt8377 (their hwcodes are 0x6575).
            """
            res = self.write16(addr, value)
        else:
            res = self.write32(addr, value)
            if res and hwcode == 0x6592:
                """
                mt6592 has an additional watchdog register at 0x10000500.
                TODO: verify if writing to this register is actually needed.
                """
                res = self.write32(0x10000500, 0x22000000)
        if not res:
            self.error("Received wrong SetReg_DisableWatchDogTimer response")
            return False
        else:
            return True

    def get_bromver(self):
        if self.usbwrite(self.Cmd.GET_VERSION.value):
            res = self.usbread(1)
            self.mtk.config.bromver = unpack("B", res)[0]
            return self.mtk.config.bromver
        return -1

    def get_blver(self):
        if self.usbwrite(self.Cmd.GET_BL_VER.value):
            res = self.usbread(1)
            if res == self.Cmd.GET_BL_VER.value:
                # We are in boot rom ...
                self.info("BROM mode detected.")
            self.mtk.config.blver = unpack("B", res)[0]
            return self.mtk.config.blver
        return -1

    def get_target_config(self, display=True):
        if self.echo(self.Cmd.GET_TARGET_CONFIG.value):
            target_config, status = unpack(">IH", self.rbyte(6))
            sbc = True if (target_config & 0x1) else False
            sla = True if (target_config & 0x2) else False
            daa = True if (target_config & 0x4) else False
            swjtag = True if (target_config & 0x6) else False
            epp = True if (target_config & 0x8) else False
            cert = True if (target_config & 0x10) else False
            memread = True if (target_config & 0x20) else False
            memwrite = True if (target_config & 0x40) else False
            cmd_c8 = True if (target_config & 0x80) else False
            if display:
                self.info(f"Target config:\t\t{hex(target_config)}")
                self.info(f"\tSBC enabled:\t\t{sbc}")
                self.info(f"\tSLA enabled:\t\t{sla}")
                self.info(f"\tDAA enabled:\t\t{daa}")
                self.info(f"\tSWJTAG enabled:\t\t{swjtag}")
                self.info(f"\tEPP_PARAM at 0x600 after EMMC_BOOT/SDMMC_BOOT:\t{epp}")
                self.info(f"\tRoot cert required:\t{cert}")
                self.info(f"\tMem read auth:\t\t{memread}")
                self.info(f"\tMem write auth:\t\t{memwrite}")
                self.info(f"\tCmd 0xC8 blocked:\t{cmd_c8}")

            if status > 0xff:
                raise Exception("Get Target Config Error")
            return {"sbc": sbc, "sla": sla, "daa": daa, "epp": epp, "cert": cert,
                    "memread": memread, "memwrite": memwrite, "cmdC8": cmd_c8}
        else:
            self.warning("CMD Get_Target_Config not supported.")
            return {"sbc": False, "sla": False, "daa": False, "epp": False, "cert": False,
                    "memread": False, "memwrite": False, "cmdC8": False}

    def jump_da(self, addr):
        self.info(f"Jumping to {hex(addr)}")
        self.config.set_gui_status(self.config.tr(f"Jumping to {hex(addr)}"))
        if self.echo(self.Cmd.JUMP_DA.value):
            self.usbwrite(pack(">I", addr))
            data = b""
            try:
                resaddr = self.rdword()
            except Exception as e:
                self.error(f"Jump_DA Resp2 {str(e)} ," + hexlify(data).decode('utf-8'))
                self.config.set_gui_status(self.config.tr("DA Error"))
                return False
            if resaddr == addr:
                try:
                    status = self.rword()
                except Exception as e:
                    self.error(f"Jump_DA No data available {str(e)} ," + hexlify(data).decode('utf-8'))
                    self.config.set_gui_status(self.config.tr("DA Error"))
                    return False
                if status == 0:
                    self.info(f"Jumping to {hex(addr)}: ok.")
                    self.config.set_gui_status(self.config.tr(f"Jumping to {hex(addr)}: ok."))
                    return True
            self.error(f"Jump_DA status error:{self.eh.status(status)}")
            self.config.set_gui_status(self.config.tr("DA Error"))
        return False

    def jump_da64(self, addr: int):
        if self.echo(self.Cmd.JUMP_DA64.value):
            self.usbwrite(pack(">I", addr))
            try:
                resaddr = self.rdword()
            except Exception as e:
                self.error(f"Jump_DA Resp2 {str(e)} , addr {hex(addr)}")
                return False
            if resaddr == addr:
                self.echo(b"\x01")  # for 64Bit, 0 for 32Bit
                try:
                    status = self.rword()
                except Exception as e:
                    self.error(f"Jump_DA Resp2 {str(e)} , addr {hex(addr)}")
                    return False
                if status == 0:
                    return True
                else:
                    self.error(f"Jump_DA64 status error:{self.eh.status(status)}")
        return False

    def uart1_log_enable(self):
        if self.echo(self.Cmd.UART1_LOG_EN):
            status = self.rword()
            if status == 0:
                return True
            else:
                self.error(f"Uart1 log enable error:{self.eh.status(status)}")
        return False

    def uart1_set_baud(self, baudrate):
        if self.echo(self.Cmd.UART1_SET_BAUDRATE.value):
            self.usbwrite(pack(">I", baudrate))
            status = self.rword()
            if status == 0:
                return True
            else:
                self.error(f"Uart1 set baudrate error:{self.eh.status(status)}")
        return False

    def send_root_cert(self, cert):
        gen_chksum, data = self.prepare_data(b"", cert)
        if self.echo(self.Cmd.SEND_CERT.value):
            if self.echo(pack(">I", len(data))):
                status = self.rword()
                if 0x0 <= status <= 0xFF:
                    if not self.upload_data(cert, gen_chksum):
                        self.error("Error on uploading certificate.")
                        return False
                    return True
                self.error(f"Send cert error:{self.eh.status(status)}")
        return False

    def send_auth(self, auth):
        gen_chksum, data = self.prepare_data(data=auth, sigdata=b"", maxsize=len(auth))
        if self.echo(self.Cmd.SEND_AUTH.value):
            length = len(data)
            self.usbwrite(int.to_bytes(length, 4, 'big'))
            rlen = self.rdword()
            if rlen != length:
                return False
            self.config.set_gui_status(self.config.tr("Uploading data."))
            status = self.rword()
            if status < 0xFF:
                bytestowrite = len(data)
                pos = 0
                while bytestowrite > 0:
                    size = min(bytestowrite, 64)
                    self.usbwrite(data[pos:pos + size])
                    bytestowrite -= size
                    pos += size
                self.usbwrite(b"")
                time.sleep(0.035)
                status = self.rword()
                if 0x0 <= status <= 0xFF:
                    return True
            if status == 0x1D0C:
                self.info("No auth needed.")
            else:
                self.error(f"Send auth error:{self.eh.status(status)}")
        return False

    def handle_sla(self, func=None, isbrom: bool = True):
        rsakeys = [
            # libsla_challenge.so, secure_chip_tools/keys/toolauth/sla_prvk.pem V5
            (bytes_to_long(bytes.fromhex("010001")),
             bytes_to_long(bytes.fromhex(
                 "C43469A95B143CDC63CE318FE32BAD35B9554A136244FA74D13947425A32949EE6DC808CDEBF4121687A570B83C51E65" +
                 "7303C925EC280B420C757E5A63AD3EC6980AAD5B6CA6D1BBDC50DB793D2FDDC0D0361C06163CFF9757C07F96559A2186" +
                 "322F7ABF1FFC7765F396673A48A4E8E3296427BC5510D0F97F54E5CA1BD7A93ADE3F6A625056426BDFE77B3B502C68A1" +
                 "8F08B470DA23B0A2FAE13B8D4DB3746255371F43306582C74794D1491E97FDE504F0B1ECAC9DDEF282D674B817B7FFA8" +
                 "522672CF6281790910378FEBFA7DC6C2B0AF9DA03A58509D60AA1AD6F9BFDC84537CD0959B8735FE0BB9B471104B458A" +
                 "38DF846366926993097222F90628528F")),
             bytes_to_long(bytes.fromhex(
                 "8E02CDB389BBC52D5383EBB5949C895B0850E633CF7DD3B5F7B5B8911B0DDF2A80387B46FAF67D22BC2748978A0183B5" +
                 "B420BA579B6D847082EA0BD14AB21B6CCCA175C66586FCE93756C2F426C85D7DF07629A47236265D1963B8354CB229AF" +
                 "A2E560B7B3641DDB8A0A839ED8F39BA8C7CDB94104650E8C7790305E2FF6D18206F49B7290B1ADB7B4C523E10EBF5363" +
                 "0D438EF49C877402EA3C1BD6DD903892FD662FBDF1DFF5D7B095712E58E728BD7F6A8B5621175F4C08EBD6143CDACD65" +
                 "D9284DFFECAB64F70FD63182E4981551522727A2EE9873D0DB78180C26553AD0EE1CAAA21BCEBC5A8C0B331FE7FD8710" +
                 "F905A7456AF675A04AF1118CE71E36C9"))),
            # bootloader/preloader/platform/mt6781/flash/custom/oemkey.h V6
            (bytes_to_long(bytes.fromhex("010001")),
             bytes_to_long(bytes.fromhex(
                 "B243F6694336D527C5B3ED569DDD0386D309C6592841E4C033DCB461EEA7B6F8535FC4939E403060646A970DD81DE367" +
                 "CF003848146F19D259F50A385015AF6309EAA71BFED6B098C7A24D4871B4B82AAD7DC6E2856C301BE7CDB46DC10795C0" +
                 "D30A68DD8432B5EE5DA42BA22124796512FCA21D811D50B34C2F672E25BCC2594D9C012B34D473EE222D1E56B90E7D69" +
                 "7CEA97E8DD4CCC6BED5FDAECE1A43F96495335F322CCE32612DAB462B024281841F553FF7FF33E0103A7904037F8FE5D" +
                 "9BE293ACD7485CDB50957DB11CA6DB28AF6393C3E78D9FBCD4567DEBCA2601622F0F2EB19DA9192372F9EA3B28B10794" +
                 "09C0A09E3D51D64A4C4CE026FAD24CD7")),
             bytes_to_long(bytes.fromhex(
                 "607C8892D0DE8CE0CA116914C8BD277B821E784D298D00D3473EDE236399435F8541009525C2786CB3ED3D7530D47C91" +
                 "63692B0D588209E7E0E8D06F4A69725498B979599DC576303B5D8D96F874687A310D32E8C86E965B844BC2ACE51DC5E0" +
                 "6859EA087BD536C39DCB8E1262FDEAF6DA20035F14D3592AB2C1B58734C5C62AC86FE44F98C602BABAB60A6C8D09A199" +
                 "D2170E373D9B9A5D9B6DE852E859DEB1BDF33034DCD91EC4EEBFDDBECA88E29724391BB928F40EFD945299DFFC4595BB" +
                 "8D45F426AC15EC8B1C68A19EB51BEB2CC6611072AE5637DF0ABA89ED1E9CB8C9AC1EB05B1F01734DB303C23BE1869C90" +
                 "13561B9F6EA65BD2516DE950F08B2E81"))),
            # lk/files/pbp/keys/toolauth/sla_prvk.pem, rowan
            (bytes_to_long(bytes.fromhex("010001")),
             bytes_to_long(bytes.fromhex(
                 "D16403466C530EF9BB53C1E8A96A61A4E332E17DC0F55BB46D207AC305BAE9354EAAC2CB3077B33740D275036B822DB2" +
                 "68200DE17DA3DB7266B27686B8970B85737050F084F8D576904E74CD6C53B31F0BB0CD60686BF67C60DA0EC20F563EEA" +
                 "715CEBDBF76D1C5C10E982AB2955D833DE553C9CDAFD7EA2388C02823CFE7DD9AC83FA2A8EB0685ABDAB56A92DF1A780" +
                 "5E8AC0BD10C0F3DCB1770A9E6BBC3418C5F84A48B7CB2316B2C8F64972F391B116A58C9395A9CE9E743569A367086D77" +
                 "71D39FEC8EBBBA3DD2B519785A76A9F589D36D637AF884543FD65BAC75BE823C0C50AA16D58187B97223625C54C66B5A" +
                 "5E4DBAEAB7BE89A4E340A2E241B09B2F")),
             bytes_to_long(bytes.fromhex(
                 "09976537029b4362591c5b13873f223de5525d55df52dde283e52afa67f6c9dbf1408d2fb586a624efc93426f5f3be98" +
                 "1f80e861ddd975a1e5e662db84f5164804a3ae717605d7f15866df9ed1497c38fdd6197243163ef22f958d7b822c5731" +
                 "7203e9a1e7d18dad01f15054facdbddb9261a1272638da661fe4f9f0714ecf00e6541cc435afb1fd75a27d34b17ad400" +
                 "e9474ba850dafce266799caff32a058ff71e4c2daacaf8ba709e9ca4dc87584a7ffe8aa9a0a160ed069c3970b7dae398" +
                 "7ded71bd0bc824356987bd74363d46682c71913c3edbdb2a911f701f23aee3f8dd98180b5a138fd5ad74743682d2d2d1" +
                 "bb3d92786710248f316dd8391178ea81"))),
            # Alcatel/TCL MTK_U91
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "9a97c44b0768424b6bbb0b6aa987a2d373448c6fee1f61fb81f8cf53d70856f0f77e76c06a6901de90ed3b4d9ad4b" +
                    "9e04eaed42e5657bf2fccf390fe9f5abe1abe8575f07916da69acef95d38874223ec51cb501148a1feea2be2b8ccd" +
                    "a08672aa423a4099203c6aa4777fed7353c57696b8e0d4020bd6930b828b9846a454cd")),
                bytes_to_long(bytes.fromhex(
                    "8553e31d7a73f6c9294e961815c23f31f2b5ea1116e3c613ae12b26cf285e4c5ca0e2dc8e17d52f96b30cef6ad544" +
                    "e43205933f20ad17eb8712097aaa23116c68eb6328980b8ba26706105656fa65315688b8232758607b8936d0abc27" +
                    "dbc97d94e95b4f1957fd1965082e5849c4185ebba8afc7d558d4f5f001ac5363423ac1"))
            ),
            # Alcatel/TCL MTK_OTMINI
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "bc7b5107bcf46c2cd7758f4bd4d4e9f06b731d9cff383dffe48156d1ad91ff74a7925fa3027669766b3d4c6e28c1c" +
                    "9310194c34a59e672c8ced38588e998d7b162889dcf06668345f93e4efca34b5fee5bb57dfc38d7623a48f31b382d" +
                    "e2db656ec1f3b5267a9a8f5e441c61448a283e4717ace6983d01b163e34f959c9972cd")),
                bytes_to_long(bytes.fromhex(
                    "6bc0e84b4f38415bc575dd0d5248c2d182ec55e2ba7a11dfe86815155c709a25bbe34fafa6a9c19344adcfb32eb3d" +
                    "2eca465c2dc0fd7528a00cc268c6657cdff0b0da1b2ac6a95b94865facb7e1494cedf44358e29ec7e8f091172e4ef" +
                    "29856d1f45032aa644efc273f141c10cb8281a12cebe202b65f176e1a145c326d75841"))
            ),
            # Alcatel/TCL ST513
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "df836c16bc8e129dac8e6efcd3f41636981687c29c465b481cbe874ffb14d592de024b70f4fa20ad96c96e4e3eded3" +
                    "625f314dedb4d8635782f6d668d04ab1167982229e03ede17a7857a22cbf72444a6bee2bba54f32099e0eabe654c3d" +
                    "a4933926db4d97dcaeb68236df4b3e51bd3c4bfa8b2d47c2534405e4f1c1d43e1069")),
                bytes_to_long(bytes.fromhex(
                    "9ea0f7256bcca9099e5db80757a5f3ddeb3292475c01d2e6eaff8da905d9537a5875e874d26872a8c04b552dd310f1" +
                    "94ef5a5ea445a50d5c1e6670e5126ef01e5fb1af24a67d07b5a9f72197bc66d5743faab54759fbedcf1fd8ac1aabed" +
                    "e2c6fb29601b4734334db92a92fc25f7ed8700d307b74a2c435c9ce5b5caba4b3801"))
            ),
            # Alcatel/TCL MPK_U7
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "db0b6e89fabdc24e6e7379d25b0c402686537ab6375d8b2407beaf44cbbef27e04e90b556801bbce5eee2a7ec636ac" +
                    "825667dae3578eb7bbb66701bc62ee86f28fc14d57e8637a2ddcee00cc3ab87dff4155250c2dbde9ae62f3d7a9d5e4" +
                    "a265fb0a8b23c082be263d7788e44d59780b47a31b25dc588f81902be419f917933b")),
                bytes_to_long(bytes.fromhex(
                    "c5829b5bc34253f090db831f5085cd5a6f88da7f6f90e3a3cb6fff6e53218c5a616719971b3f64ef02de526719a7b7" +
                    "09978bf1ed48c821981b32ea77c9e536bbda206fad74946d02a20d17120f89419b0daee2d8a47275768930ad53c876" +
                    "afebffb6805483c1ddcf6c19f3566f0de494838afb51b18080beff66364de5294581"))
            ),
            # Alcatel/TCL MTK_U8
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "9bc517a0dfa87a7e240000c5f42cf31905ab93d4bcb95694dee85282867d5c83270aea0b0948d66eb39d8500aa6c8b" +
                    "1069b8ee784f75948958f7bbf627d6ed5f286fd3bd4df60a6c9490cb319448b22765aba9329820eec50f62f1ca0b6b" +
                    "3322aa27747b26855a1f1719cf0c4060c9f5a6a3a60ec60fe6e04e7b044e5da994e9")),
                bytes_to_long(bytes.fromhex(
                    "76ca90a16bcf7552db2b716b8531fe5617bfe86635627647e3d27291fdf47e67ba8f953ac362dbbce2977f05a9f24a" +
                    "ff4250f8f3a14d3ef09b7b99c9384aad0c53104f87b47d7daea3ca725beb233d127ec342ce0619b16bd3d5e44371cf" +
                    "fce9f23178ff48dd42fc4450ccdb3e2d63437ef9dfc0296b12840ae85d472cf0135d"))
            ),
            # Alcatel/TCL MPK_U91
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "9a97c44b0768424b6bbb0b6aa987a2d373448c6fee1f61fb81f8cf53d70856f0f77e76c06a6901de90ed3b4d9ad4b9" +
                    "e04eaed42e5657bf2fccf390fe9f5abe1abe8575f07916da69acef95d38874223ec51cb501148a1feea2be2b8ccda0" +
                    "8672aa423a4099203c6aa4777fed7353c57696b8e0d4020bd6930b828b9846a454cd")),
                bytes_to_long(bytes.fromhex(
                    "8553e31d7a73f6c9294e961815c23f31f2b5ea1116e3c613ae12b26cf285e4c5ca0e2dc8e17d52f96b30cef6ad544e" +
                    "43205933f20ad17eb8712097aaa23116c68eb6328980b8ba26706105656fa65315688b8232758607b8936d0abc27db" +
                    "c97d94e95b4f1957fd1965082e5849c4185ebba8afc7d558d4f5f001ac5363423ac1"))
            ),
            # Alcatel/TCL MTK_6577_HUIZHOU
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "ac2a2c19bf4beef4272df8899cb648f90453e53faa1dd8143327978620ec74e6068a8fd051fac856a59ff0a2f3051b" +
                    "7512f55fcd6eea57262a5a24e141b2a9c105509b79976b952a4cfa0367535aa1db83290f18f62e2f604bfd5fee3fb6" +
                    "fa863ca5546e359e0348937e5b62e47f645e9552ebd2e7e516c13a192a6075c55351192dd545dd90c34fa28c695d66" +
                    "43a2449c0c7acc9d003b9bb4f9d249bc19beb8ffdc2d6115260499156461eea896361aac9a24ace3bf6c81db3e8c32" +
                    "fd6d74d876882382618c7ae920ce63b0c33a3ed6a59642acdcdccd68f2e84f6b1dfe8e4dd33fd78208c750f877a8ed" +
                    "dbf32b7f6cd28bc7f62a79e1281cad49b29ea1aeeb")),
                bytes_to_long(bytes.fromhex(
                    "3d6ff33ae0ec1d029db4a6fb9ca3e41890f5cb5a53bfc0ab3cb2053d85243c7715a07ebfad719bea67c252a223ad0f" +
                    "e65074a5d26ea14ba63ff8d92e553e879b6ce51e065f05b23e5d27deed116ec751c9556ea0cec11e80f3bd206da9e9" +
                    "072fbe1695b19a8a9fcb576f00f7a268df8d6d262127ab3f3246941004f25534ac8d2f418815d15f4a5a663a2f1383" +
                    "115cb3e8bd263ebcd92c5bd1b92644497e15a1b41e77e648cac179182d83c496728fb52b9a1c600954ad0c3eac5d46" +
                    "33d519c88daf775fe090c2f2568c7c91a8938a2859245f100fce764033147d84d79075a81331ecdd170d2541832ab9" +
                    "161dc473cadc1dfbc17df2be89fa6d6c13d9db3611"))
            ),
            # Alcatel/TCL MTK_S_2019
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "e4607e6cf78f5e4857bdaea441f8ddd35a7576f552b4ad2c8b4ee7f578c0590d747b049bb5014e06f8350dc6b78d5e" +
                    "0ddff1b4bb8af695e4a338a154596555738cccbe6b58eb43ae221df9babfe9dda6ca770c25ab42ff986f946756b46e" +
                    "c553daf7616f2843dcd6a48f48d9011c050e7ed11c99f61624f057695d622088f868bf6a3966f25bd8ad58db81623f" +
                    "d63f2b91f3ded1a5be0efb69a64bb40d8bbfc251d9c32fbf0a1bad516751e9e04439392c59ba6f856b5c0bebe0dcc6" +
                    "7d7d4f25da5342aba94680583ed76d94823c6f62e5e7484f7e2d2a467d167ad3f5647f958dbba3eb66f756c851a551" +
                    "38d1ce465333592969470fa8652df2e38bc380ff4f")),
                bytes_to_long(bytes.fromhex(
                    "68d01875ee507057075dd8cf2e3007aebeaf767f350c130684911c483eb918a5e235ab71c2eaec62aa7bbeecdac518" +
                    "cb8962272e83a2943cb0e486b66da8e244fbf3e3d8e4a065198032fdb045f011784127cdfd63d285f7f20dcc37b0eb" +
                    "bdc8b49020b9a16333f196e8e3e8246835b1e76615985ba6e221241d096cc5bdd7336d8b22704dc1576ae0ac252fea" +
                    "8dab129756a609f347d60e25d8d085cf0c8775631d3c0e54e50fc67dff2c55148b4e78cf36987febb23e14ffc1da9c" +
                    "b0adfc139d509826aa98f6fe0e25ec6ab6442e5a7cebbe6454ff06b897467512cdd8f0460201125d0bc9cc2bae2598" +
                    "40722ae56d16b06f9e0515a2d128a23b5b0a1896e1"))
            ),
            # Alcatel/TCL MTK_6577_SHENZHEN
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "a29274e3085c260de63f571646cd2c69737ba5a0bf604ad31cf6a86d6a9e08dc931ecdddb7404f4c9255c72b5debdb" +
                    "69114146bdd7edf6b38505b19c4d18eb0e71516d4faa871cbe1d2e24e15c1877b33587a8bdd1e7dfe1b17235d1ac43" +
                    "1c27cae07804014c287fbf2479e6b4b80665898f7cbaa7edcf23daa8dd95f63039fe7eb641ad7c05e221d29adc62cf" +
                    "84893ffc6acfd44a9d2cd60d5e0f94d1c29d317bbddb3f5a324648069c72857cfc708fc9bd8a3f7a98051fa9835af1" +
                    "f9c71d80236334ea51cbd52e57e5a7950beb394d9c97bcc32591d9700106b0abfe1dd2db9617fb7dd2eaa3885630c3" +
                    "ce1dfcf087c814b480f30c411f3071f12aedee4077")),
                bytes_to_long(bytes.fromhex(
                    "6d209285b39ee78c7cfa17a34473855463c8a42d7b494ff0d6885c16d672aed0219193ef388b5aafb3ab10bef394d6" +
                    "fb7831b122ce47564abb084f68f3f7be113bcfc4e8ad3774fbc8eaa8a6fe030e96a56022cd0891f59eb2564ffa2700" +
                    "056e50a8cce72357d3f7ac7ef7b4fdaa69e0ceae1ab3d0f5b90e00414a3cd7bd17afc3b6463ef43bfd22788b68fcfc" +
                    "c2964421b1b622907d8c75e8d83193a579e50c26b0beb93e53e2888cfddafefa03c368c68e6d357087f1bf0800e1bb" +
                    "4f0fc97c092a7e7098cb60cad71e292b506c0cd1f428aff3192da6818351a780aa1b4cce0dccd15adad815b610f445" +
                    "a6571d3c65d2c44da9057b5c8970cded0dfc3072c1"))
            ),
            # Alcatel/TCL MTK_S_2022
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "af823063550d6e5adcca01a1ae1fe357f73d7e5c60cfa25e4beac24304b70623654fd13547de869899be532f45f3c5" +
                    "ff26b50292dccd112dda1478721c05304445058499bd00f6b104e16fcf2d0af55781be147787227eff54a25dca42b9" +
                    "d6f1fc8f4b821c099f483c402addd178330167aa9b1021dae121bb2bdcb0127ac47ae866a1579f2399c70e69293ddd" +
                    "3b0bacec2df9dc518aa0c58c2d7561c5783ac32e57b91d16d6c57764755894963733b85f19f9a3bcbf624199cdd1b3" +
                    "1cbecc5448b132c3799e2d0e569f0ba61245796db5876820ef125f4a230039c5cd16b2414855bf3a3b565f81787a4e" +
                    "9b264c9bc855b4fe7ac17caca1bc5f070594a9c175")),
                bytes_to_long(bytes.fromhex(
                    "3be4c4d89124e53d12cdc922c0c6571224e8925fba160186068855c5032de6655be49233899432008faef8ba5037f1" +
                    "a0b237e169f6f9f05be2694bf53d04b44507fceb1480007d2f49c8191ced7528e6b4fb06070851c85f2025ccb60271" +
                    "631def9f831822b351ed17ca9a165aae97516a6c3940971d17e927f3befb43432c1b689cc660a896237f090d7b311d" +
                    "9e39aa1eee5a4e3af00843c965c30ca9aa5dd7767809d27d4f66777661779d2a1fb90b014329a1973e67b8989de924" +
                    "e8ac98673667e4f734382f87f0dd0300d360142afa772d5beca2ef248e90a7bd32240c4a5b5f41aed3f4b63f90642f" +
                    "138186fe17afd713a3242eea7b2dd0f32b06b67681"))
            ),
            # Alcatel/TCL MTK_B3G
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "cf8243d13128ed39fadad9ca97c15585d634f4d9b38dd59e4eec4b0b93e4eb2fd2d96c425855e69706d5c11021a8c2" +
                    "e08bff87b424bed2dc3efa9360bf1bcf80c96cd4ba9c39eb79bfa2bf9d4efc5a56798ccd9c6599ede595aea6440866" +
                    "05fbe55b2f7719fccbafe0c95956fcffb0ce77a9637c9ed66e067165cbe901eb041b")),
                bytes_to_long(bytes.fromhex(
                    "12ff6a160cda225ddc898cc6ef7dd3c69d05dc24d23b7a0334568dc85191f3b63d278ab1c8449507dea8533496e04c" +
                    "77225a12a27b7abcf34d10c3cd67b1b41d7c19c44114e344a74396541d998d7b76ca06d0322bf3333684652528df22" +
                    "021c190bc38acdac2a3be6e2d0bce7f1e3c77a71750ff17895cff9c6225275a3ce81"))
            ),
            # Alcatel/TCL MTK_E8
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "bdef438901dfa726cfc2cca59d12f009108b8e1fd7dd9b91a5cc71fa7b1e36c8783f9de5850050e6505fc715c50bdd" +
                    "d59a3064b05214c4365360cb98d080cc38658a94695184b564e8e8dcc28f70eb0122a4bb7662e3a1f34c057ea52381" +
                    "9ed02ed46bae0cd9530b0536cbe7a1ba3f33a45feb2f92ff5104dc32ebe94f249eed")),
                bytes_to_long(bytes.fromhex(
                    "95b32d61a10e6c2a54fa4e5e020d590f6bf0f295fa87fa03b3d00dcdc4982dc997ad5c7ff872255141ec1b77f714c1" +
                    "4587ffb87c985531c937b245062ee03514aa796ad79698c40c49a8b3c54ec66fc20deb874a8bbce87239c414f54136" +
                    "7a350d525fa6bdea77e4cd3078cf7ddf22a8aefb0c595a6c76285d837008c0a77e29"))
            ),
            # Alcatel/TCL MTK_C3G
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "c04e6a1be49c5a57accaebc837099b40890180fc046c3dca58745749d0979cadb63b8b4573fafc129c2f89ebb64c4ec" +
                    "81339e862f5638ae145e2c8bc291097e6b90434ff3f3a1e620fa77dcb6d963f53b79abaf4eefb8a5d4378cdf4ab3060" +
                    "a9901909fd455cf850ae5adbdf035cb3cbcf572ac4dce4bc1321562273a461ddf1")),
                bytes_to_long(bytes.fromhex(
                    "4375be875664fad432cb6476f1c7aeecaea3166a51eadeaa32e96d0d79dd159b6287f4cd42685330fc15391eb4ee83d" +
                    "c6fd22a913c5fd5023d8fd6b71af8b530209b5355acf1cc6e6397aa6e5d2dc92b7d37635d391cd22a3aa337d8fc0a27" +
                    "4cdd7d6630395d13517e32c91daab2f5378ed7a1be86c81c2e775c249201f2c221"))
            ),
            # Alcatel/TCL MTK_K6
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "a7e3089840bb7a9a7a972e8c88d7c464fe40dc4771a2df0da981079cc800f5d3cd45ed9eb34efac6bf7d2aa6dbc1266" +
                    "285f50d7e86e6e0e5dc6d062bc8fe871672139904e5ffe64c6ffb4ff00817ffc0ad4c18787a253ba5f7f7bd8412e5f4" +
                    "6e2c264cedf174ed5163943331a658b434c59ec9e11b269e829ab638c80c4ebe51")),
                bytes_to_long(bytes.fromhex(
                    "4f65cda0c3ac66753c58d748db46bfb8cb8dbd1f849c7444afcf37dc6bb218904c5a2fe08808680d2a6e7587681256a" +
                    "6ed9751046fa42ce44874bf2061f40dca4953c345c2f156e8ee7e2f497ebc59b3ddccda98584dfc999d213d6782f2b0" +
                    "faff59a9671cee801defeb5a51178a7b95c487aa735b463e8b1321b6ebe58c7401"))
            ),
            # Alcatel/TCL OPK_VLE5
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "cb676a5de86e2c7d75a17f10fb2e3f81a473e5d2d088833d8c1928ce78caf1000aaa607c83f55b57dc07fac7a9ecad1" +
                    "600df5d033986c02c003884620661a9674042a835b99cf8a024c27a10410eb379ac69e72d6f5a9cf72c185262331c98" +
                    "879cbc225de835d864983d2bd085f1df99341d3cbb0ba3b0a50491c8ee98d691b5")),
                bytes_to_long(bytes.fromhex(
                    "4befe0eb0c424d83cd2dacb59740cddec599ab3c8833dee354717425993d12ba5441056297153bb3d2667c3e9c76caa" +
                    "bc349a07cfab60efa9e5e7b35e971fe7eedac090a1a5a7d8a2cd59de84762f09cacffecb65bf70ed504243721fd0e09" +
                    "4c3f216fbb85778ad82829658232a2f472919e992060394e79f2aada9e8a42ce21"))
            ),
            # Alcatel/TCL OPK_U7_1
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "de15dc10818e30c363bd0a87d5f8d89b832329fa25b8388709d94e9b0ee4efdd3e24eed3d931f01ea1b0e2b76265d7d" +
                    "c270ea8012545bb7245c286761210bf46c6dd1fadefc257fabebba29bbbd86e8336460e5d21888a319156e8ba529e4b" +
                    "6a200136ae4aba447fb37a357028142d8b16d79a421d513ecd9b9ec0d908ba8217")),
                bytes_to_long(bytes.fromhex(
                    "18e2fa361f4e7fc86574d9a93f2113a4d99d272710f303e29e07ebf71444335ce789dbf9816d472b27935ad49202379" +
                    "e44023071706bd0058e2bae45ace0938e75610579240ec87086d27fc0844ba25bba09214ae43037cb902801a58915ce" +
                    "58c6f805fb3ad6cf7996f25e0cf0a94c13e04eb4370ed6b93c39ba2136f8cfd101"))
            ),
            # Alcatel/TCL MPK_U7_1
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "b6a33b825b0cf6abd3c9d39d1c8bdce50a41f9bd5ca2de52c4c447afa9943f5c1365d2e9cb7961ffd877fd38696b447" +
                    "9a8bb7eb8da15bd8d59a1cd7e5ee517d1a20f29bc66974f87796a11f7537529f8f46ac57861484808bfce9ee6cd6527" +
                    "f7fe3bfd57b4a7fd46f8dc047d6c8370de6507620c2b9a3bf864e8ee4c4d2abda1")),
                bytes_to_long(bytes.fromhex(
                    "88a4477997b57337cb144d0656bd2d5f0ef59d6b574b631a79ac8015a4c20d454e1df85682ad25eccc7fb92be373259" +
                    "fffe58741b5a85e50caa68b9fe84f6e295d2176b96c20ff819e8bb889702c474effe1a77710ff3b93e896fa488f1717" +
                    "c75e46a1b0f5898fcacfa35943f1abf80ebb665ba7fde59c4baa61dd2f6c5ec001"))
            ),
            # Alcatel/TCL MTK_S_AT_META
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "d1eee63f19d148c904076c507aa8d4f6c7e931a65476fe5231c06036fea2ecbcb8c811882c4f70e6e3523be73f5c7a8" +
                    "3570f3a40bd894399a5ee9f903e8e745ec4e4e034495175b167192535843f06241d6477e3ce1ad5270e590db9cb9054" +
                    "04c01aa407433fa2c2ca1f8366c1623fa45bd5ee68e3145a57f9af3e6e68fce41b8c682c0e07f3c48f4b377951b23b4" +
                    "67fea0d4ee0e67c0235d0e83ae27e40ad1c060063ceb966835a0ac1eb68066f8b55775ceb7b444ffaeec19548a42247" +
                    "ebe687f881a0c8e5277beec22241e2ddae1c21cec8046eb005302812b7ef42ac153cab317bbeaad73f7ccaced38c433" +
                    "530b7e0ad464150026025a9a3ff5d45e025db")),
                bytes_to_long(bytes.fromhex(
                    "8294e45929b8f95a380c59fe715da5225fd518920a85fdc9a8b2ade6675b7680293c21539fa4466907cb3601b072d8a" +
                    "debb0481ecf069baaee00d0f5cb4396f4ffea11dfd41f3c62fdeb312ee9b4be2026bc40aacd9ff928130fa7af030522" +
                    "8dd5e47c551c2a701653dd6841b9566099de99e2731194ae617ca8d9df99a47c49d9f514620ea1e3742da8dc7dec675" +
                    "6403631a274dc226c6121863e4a571a120b63c38d134853df5b986fac1565e1f3bd8a02d239462967e9c71cedd9ae0c" +
                    "0eec330018ca553cc7cc2fbc73d6ba37be2fe360644ff69ab7c734264675c057417857df4ca206dfdac9a5621f9d8e4" +
                    "5dd2e58dc8b4198667de3efd1d5bd7ce007a1"))
            ),
            # Alcatel/TCL MTK_B7
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "e3e3166f47177de4915e915a9d555d980afad96be22cbb8a02516ac8fe69657bd10bc6d072046dcd33e4476e24f128c" +
                    "b7ac613df140cefe71abf080a74d27c114635d3954c55299f6f81c2a0aa14c4c678307f4b3bbf0c64f0006051ea7573" +
                    "b5b0cc290201c76c4d272c981b1bb19bd0a0a0ac046e6e63b0f4cf88d2c98a5c91")),
                bytes_to_long(bytes.fromhex(
                    "776b1deb8c3e943b3dae67cf2b597ba55c439dc1fa10e4e9ea530df96bd0815cc3ec3ef0267f89a699c5cb64bdb91e5" +
                    "e9ae4c7af03cbcfbfb4755cda55e3a31d510f96a102b5aed90731788a426e371f8ae24f660403377cc0836a06b2a8e1" +
                    "59bd177f4cf68e36d447e4b52ca63611cd8416c1efcac52143106c272f7474387d"))
            ),
            # Alcatel/TCL MTK_BACHATA
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "94cc529bb1af0ab8043f09e3ca612d787cc19485d3769546e750f6edb844979ba8f1f9afb8b93b521330b74713831a7" +
                    "8a584f7b24780f92dd00e5d56ce8defa3cd39d01752e514a4c2ba7499f334729622049491b1aecee6c9e1c867e996c2" +
                    "94b10f5d62ea4504e333424b280162087296c300c01fdf75f47d874df40dbdb94f")),
                bytes_to_long(bytes.fromhex(
                    "09fe029a23ff7e37c749386fcc9a640450546b95e5127489d364d380393c99f5c10da6d7cf0ed955f4a5f3d8d90d97c" +
                    "c7c49069d394206f9b59c11568ffe66163eae377447abb103cd5d4256885cf7984b28cff8a096dc479b9196d66cd534" +
                    "cbdfece7a61de04110bb14a3ba5e0f20ae0bb4d82e18fbff0335904dc09b829e91"))
            ),
            # Alcatel/TCL MPK_VLE5
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "a62bf756a70657b6b560588e85e662e181b6a61ae466ac3d0d2e971f160e88216792cedfb1979b3d6b665068eee8a86" +
                    "99888cd74ec9482c61ae7eae3571e50beccdcb336477c26040d09b46dbd93efc0fece4adde2e00c1cbedafd6ad7c43b" +
                    "d621675a6a46425c5cf6182fc5602be443a372fb4ead4531e64285ce29be913285")),
                bytes_to_long(bytes.fromhex(
                    "7005d1bf5be81db7b17c9b16b1d407b308b42e3490e75a93e9d00fd6c812d1d8db2f1041a342964808a037f315a448e" +
                    "caf0502a5215c58f0de709c5bd87e3a65e0291a1a23547c76cf437ef1d9b434b70dbb417049a31de9ee7becf218a5bb" +
                    "63b05fb84ff49d1e6aaa4b9b4376f47417435ecd85ccda63be9070e7892ecd4a41"))
            ),
            # Alcatel/TCL MTK_C7
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "c1d6c392828f4620e455c138840ab448cfcd4aca821663335dba9c51dec9b8198301ca6b069adefcd1887f1cec31c15" +
                    "674ab264daeeb82398b419f08b4236904203c48a7db8724f1773d04a6b8c88cb38907a00bc53e86cdb2bbf479a68b82" +
                    "41382bdc5ac6105270efc2da4cb91a36459ccf6a2a87dd56ec4c331dd419ba5931")),
                bytes_to_long(bytes.fromhex(
                    "31d28ed040a8ace0d56fc94b4a7d29dbb135d62c7905621818d657499fd6ff6fe7417592cececdd3f3d37ec0a361228d" +
                    "a34d3e7a2724b7832ced00008fb4ae500357fc3d285c64fbf7efd4bd1ee48ed40190296171acc3c2d0c69e89da5a8fde" +
                    "7e0ba7048aec6bef1bb19646f883fe9d77d8d263545e7c00e8604be38210d065"))
            ),
            # Alcatel/TCL MTK_MARTELL
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "a800d061e4a42e4c3453a17cc8daa974e23bfaa403b4a60fad6d3516d8ec035c1ebabdcd60009d9b8c639954e616c6c" +
                    "b6cf821e31e58772ffc366e6ffb7314657567b12279a34dd69e46b8a4a628dc2dfabc68fa1d89388d2058a97d2e3152" +
                    "0b4fb04bc2f963e110e8541eefd22d90a03eca806b3c6a20c6bd1a7468e61ea1ab283ed1bc462dfae189eb5fb451f80" +
                    "2fb868cda9a7409aa52e42b18882e79f4f1c2377829fafd9760468bd1db823bd9080378cf46ef405d91636cafc03aca" +
                    "d9fada6b0446dbaf51e9d533887e4a3a8f62114063e0b8920684c28bfbe256aab26e98751166358c201347ba6c3b36d" +
                    "49aab6302fc248eea3c254e15a08429fd2149")),
                bytes_to_long(bytes.fromhex(
                    "985e549fd42c0b4955d3db8c3ee601f65e10a3db08f957fab4016dbad0f60c7e09e8b7a782404cb0fc7c805dfd67fed" +
                    "814765ed58b7a146ed2c1d31b80e3f845a45b6ccda5a0344247be404c23debf027c7b5082373372b49bf78d9058caa6" +
                    "6c57d3be829088c3610034faf1ea9f24a21110bbb3865182747ca1779e83c6983c189b3f19f3df49e5f9cdfa57f4f69" +
                    "dfae53e19ee0b1ec30986d59ad11f52bdc022a9499dfa89f8546d266f6026aa307501ca5a619f5413a45ef38f139c3e" +
                    "a8b52f02fbc8983aa878052d9108668ecfc8605057a298355d2f680c34630e224c57dd4c4f2dc0d51766ef7070daddf" +
                    "a3c885a3f94d76c943c6c1054d338e2323b99"))
            ),
            # Alcatel/TCL OPK_U7
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "9f94e8f1171fed4b427629c928e807b2220f109ac70a3d5b1b8cbd295bc3fa3226d3903298cd81319b9b08a6f8e77ef" +
                    "ad0b04139b686ee0d1586175913ad6f65d6cf21bbc7f769885381ba6d840414b26fe7b9b3e393acacb3453e3a0cb79c" +
                    "a21cb38a42685a03462244fdb2a5f1d8b9e20745fb3206e799655c47146310911b")),
                bytes_to_long(bytes.fromhex(
                    "61ed86791440c26491b763730f483c18c32fcd77bdb6f9e9e3e11cdfb9716d22c392c68556219e2b6c1ada57649ce2d" +
                    "e559c239a9ff8f33252480421e4a2649df8e3ee0095c9bec361f25a5ec67d0b4d96c73404ff8a115fecf1173a656884" +
                    "5480fd4423b5dba2e5111335655f3bc2f3fec65510648571992e010ba0aaf243e1"))
            ),
            # Alcatel/TCL MTK_S_2020
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "e4cc4967bec817bb348468024c3084b15fd4f7810c8a9d078a4f51cf9974d2e3bae8d5a19a85c0a73befd0675100e64" +
                    "2a3f425e3192dfb1de56928c37f45fc142adaa65798ada863b84d4b5f22c3f79b95cc201ac7c292c99475453a62b7b7" +
                    "e06e84833dfca7a0df931084932a80129e543c6d24a13c5f2cba6ef5ffed9efd4dbc20496f5194f0d1aad9d789f3257" +
                    "7f8846df9a14778504ccb5dd7507114c148c1937fb99da15f9596d4fa052cdaf1f66d7e5e0c0793628752bf9af3c4ac" +
                    "67e21c21d170ad448160761bddf586a4900fbb7dcc44467f1550d15db774d7cacfe3105b465321a5f95fec22c2011d6" +
                    "16a5c0e22f0535dd1f969202be56ec015f891")),
                bytes_to_long(bytes.fromhex(
                    "b86887499d157d3b1feb1041b9d2e94065732b41d22feebce317676321d66d1babcc7a53544e35a714c207811e62d13" +
                    "4291d616417295e5b0c4aa3d65e40b41a352822263c22cbb4041a1883c76b97a8c925cb428a7b2300622ddaec62209d" +
                    "8dc0c60159f6c7ccfc26768bc469deec22bcd62f49f4c2ca1b2cf0be49d6e5ec563279cdee79c92800c6c965200d316" +
                    "c79285551a54359b37ec4173eadf4c0506d857ddca4831ade7ea8f13097b4e2b630a2d3eb9c57abcc65f84d693c55e3" +
                    "61763d8d37bb40cd6e2520684ae05edc62a36cda6747509600f4605b7ed924ee1ad49e66eca1176a20794600173dbb4" +
                    "2fced2f1fa0cccc0af3b56d58453bee420099"))
            ),
            # Alcatel/TCL MTK_U82
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "ed2055a7b95db86f7e3101196ae6218015d70d03df6fd5787de150e82927443097a90485757743447e2f4641afcf510" +
                    "acf585f73e79c45b2908d5de8835221a76d93e48ca465ffbe0dd76cdaa98550ab2e7b84a6470d48595742fb54a20444" +
                    "2ce67bab989c69adf86457e313eb24c87d80aa7d635449fab0d97b6b08c5f7c86f")),
                bytes_to_long(bytes.fromhex(
                    "3f5d99a61561d70c6c335a30d9a11fa8a3ad70fbecf46c9e233d57aa827cccbb137c060a47e693e234ba1b532851053" +
                    "e17446d5582b9fee205c0d12c7613378c8b8c8c0184cdba90d56a308014aac0458c5572699d599a15ba36146b6f2e23" +
                    "0034708cf67d31ab837b7bd8e5967fd9a7bf413b7d9314302b18e48962d01cf6f1"))
            ),
            # Alcatel/TCL MTK_JADE
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "e8490dcbd3488278442f78ec5634ccdb8befee081ed0d19071480a10c299416ab8d0e9eb19e8975cac260606463c51b" +
                    "b62875ab24690d07905b9c48fe60086da12899bce3dbed91e0157cff76f27a1c09b37e837e7acb71da3c0e30564223a" +
                    "e20216fbcb3de5e93c2d7f98827d61441b988e57497c1ddacb87cec1e73139bf67")),
                bytes_to_long(bytes.fromhex(
                    "69fd6b9e25ba604e204ec90e8e0769b28417e6b52dda7ac53deb712c549f398a48ea8ad20bf065a093ac85f336f92f1" +
                    "221d3413f3793bc8c7c6057a091828c04f6fb695f43747d0d22de100bccce70ac7a8f9d092afaa7d44fcda99b12454f" +
                    "8c887e383c69e7e21ad15203eaae51d803cf35da09c8d536139c658bebfddccf01"))
            ),
            # Alcatel/TCL MTK_B82
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "b6a33b825b0cf6abd3c9d39d1c8bdce50a41f9bd5ca2de52c4c447afa9943f5c1365d2e9cb7961ffd877fd38696b447" +
                    "9a8bb7eb8da15bd8d59a1cd7e5ee517d1a20f29bc66974f87796a11f7537529f8f46ac57861484808bfce9ee6cd6527" +
                    "f7fe3bfd57b4a7fd46f8dc047d6c8370de6507620c2b9a3bf864e8ee4c4d2abda1")),
                bytes_to_long(bytes.fromhex(
                    "88a4477997b57337cb144d0656bd2d5f0ef59d6b574b631a79ac8015a4c20d454e1df85682ad25eccc7fb92be373259" +
                    "fffe58741b5a85e50caa68b9fe84f6e295d2176b96c20ff819e8bb889702c474effe1a77710ff3b93e896fa488f1717" +
                    "c75e46a1b0f5898fcacfa35943f1abf80ebb665ba7fde59c4baa61dd2f6c5ec001"))
            ),
            # Alcatel/TCL MTK_S_2021
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "df85f4c4ae8c98e78142d403d002276a5bf9edd17870caa848fc45720e8b4be94f6f9a47181417840a5b7d4fc365751" +
                    "29afd6a848a0de3f62fac5b5f687a2219cab8cdf2e7527d6af3c6be84eb99bf519b0b210960fc8f5223c9bc38e8f20d" +
                    "0267642153cf370312b955143e10490c6a207868ac7ac314bbe10f6063a1ba606e28d248a1ee3e7000d12e9c4ebd47a" +
                    "e483b625156b82026fcfdc36118198cac1463aeb56bdfe260efa38ac1d4123c13fe59e0fb0f2f895609c117f7a39fb9" +
                    "f27c356d4748cf7af41e15ea68c6c7c64c4d0a1acb4632965e0260d9b08de9fd81b82050c9929b79ee865f89272483b" +
                    "6fed8a409d6a1af2429d24fd358a4b4da4e77")),
                bytes_to_long(bytes.fromhex(
                    "cf553c03ac3cf21fdb4097d4a97f35fc6c305a2e30dfbebb7667ba2adfdec99d3277bccd314281c592ade680b42849f" +
                    "de6122659a68cd7e525b764520d612c7c6c141bc4b2594bc88732d4ca0a97e464d7c1ecf4fc2788f1920cb030c1b2b3" +
                    "ea84e8d6191d5e53d56c5fc495051a1d0fdbea947d58a9d773a68152d157d4bf57f2b4fba8182f96ea4c9b798018361" +
                    "054f95b251089c786be542c7881c49b077ad52af25a359bb26257170706217f66533cf4b8379a1fb7a30c955c8ed4c1" +
                    "c6dca905ce6e7e5e92ec7e1bda1db44cd187a9e5137fe44a37cfdbee173a49654994926cb2fdd7857dfc8978d9de73e" +
                    "899e18f5dfe33a64e6414fc5d93738f8c5591"))
            ),
            # Alcatel/TCL MTK_MINIQ2
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "ba1d10a245e60471e8d3138611615170f213cae5b895c8af35eb720e2671915f07dd6ccb5384d7580200d18f430c894" +
                    "05dcb0be6a5e91cff0fda970e292d5f0704720473bc61e19590539b1bb08ce2b306755db1f70cf1193933802ca44281" +
                    "fe01699f75e56fb7660fce0342ccc284d497a17ad7d3d15eaa20ad4c67bd92de61")),
                bytes_to_long(bytes.fromhex(
                    "a475ba952a9f2f9e58d6ec91b41a03158354ea1e451656d83d15691c07eca3410e7a2401283462f66a0ebf1f91682a8" +
                    "0ae61168b2260f4368f93e197a9db65f4139523ef5449a6fa77568a9ffe90e0a34a37f99b7c1ec6ed1683a574d90459" +
                    "93679ef73299991cd43b96fdba6673ae4318f2f635a816f8559d325f9ebe428a01"))
            ),
            # Alcatel/TCL MTK_HIGHWAY
            (
                bytes_to_long(bytes.fromhex("00010001")),
                bytes_to_long(bytes.fromhex(
                    "beca753fd31ef104bbb01b0a7c560c7bc040d30ea18f216b64b7de416b695af2b3350ecc02fa5224b412793f876a7bd" +
                    "bd8cbe7fecd754aa8214a27bfe7ececd8caa16959df83bdaeed524880a820f8dfe601dc70f164ff1921baaa06efd8c5" +
                    "84c22269a109d16287356fd30e7eb02a1365ca93fcb8088278f119a2c7298306a9")),
                bytes_to_long(bytes.fromhex(
                    "5407571c851f5b877a2255c6887c5d832369698b481c81db8ac07062dfabc7229d4b00f95956665743f7deeedbf54a1" +
                    "7c9a404c97433f46d983bd0c5f49fa4b013b9d86e5f1377f563d8299675c0ea2b81f51c33ad74a265184df9389eefb8" +
                    "e72d2f0585e4a41826b8846b0ee6da5ef8cce471536109fe4c658735247ebbc301"))
            ),
            # Motorola G13
            (
                bytes_to_long(bytes.fromhex("00010001")),
                # N
                bytes_to_long(bytes.fromhex("DA61964924F441559A1F8B5264CEB01DACE8E417413BBA4657F4556811D07B85074FD69" +
                                            "87F315A7492E003D03C57FC83D3B889F2D4F136D0989E515A08628A7B16A300217162DC" +
                                            "35C340B1127046AA86649B763AF97F7C9871964483DE6695CDA2E8CCE82E1F6A0F701AF" +
                                            "8BE767BB16927489524F8FC9A2C280F5692E850E4C4E2606436CF2E253147AFAB32E6B9" +
                                            "2A19FA180C43CF480619B71B3D6A7863C7CC376C0A36BCF8BA3DA89CBF3E6DAA4691DCD" +
                                            "769C0AE4535E502A9966AFF3F123C7A0EDA2DF04593B0E1FC60DC688F2BA7617DFE67D3" +
                                            "1854443ED95D2645323728C594CA49DAA9351A572E3182D0A1B3146C92CEF87380CBD2D" +
                                            "EFFEBC4E8F420D3")),
                # D
                bytes_to_long(bytes.fromhex("AEAC47CD11A5DD6C5EEEC43D8F2C536A2917CEF95AD02F5A7C978E88C35702B590F7A72" +
                                            "A2AF28AEB9B5F5B2D8056D03F916595D189C9B6927AC0874980537178AACE8E1831DD65" +
                                            "4E0B72FF2F44670196A57A43C340355CAF828B331A5715AED4E06D5D18896BCF25B201A" +
                                            "0DC9760B0B2EF1CFB4EAB6940D7F8E2EBD86DC1E678AA69F6B0BBF55C688BF72C2123CF" +
                                            "42E367F789E2592CE281C7C4752E14F6FD00D54610977DEF753E3890F12F704688537E8" +
                                            "60D81142805750B805E7CAE3AACDE1CD7A272D227E9F8CCAADCB4D06489664627BAC46C" +
                                            "AF5DA0F0740CEEDEBC7ED1C1D1EB1E37C6A8A9E6A0454F742B3248448B20C93D5FF6E5C" +
                                            "789907A862C90A1")),
            )
        ]
        if isbrom:
            # e, n, d
            for key in rsakeys:
                if self.echo(self.Cmd.SLA.value):
                    status = self.rword()
                    if status == 0x7017:
                        return True
                    if status > 0xFF:
                        self.error(f"Send auth error:{self.eh.status(status)}")
                        return False
                    # e = key[0]
                    n = key[1]
                    d = key[2]
                    challenge_length = self.rdword()
                    challenge = self.rbyte(challenge_length)
                    response = generate_rsa_challenge(n, d, challenge)
                    resplen = len(response)  # 0x80, 0x100, 0x180
                    self.usbwrite(int.to_bytes(resplen, 4, 'little'))
                    rlen = self.rdword()
                    if resplen == rlen:
                        status = self.rword()
                        if status > 0xFF:
                            self.error(f"Send sla challenge response len error:{self.eh.status(status)}")
                            return False
                        self.usbwrite(response[:resplen])
                        status = self.rdword()
                        if status < 0xFF:
                            return True
                        else:
                            self.error(f"Send auth error:{self.eh.status(status)}")
                            continue
            return False
        else:  # not brom / da
            """
            # N=B243F669.....
            for key in rsakeys:
                rsakey = RSA.construct((n, e, d))
                encryptor = PKCS1_OAEP.new(rsakey)
                encrypted = encryptor.encrypt(data)
                print(encrypted.hex())
            """
            return True

    def get_brom_log(self):
        if self.echo(self.Cmd.BROM_DEBUGLOG.value):  # 0xDD
            length = self.rdword()
            logdata = self.rbyte(length)
            return logdata
        else:
            self.error("Brom log cmd not supported.")
        return b""

    def get_brom_log_new(self):
        if self.echo(self.Cmd.GET_BROM_LOG_NEW.value):  # 0xDF
            length = self.rdword()
            logdata = self.rbyte(length)
            status = self.rword()
            if status == 0:
                return logdata
            else:
                self.error(f"Brom log status error:{self.eh.status(status)}")
        return b""

    def get_hwcode(self):
        res = self.sendcmd(self.Cmd.GET_HW_CODE.value, 4)  # 0xFD
        return unpack(">HH", res)

    def brom_register_access(self, address, length, data=None, check_status=True):
        if data is None:
            mode = 0
        else:
            mode = 1
        if self.mtk.port.echo(self.Cmd.brom_register_access.value):
            self.mtk.port.echo(pack(">I", mode))
            self.mtk.port.echo(pack(">I", address))
            self.mtk.port.echo(pack(">I", length))
            status = self.mtk.port.usbread(2)
            try:
                status = unpack("<H", status)[0]
            except Exception:
                pass

            if status != 0:
                if status == 0x1A1D:
                    raise RuntimeError("Kamakiri2 failed, cache issue :(")
                if isinstance(status, int):
                    raise RuntimeError(self.eh.status(status))
                else:
                    raise RuntimeError("Kamakiri2 failed :(")

            if mode == 0:
                data = self.mtk.port.usbread(length)
            else:
                self.mtk.port.usbwrite(data[:length])

            if check_status:
                status = self.mtk.port.usbread(2)
                try:
                    status = unpack("<H", status)[0]
                except Exception:
                    pass
                if status != 0:
                    raise RuntimeError(self.eh.status(status))
            return data

    def get_plcap(self):
        res = self.sendcmd(self.Cmd.GET_PL_CAP.value, 8)  # 0xFB
        self.mtk.config.plcap = unpack(">II", res)
        return self.mtk.config.plcap

    def get_hw_sw_ver(self):
        res = self.sendcmd(self.Cmd.GET_HW_SW_VER.value, 8)  # 0xFC
        return unpack(">HHHH", res)

    def get_meid(self):
        if self.usbwrite(self.Cmd.GET_BL_VER.value):
            res = self.usbread(1)
            if res == self.Cmd.GET_BL_VER.value:
                self.usbwrite(self.Cmd.GET_ME_ID.value)  # 0xE1
                if self.usbread(1) == self.Cmd.GET_ME_ID.value:
                    length = unpack(">I", self.usbread(4))[0]
                    self.mtk.config.meid = self.usbread(length)
                    status = unpack("<H", self.usbread(2))[0]
                    if status == 0:
                        self.config.is_brom = True
                        return self.mtk.config.meid
                    else:
                        self.error("Error on get_meid: " + self.eh.status(status))
            elif int.from_bytes(res, 'little') > 2:
                self.usbwrite(self.Cmd.GET_ME_ID.value)
                if self.usbread(1) == self.Cmd.GET_ME_ID.value:
                    length = unpack(">I", self.usbread(4))[0]
                    self.mtk.config.meid = self.usbread(length)
                    status = unpack("<H", self.usbread(2))[0]
                    self.config.is_brom = False
                    if status == 0:
                        return self.mtk.config.meid
                    else:
                        self.error("Error on get_meid: " + self.eh.status(status))
                self.config.is_brom = False
        return None

    def get_socid(self):
        if self.usbwrite(self.Cmd.GET_BL_VER.value):
            res = self.usbread(1)
            if res == self.Cmd.GET_BL_VER.value:
                self.usbwrite(self.Cmd.GET_SOC_ID.value)  # 0xE7
                if self.usbread(1) == self.Cmd.GET_SOC_ID.value:
                    length = unpack(">I", self.usbread(4))[0]
                    self.mtk.config.socid = self.usbread(length)
                    status = unpack("<H", self.usbread(2))[0]
                    if status == 0:
                        return self.mtk.config.socid
                    else:
                        self.error("Error on get_socid: " + self.eh.status(status))
            elif int.from_bytes(res, 'little') > 2:
                self.usbwrite(self.Cmd.GET_SOC_ID.value)
                if self.usbread(1) == self.Cmd.GET_SOC_ID.value:
                    length = unpack(">I", self.usbread(4))[0]
                    self.mtk.config.socid = self.usbread(length)
                    status = unpack("<H", self.usbread(2))[0]
                    self.config.is_brom = False
                    if status == 0:
                        return self.mtk.config.socid
                    else:
                        self.error("Error on get_socid: " + self.eh.status(status))
                self.config.is_brom = False
        return b""

    @staticmethod
    def prepare_data(data, sigdata=b"", maxsize=0):
        gen_chksum = 0
        data = (data[:maxsize] + sigdata)
        if len(data + sigdata) % 2 != 0:
            data += b"\x00"
        for x in range(0, len(data), 2):
            gen_chksum ^= unpack("<H", data[x:x + 2])[0]  # 3CDC
        if len(data) & 1 != 0:
            gen_chksum ^= data[-1:]
        return gen_chksum, data

    def upload_data(self, data, gen_chksum):
        self.config.set_gui_status(self.config.tr("Uploading data."))
        bytestowrite = len(data)
        pos = 0
        while bytestowrite > 0:
            size = min(bytestowrite, 64)
            self.usbwrite(data[pos:pos + size])
            bytestowrite -= size
            pos += size
        self.usbwrite(b"")
        time.sleep(0.035)
        try:
            res = self.rword(2)
            if isinstance(res, list) and res == []:
                self.error("No reply from da loader.")
                return False
            if isinstance(res, list):
                checksum, status = res
                if gen_chksum != checksum and checksum != 0:
                    self.warning("Checksum of upload doesn't match !")
                if 0 <= status <= 0xFF:
                    return True
                else:
                    self.error("upload_data failed with error: " + self.eh.status(status))
                    return False
            else:
                self.error("Error on getting checksum while uploading data.")
                return False
        except Exception as e:
            self.error(f"upload_data resp error : {str(e)}")
            return False
        return True

    def send_da(self, address, size, sig_len, dadata):
        self.config.set_gui_status(self.config.tr("Sending DA."))
        gen_chksum, data = self.prepare_data(dadata[:-sig_len], dadata[-sig_len:], size)
        if not self.echo(self.Cmd.SEND_DA.value):  # 0xD7
            self.error("Error on DA_Send cmd")
            self.config.set_gui_status(self.config.tr("Error on DA_Send cmd"))
            return False
        if not self.echo(address):
            self.error("Error on DA_Send address")
            self.config.set_gui_status(self.config.tr("Error on DA_Send address"))
            return False
        if not self.echo(len(data)):
            self.error("Error on DA_Send size")
            self.config.set_gui_status(self.config.tr("Error on DA_Send size"))
            return False
        if not self.echo(sig_len):
            self.error("Error on DA_Send sig_len")
            self.config.set_gui_status(self.config.tr("Error on DA_Send sig_len"))
            return False

        status = self.rword()
        if status == 0x1D0D:
            self.info("SLA required ...")
            if not self.handle_sla(func=None, isbrom=self.config.is_brom):
                self.info("Bad sla challenge :(")
                return False
            status = 0
        if 0 <= status <= 0xFF:
            if not self.upload_data(data, gen_chksum):
                self.error("Error on uploading da data")
                return False
            else:
                return True
        self.error(f"DA_Send status error:{self.eh.status(status)}")
        self.config.set_gui_status(self.config.tr("Error on DA_Send"))
        return False


if __name__ == "__main__":
    """
    e = bytes_to_long(bytes.fromhex("010001"))
    n = bytes_to_long(bytes.fromhex(
        "C43469A95B143CDC63CE318FE32BAD35B9554A136244FA74D13947425A32949EE6DC808CDEBF4121687A570B83C51E657303C925EC280B420C757E5A63AD3EC6980AAD5B6CA6D1BBDC50DB793D2FDDC0D0361C06163CFF9757C07F96559A2186322F7ABF1FFC7765F396673A48A4E8E3296427BC5510D0F97F54E5CA1BD7A93ADE3F6A625056426BDFE77B3B502C68A18F08B470DA23B0A2FAE13B8D4DB3746255371F43306582C74794D1491E97FDE504F0B1ECAC9DDEF282D674B817B7FFA8522672CF6281790910378FEBFA7DC6C2B0AF9DA03A58509D60AA1AD6F9BFDC84537CD0959B8735FE0BB9B471104B458A38DF846366926993097222F90628528F"))
    d = bytes_to_long(bytes.fromhex(
        "8E02CDB389BBC52D5383EBB5949C895B0850E633CF7DD3B5F7B5B8911B0DDF2A80387B46FAF67D22BC2748978A0183B5B420BA579B6D847082EA0BD14AB21B6CCCA175C66586FCE93756C2F426C85D7DF07629A47236265D1963B8354CB229AFA2E560B7B3641DDB8A0A839ED8F39BA8C7CDB94104650E8C7790305E2FF6D18206F49B7290B1ADB7B4C523E10EBF53630D438EF49C877402EA3C1BD6DD903892FD662FBDF1DFF5D7B095712E58E728BD7F6A8B5621175F4C08EBD6143CDACD65D9284DFFECAB64F70FD63182E4981551522727A2EE9873D0DB78180C26553AD0EE1CAAA21BCEBC5A8C0B331FE7FD8710F905A7456AF675A04AF1118CE71E36C9"))
    data=bytearray([0xA,0xB,0xC,0xD,0xE,0xF,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9])
    msg = generate_rsa_challenge(n,d,data)
    print(msg.hex())
    """
    data = bytearray([0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9])
    # from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP

    # E_DA=bytes_to_long(bytes.fromhex("010001"))
    # N_DA= bytes_to_long(bytes.fromhex("A243F6694336D527C5B3ED569DDD0386D309C6592841E4C033DCB461EEA7B6F8535FC49" +
    # "39E403060646A970DD81DE367CF003848146F19D259F50A385015AF6309EAA71BFED6B098C7A24D4871B4B82AAD7DC6E2856C301BE" +
    # "7CDB46DC10795C0D30A68DD8432B5EE5DA42BA22124796512FCA21D811D50B34C2F672E25BCC2594D9C012B34D473EE222D1E56B90" +
    # "E7D697CEA97E8DD4CCC6BED5FDAECE1A43F96495335F322CCE32612DAB462B024281841F553FF7FF33E0103A7904037F8FE5D9BE29" +
    # "3ACD7485CDB50957DB11CA6DB28AF6393C3E78D9FBCD4567DEBCA2601622F0F2EB19DA9192372F9EA3B28B1079409C0A09E3D51D64" +
    # "A4C4CE026FAD24CD7"))
    # D_DA= bytes_to_long(bytes.fromhex("707C8892D0DE8CE0CA116914C8BD277B821E784D298D00D3473EDE236399435F85410095" +
    # "25C2786CB3ED3D7530D47C9163692B0D588209E7E0E8D06F4A69725498B979599DC576303B5D8D96F874687A310D32E8C86E965B84" +
    # "4BC2ACE51DC5E06859EA087BD536C39DCB8E1262FDEAF6DA20035F14D3592AB2C1B58734C5C62AC86FE44F98C602BABAB60A6C8D09" +
    # "A199D2170E373D9B9A5D9B6DE852E859DEB1BDF33034DCD91EC4EEBFDDBECA88E29724391BB928F40EFD945299DFFC4595BB8D45F4" +
    # "26AC15EC8B1C68A19EB51BEB2CC6611072AE5637DF0ABA89ED1E9CB8C9AC1EB05B1F01734DB303C23BE1869C9013561B9F6EA65BD2" +
    # "516DE950F08B2E81"))
    e = bytes_to_long(bytes.fromhex("010001"))
    n = bytes_to_long(bytes.fromhex(
        "C43469A95B143CDC63CE318FE32BAD35B9554A136244FA74D13947425A32949EE6DC808CDEBF4121687A570B83C51E657303C925" +
        "EC280B420C757E5A63AD3EC6980AAD5B6CA6D1BBDC50DB793D2FDDC0D0361C06163CFF9757C07F96559A2186322F7ABF1FFC7765" +
        "F396673A48A4E8E3296427BC5510D0F97F54E5CA1BD7A93ADE3F6A625056426BDFE77B3B502C68A18F08B470DA23B0A2FAE13B8D" +
        "4DB3746255371F43306582C74794D1491E97FDE504F0B1ECAC9DDEF282D674B817B7FFA8522672CF6281790910378FEBFA7DC6C2" +
        "B0AF9DA03A58509D60AA1AD6F9BFDC84537CD0959B8735FE0BB9B471104B458A38DF846366926993097222F90628528F"))
    d = bytes_to_long(bytes.fromhex(
        "8E02CDB389BBC52D5383EBB5949C895B0850E633CF7DD3B5F7B5B8911B0DDF2A80387B46FAF67D22BC2748978A0183B5B420BA57" +
        "9B6D847082EA0BD14AB21B6CCCA175C66586FCE93756C2F426C85D7DF07629A47236265D1963B8354CB229AFA2E560B7B3641DDB" +
        "8A0A839ED8F39BA8C7CDB94104650E8C7790305E2FF6D18206F49B7290B1ADB7B4C523E10EBF53630D438EF49C877402EA3C1BD6" +
        "DD903892FD662FBDF1DFF5D7B095712E58E728BD7F6A8B5621175F4C08EBD6143CDACD65D9284DFFECAB64F70FD63182E4981551" +
        "522727A2EE9873D0DB78180C26553AD0EE1CAAA21BCEBC5A8C0B331FE7FD8710F905A7456AF675A04AF1118CE71E36C9"))
    rsakey = RSA.construct((n, e, d))
    encryptor = PKCS1_OAEP.new(rsakey)
    encrypted = encryptor.encrypt(data)
    decrypted = encryptor.decrypt(encrypted)
    print(encrypted.hex())
    print(decrypted.hex())
