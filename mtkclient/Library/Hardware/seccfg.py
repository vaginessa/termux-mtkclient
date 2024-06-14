from struct import pack
import os
import hashlib
import logging
from io import BytesIO
from mtkclient.Library.utils import structhelper_io
from mtkclient.Library.utils import LogBase
from mtkclient.config.mtk_config import Mtk_Config


class seccfgV4(metaclass=LogBase):
    def __init__(self, hwc, mtk, loglevel=logging.INFO):
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.hwtype = None
        self.hwc = hwc
        self.mtk = mtk
        self.magic = 0x4D4D4D4D
        self.seccfg_ver = None
        self.seccfg_size = None
        self.lock_state = None
        self.critical_lock_state = None
        self.sboot_runtime = None
        self.endflag = 0x45454545
        self.hash = b""
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def parse(self, data):
        rf = structhelper_io(BytesIO(bytearray(data)))
        self.magic = rf.dword()
        self.seccfg_ver = rf.dword()
        self.seccfg_size = rf.dword()
        self.lock_state = rf.dword()
        self.critical_lock_state = rf.dword()
        self.sboot_runtime = rf.dword()
        self.endflag = rf.dword()
        rf.seek(self.seccfg_size - 0x20)
        self.hash = rf.bytes(0x20)
        if self.magic != 0x4D4D4D4D or self.endflag != 0x45454545:
            self.error("Unknown V4 seccfg structure !")
            return False
        seccfg_data = pack("<IIIIIII", self.magic, self.seccfg_ver, self.seccfg_size, self.lock_state,
                           self.critical_lock_state, self.sboot_runtime, 0x45454545)
        hash = hashlib.sha256(seccfg_data).digest()
        dec_hash = self.hwc.sej.sej_sec_cfg_sw(self.hash, False)
        if hash == dec_hash:
            self.hwtype = "SW"
        else:
            dec_hash = self.hwc.sej.sej_sec_cfg_hw(self.hash, False)
            if hash == dec_hash:
                self.hwtype = "V2"
            else:
                dec_hash = self.hwc.sej.sej_sec_cfg_hw_V3(self.hash, False)
                if hash == dec_hash:
                    self.hwtype = "V3"
                else:
                    return False
        return True

        """
        LKS_DEFAULT = 0x01
        LKS_MP_DEFAULT = 0x02
        LKS_UNLOCK = 0x03
        LKS_LOCK = 0x04
        LKS_VERIFIED = 0x05
        LKS_CUSTOM = 0x06
        LKCS_UNLOCK = 0x01
        LKCS_LOCK = 0x02
        SBOOT_RUNTIME_OFF = 0
        SBOOT_RUNTIME_ON  = 1
        """

    def create(self, lockflag: str = "unlock"):
        if lockflag == "lock" and self.lock_state == 1:
            return False, "Device is already locked"
        elif lockflag == "unlock" and self.lock_state == 3:
            return False, "Device is already unlocked"
        if lockflag == "unlock":
            self.lock_state = 3
            self.critical_lock_state = 1
        elif lockflag == "lock":
            self.lock_state = 1
            self.critical_lock_state = 0
        seccfg_data = pack("<IIIIIII", self.magic, self.seccfg_ver, self.seccfg_size, self.lock_state,
                           self.critical_lock_state, self.sboot_runtime, 0x45454545)
        dec_hash = hashlib.sha256(seccfg_data).digest()
        enc_hash = b""
        if self.hwtype == "SW":
            enc_hash = self.hwc.sej.sej_sec_cfg_sw(dec_hash, True)
        elif self.hwtype == "V2":
            enc_hash = self.hwc.sej.sej_sec_cfg_hw(dec_hash, True)
        elif self.hwtype == "V3":
            enc_hash = self.hwc.sej.sej_sec_cfg_hw_V3(dec_hash, True)
        data = seccfg_data + enc_hash
        while len(data) % 0x200 != 0:
            data += b"\x00"
        return True, bytearray(data)


class SECCFG_STATUS:
    SEC_CFG_COMPLETE_NUM = 0x43434343  # CCCC
    SEC_CFG_INCOMPLETE_NUM = 0x49494949  # IIII


class SECCFG_ATTR:
    ATTR_LOCK = 0x6000
    ATTR_VERIFIED = 0x6001
    ATTR_CUSTOM = 0x6002
    ATTR_MP_DEFAULT = 0x6003
    ATTR_DEFAULT = 0x33333333
    ATTR_UNLOCK = 0x44444444


class SIU_STATUS:
    UBOOT_UPDATED_BY_SIU = 0x0001
    BOOT_UPDATED_BY_SIU = 0x0010
    RECOVERY_UPDATED_BY_SIU = 0x0100
    SYSTEM_UPDATED_BY_SIU = 0x1000


class ROM_TYPE:
    NORMAL_ROM = 0x01
    YAFFS_IMG = 0x08


class SEC_IMG_ATTR:
    ATTR_SEC_IMG_UPDATE = 0x10,
    ATTR_SEC_IMG_COMPLETE = 0x43434343,  # CCCC
    ATTR_SEC_IMG_INCOMPLETE = 0x49494949,  # IIII
    ATTR_SEC_IMG_FORCE_UPDATE = 0x46464646  # FFFF


class seccfgV3(metaclass=LogBase):
    def __init__(self, hwc, mtk, loglevel=logging.INFO):
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.hwtype = None
        self.data = None
        self.org_data = None
        self.hwc = hwc
        self.mtk = mtk
        self.info_header = b"AND_SECCFG_v\x00\x00\x00\x00"
        self.magic = 0x4D4D4D4D
        self.seccfg_ver = 3
        self.seccfg_size = 0x1860
        self.seccfg_enc_len = 0x01000000  # 0x07F20000 for unlocked
        self.seccfg_enc_offset = 0
        self.endflag = 0x45454545
        self.sw_sec_lock_try = 0
        self.sw_sec_lock_done = 0
        self.page_size = 0
        self.page_count = 0
        self.imginfo = b"\x00" * (0x68 * 20)
        self.siu_status = 0
        self.seccfg_status = SECCFG_STATUS.SEC_CFG_COMPLETE_NUM
        self.seccfg_attr = SECCFG_ATTR.ATTR_DEFAULT
        self.seccfg_ext = b"\x00" * 0x1004
        if self.hwc.read32 is not None:
            self.setotp(hwc)
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def setotp(self, hwc):
        otp = None
        if self.mtk.config.preloader is not None:
            idx = self.mtk.config.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                otp = self.mtk.config.preloader[idx + 0xC:idx + 0xC + 32]
        if otp is None:
            otp = 32 * b"\x00"
        hwc.sej.sej_set_otp(otp)

    def parse(self, data):
        if data[:0x10] != b"AND_SECCFG_v\x00\x00\x00\x00":
            return False
        rf = structhelper_io(BytesIO(bytearray(data)))
        self.info_header = rf.bytes(0x10)
        self.magic = rf.dword()
        self.seccfg_ver = rf.dword()
        self.seccfg_size = rf.dword()
        self.seccfg_enc_offset = rf.dword()
        self.seccfg_enc_len = rf.dword()  # 0x1 = Locked, 0xF207 = Unlocked
        self.sw_sec_lock_try = rf.bytes(1)
        self.sw_sec_lock_done = rf.bytes(1)
        self.page_size = rf.short()
        self.page_count = rf.dword()
        self.data = rf.bytes(self.seccfg_size - 0x2C - 4)
        self.endflag = rf.dword()
        if self.magic != 0x4D4D4D4D or self.endflag != 0x45454545:
            self.error("Unknown V3 seccfg structure !")
            return False
        ret = self.hwc.sej.sej_sec_cfg_sw(self.data, False)
        if ret[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
            ret = self.hwc.sej.sej_sec_cfg_hw_V3(self.data, False)
            if ret[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
                ret = self.hwc.sej.sej_sec_cfg_hw(self.data, False)
                if ret[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
                    self.error("Unknown V3 seccfg encryption !")
                    return False
                else:
                    self.hwtype = "V3"
            else:
                self.hwtype = "V2"
        else:
            self.hwtype = "SW"
        self.org_data = ret
        ed = structhelper_io(BytesIO(bytearray(ret)))
        self.imginfo = [ed.bytes(0x68) for _ in range(20)]
        self.siu_status = ed.dword()
        self.seccfg_status = ed.dword()
        if self.seccfg_status not in [SECCFG_STATUS.SEC_CFG_COMPLETE_NUM, SECCFG_STATUS.SEC_CFG_INCOMPLETE_NUM]:
            return False
        self.seccfg_attr = ed.dword()
        if self.seccfg_attr not in [SECCFG_ATTR.ATTR_DEFAULT, SECCFG_ATTR.ATTR_UNLOCK, SECCFG_ATTR.ATTR_MP_DEFAULT,
                                    SECCFG_ATTR.ATTR_LOCK, SECCFG_ATTR.ATTR_CUSTOM, SECCFG_ATTR.ATTR_VERIFIED]:
            return False
        self.seccfg_ext = ed.bytes(0x1000 + 4)
        return True

    def create(self, lockflag: str = "unlock"):
        seccfg_attr_new = SECCFG_ATTR.ATTR_DEFAULT
        if lockflag == "unlock":
            self.seccfg_enc_len = 0x07F20000
            seccfg_attr_new = SECCFG_ATTR.ATTR_UNLOCK
        elif lockflag == "lock":
            self.seccfg_enc_len = 0x01000000
            seccfg_attr_new = SECCFG_ATTR.ATTR_DEFAULT

        if lockflag == "lock" and self.seccfg_attr != SECCFG_ATTR.ATTR_UNLOCK:
            return False, "Can't find lock state, current (%#x)" % self.seccfg_attr
        elif lockflag == "unlock" and self.seccfg_attr != SECCFG_ATTR.ATTR_DEFAULT \
                and self.seccfg_attr != SECCFG_ATTR.ATTR_MP_DEFAULT \
                and self.seccfg_attr != SECCFG_ATTR.ATTR_CUSTOM \
                and self.seccfg_attr != SECCFG_ATTR.ATTR_VERIFIED \
                and self.seccfg_attr != SECCFG_ATTR.ATTR_LOCK:
            return False, "Can't find unlock state, current (%#x)" % self.seccfg_attr

        data = bytearray()
        wf = BytesIO(data)
        wf.write(self.info_header)
        wf.write(int.to_bytes(self.magic, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_ver, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_size, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_enc_offset, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_enc_len, 4, 'little'))
        wf.write(int.to_bytes(self.sw_sec_lock_try, 1, 'little'))
        wf.write(int.to_bytes(self.sw_sec_lock_done, 1, 'little'))
        wf.write(int.to_bytes(self.page_size, 2, 'little'))
        wf.write(int.to_bytes(self.page_count, 4, 'little'))

        ed = BytesIO()
        for imginfo in self.imginfo:
            ed.write(imginfo)
        ed.write(int.to_bytes(self.siu_status, 4, 'little'))
        ed.write(int.to_bytes(self.seccfg_status, 4, 'little'))
        ed.write(int.to_bytes(seccfg_attr_new, 4, 'little'))
        ed.write(self.seccfg_ext)
        data = ed.getbuffer()
        if self.hwtype == "SW":
            data = self.hwc.sej.sej_sec_cfg_sw(data, True)
        elif self.hwtype == "V2":
            data = self.hwc.sej.sej_sec_cfg_hw(data, True)
        elif self.hwtype == "V3":
            data = self.hwc.sej.sej_sec_cfg_hw_V3(data, True)
        else:
            return False, "Unknown error"
        wf.write(data)
        wf.write(int.to_bytes(self.endflag, 4, 'little'))

        data = bytearray(wf.getbuffer())
        while len(data) % 0x200 != 0:
            data += b"\x00"
        return True, bytearray(data)


if __name__ == "__main__":
    with open("seccfg.bin", "rb") as rf:
        data = rf.read()
    from hwcrypto import hwcrypto, crypto_setup

    setup = crypto_setup()
    hwc = hwcrypto(setup)

    class mtk:
        config = Mtk_Config()
        sej_base = None

    v3 = seccfgV3(hwc, mtk)
    v3.parse(data)
    ret, newdata = v3.create("lock")
    print(newdata.hex())
