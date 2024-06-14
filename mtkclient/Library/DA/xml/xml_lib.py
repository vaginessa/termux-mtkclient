#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023 GPLv3 License
import logging
import os
from struct import pack, unpack

from mtkclient.Library.DA.xml.xml_param import DataType, FtSystemOSE, LogLevel
from mtkclient.Library.utils import logsetup, LogBase
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.DA.daconfig import EMMC_PartitionType, UFS_PartitionType, DaStorage
from mtkclient.Library.partition import Partition
from mtkclient.config.payloads import pathconfig
from mtkclient.Library.thread_handling import writedata
from queue import Queue
from threading import Thread
from mtkclient.Library.DA.xml.xml_cmd import XMLCmd, BootModes
from mtkclient.Library.DA.xml.extension.v6 import xmlflashext

rq = Queue()


class ShutDownModes:
    TEST = 3
    META = 4
    NORMAL = 0
    HOME_SCREEN = 1
    FASTBOOT = 2


def get_field(data, fieldname):
    if isinstance(data, bytes) or isinstance(data, bytearray):
        data = data.decode('utf-8')
    start = data.find(f"<{fieldname}>")
    if start != -1:
        end = data.find(f"</{fieldname}>", start + len(fieldname) + 2)
        if start != -1 and end != -1:
            return data[start + len(fieldname) + 2:end]
    return ""


class file_sys_op:
    key = None
    file_path = None

    def __init__(self, key, file_path):
        self.key = key
        self.file_path = file_path


class upfile:
    checksum = None
    info = None
    source_file = None
    packet_length = None

    def __init__(self, checksum, info, target_file, packet_length):
        self.checksum = checksum
        self.info = info
        self.target_file = target_file
        self.packet_length = packet_length


class dwnfile:
    checksum = None
    info = None
    source_file = None
    packet_length = None

    def __init__(self, checksum: str, info: str, source_file: str, packet_length: int):
        self.checksum = checksum
        self.info = info
        self.source_file = source_file
        self.packet_length = packet_length


class DAXML(metaclass=LogBase):
    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.Cmd = XMLCmd(mtk)
        self.mtk = mtk
        self.loglevel = loglevel
        self.daext = False
        self.sram = None
        self.dram = None
        self.emmc = None
        self.nand = None
        self.nor = None
        self.ufs = None
        self.chipid = None
        self.randomid = None
        self.__logger = self.__logger
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.rword = self.mtk.port.rword
        self.daconfig = daconfig
        self.partition = Partition(self.mtk, self.readflash, self.read_partition_table, loglevel)
        self.pathconfig = pathconfig()
        self.patch = False
        self.generatekeys = self.mtk.config.generatekeys
        if self.generatekeys:
            self.patch = True
        try:
            from mtkclient.Library.Exploit.carbonara import Carbonara
            self.carbonara = Carbonara(self.mtk, loglevel)
        except Exception:
            self.carbonara = None

        self.xmlft = xmlflashext(self.mtk, self, loglevel)

    def xread(self):
        try:
            hdr = self.usbread(4 + 4 + 4)
            magic, datatype, length = unpack("<III", hdr)
        except Exception as err:
            self.error("xread error: " + str(err))
            return -1
        if magic != 0xFEEEEEEF:
            self.error("xread error: Wrong magic")
            return -1
        resp = self.usbread(length)
        return resp

    def xsend(self, data, datatype=DataType.DT_PROTOCOL_FLOW, is64bit: bool = False):
        if isinstance(data, int):
            if is64bit:
                data = pack("<Q", data)
                length = 8
            else:
                data = pack("<I", data)
                length = 4
        else:
            if type(data) is str:
                length = len(data) + 1
            else:
                length = len(data)
        tmp = pack("<III", self.Cmd.MAGIC, datatype, length)
        if self.usbwrite(tmp):
            if type(data) is str:
                return self.usbwrite(bytes(data, 'utf-8') + b"\x00")
            else:
                return self.usbwrite(data)
        return False

    def ack(self):
        return self.xsend("OK")

    def ack_value(self, length):
        return self.xsend(f"OK@{hex(length)}")

    def ack_text(self, text):
        return self.xsend(f"OK@{text}")

    def setup_env(self):
        da_log_level = int(self.daconfig.uartloglevel)
        loglevel = "INFO"
        if da_log_level == 0:
            loglevel = LogLevel().TRACE
        elif da_log_level == 1:
            loglevel = LogLevel().DEBUG
        elif da_log_level == 2:
            loglevel = LogLevel().INFO
        elif da_log_level == 3:
            loglevel = LogLevel().WARN
        elif da_log_level == 4:
            loglevel = LogLevel().ERROR
        system_os = FtSystemOSE.OS_LINUX
        res = self.send_command(self.Cmd.cmd_set_runtime_parameter(da_log_level=loglevel, system_os=system_os))
        return res

    def send_command(self, xmldata, noack: bool = False):
        if self.xsend(xmldata):
            result = self.get_response()
            if result == "OK":
                if noack:
                    return True
                cmd, result = self.get_command_result()
                if cmd == "CMD:END":
                    self.ack()
                    scmd, sresult = self.get_command_result()
                    if scmd == "CMD:START":
                        if result == "OK":
                            return True
                        else:
                            self.error(result)
                            return False
                else:
                    return result
            elif result == "ERR!UNSUPPORTED":
                scmd, sresult = self.get_command_result()
                self.ack()
                tcmd, tresult = self.get_command_result()
                if tcmd == "CMD:START":
                    return sresult
            elif "ERR!" in result:
                return result
        return False

    def get_response(self, raw: bool = False) -> str:
        sync = self.usbread(4 * 3)
        if len(sync) == 4 * 3:
            if int.from_bytes(sync[:4], 'little') == 0xfeeeeeef:
                if int.from_bytes(sync[4:8], 'little') == 0x1:
                    length = int.from_bytes(sync[8:12], 'little')
                    data = self.usbread(length)
                    if len(data) == length:
                        if raw:
                            return data
                        return data.rstrip(b"\x00").decode('utf-8')
        return ""

    def get_response_data(self) -> bytes:
        sync = self.usbread(4 * 3)
        if len(sync) == 4 * 3:
            if int.from_bytes(sync[:4], 'little') == 0xfeeeeeef:
                if int.from_bytes(sync[4:8], 'little') == 0x1:
                    length = int.from_bytes(sync[8:12], 'little')
                    usbepsz = self.mtk.port.cdc.get_read_packetsize()
                    data = bytearray()
                    bytestoread = length
                    while bytestoread > 0:
                        sz = min(usbepsz, bytestoread)
                        data.extend(self.usbread(sz))
                        bytestoread -= sz
                    if len(data) == length:
                        return data
        return b""

    def patch_da(self, da1, da2):
        da1sig_len = self.daconfig.da_loader.region[1].m_sig_len
        # ------------------------------------------------
        da2sig_len = self.daconfig.da_loader.region[2].m_sig_len
        hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da1sig_len, da2sig_len,
                                                                         self.daconfig.da_loader.v6)
        if hashaddr is not None:
            da1 = self.xmlft.patch_da1(da1)
            da2 = self.xmlft.patch_da2(da2)
            da1 = self.mtk.daloader.fix_hash(da1, da2, hashaddr, hashmode, hashlen)
            self.mtk.daloader.patch = True
        else:
            self.mtk.daloader.patch = False
            self.daconfig.da2 = da2[:-da2sig_len]
        return da1, da2

    def upload_da1(self):
        if self.daconfig.da_loader is None:
            self.error("No valid da loader found... aborting.")
            return False
        loader = self.daconfig.loader
        self.info(f"Uploading xflash stage 1 from {os.path.basename(loader)}")
        if not os.path.exists(loader):
            self.info(f"Couldn't find {loader}, aborting.")
            return False
        with open(loader, 'rb') as bootldr:
            # stage 1
            da1offset = self.daconfig.da_loader.region[1].m_buf
            bootldr.seek(da1offset)
            # ------------------------------------------------
            da2offset = self.daconfig.da_loader.region[2].m_buf
            bootldr.seek(da2offset)
            da1offset = self.daconfig.da_loader.region[1].m_buf
            da1size = self.daconfig.da_loader.region[1].m_len
            da1address = self.daconfig.da_loader.region[1].m_start_addr
            da1sig_len = self.daconfig.da_loader.region[1].m_sig_len
            bootldr.seek(da1offset)
            da1 = bootldr.read(da1size)
            # ------------------------------------------------
            da2offset = self.daconfig.da_loader.region[2].m_buf
            da2sig_len = self.daconfig.da_loader.region[2].m_sig_len
            bootldr.seek(da2offset)
            da2 = bootldr.read(self.daconfig.da_loader.region[2].m_len)
            if self.patch or not self.config.target_config["sbc"]:
                da1, da2 = self.patch_da(da1,da2)
                self.patch = True
            else:
                self.patch = False
            self.daconfig.da2 = da2[:-da2sig_len]

            if self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                self.info("Successfully uploaded stage 1, jumping ..")
                if self.mtk.preloader.jump_da(da1address):
                    cmd, result = self.get_command_result()
                    if cmd == "CMD:START":
                        self.setup_env()
                        self.setup_hw_init()
                        self.setup_host_info()
                        return True
                    else:
                        return False
                else:
                    self.error("Error on jumping to DA.")
            else:
                self.error("Error on sending DA.")
        return False

    def setup_hw_init(self):
        self.send_command(self.Cmd.cmd_host_supported_commands(
            host_capability="CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@"))
        self.send_command(self.Cmd.cmd_notify_init_hw())
        return True

    def setup_host_info(self, hostinfo: str = ""):
        res = self.send_command(self.Cmd.cmd_set_host_info(hostinfo))
        return res

    def write_register(self, addr, data):
        result = self.send_command(self.Cmd.cmd_write_reg(bit_width=32, base_address=addr))
        if type(result) is dwnfile:
            if self.upload(result, data):
                self.info("Successfully wrote data.")
                return True
        return False

    def read_efuse(self):
        tmp = self.Cmd.cmd_read_efuse()
        self.send_command(tmp)
        cmd, result = self.get_command_result()
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return result
        return None

    def read_register(self, addr):
        tmp = self.Cmd.cmd_read_reg(base_address=addr)
        if self.send_command(tmp):
            cmd, data = self.get_command_result()
            if cmd != '':
                return False
            # CMD:END
            scmd, sresult = self.get_command_result()
            self.ack()
            if sresult == "OK":
                tcmd, tresult = self.get_command_result()
                if tresult == "START":
                    return data
            return None

    def get_command_result(self):
        data = self.get_response()
        cmd = get_field(data, "command")
        result = ""
        if cmd == '' and "OK@" in data:
            tmp = data.split("@")[1]
            length = int(tmp[2:], 16)
            self.ack()
            sresp = self.get_response()
            if "OK" in sresp:
                self.ack()
                data = bytearray()
                bytesread = 0
                bytestoread = length
                while bytestoread > 0:
                    tmp = self.get_response_data()
                    bytestoread -= len(tmp)
                    bytesread += len(tmp)
                    data.extend(tmp)
                self.ack()
                return cmd, data
        if cmd == "CMD:PROGRESS-REPORT":
            """
            <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version>
            <command>CMD:PROGRESS-REPORT</command>
            <arg>
                <message>init-hw</message>
            </arg></host>
            """
            self.ack()
            data = ""
            while data != "OK!EOT":
                data = self.get_response()
                self.ack()
            data = self.get_response()
            cmd = get_field(data, "command")
        if cmd == "CMD:START":
            self.ack()
            return cmd, "START"
        if cmd == "CMD:DOWNLOAD-FILE":
            """
            <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version>
            <command>CMD:DOWNLOAD-FILE</command>
            <arg>
                <checksum>CHK_NO</checksum>
                <info>2nd-DA</info>
                <source_file>MEM://0x7fe83c09a04c:0x50c78</source_file>
                <packet_length>0x1000</packet_length>
            </arg></host>
            """
            checksum = get_field(data, "checksum")
            info = get_field(data, "info")
            source_file = get_field(data, "source_file")
            packet_length = int(get_field(data, "packet_length"), 16)
            self.ack()
            return cmd, dwnfile(checksum, info, source_file, packet_length)
        elif cmd == "CMD:UPLOAD-FILE":
            checksum = get_field(data, "checksum")
            info = get_field(data, "info")
            target_file = get_field(data, "target_file")
            packet_length = get_field(data, "packet_length")
            self.ack()
            return cmd, upfile(checksum, info, target_file, packet_length)
        elif cmd == "CMD:FILE-SYS-OPERATION":
            """
            '<?xml version="1.0" encoding="utf-8"?><host><version>1.0</version><command>CMD:FILE-SYS-OPERATION</command><arg><key>FILE-SIZE</key><file_path>MEM://0x8000000:0x4000000</file_path></arg></host>'
            """
            key = get_field(data, "key")
            file_path = get_field(data, "file_path")
            self.ack()
            return cmd, file_sys_op(key, file_path)
        if cmd == "CMD:END":
            result = get_field(data, "result")
            if "message" in data and result != "OK":
                message = get_field(data, "message")
                return cmd, message
        return cmd, result

    def upload(self, result: dwnfile, data, display=True, raw=False):
        if type(result) is dwnfile:
            # checksum = result.checksum
            # info = result.info
            source_file = result.source_file
            packet_length = result.packet_length
            tmp = source_file.split(":")[2]
            length = int(tmp[2:], 16)
            self.ack_value(length)
            if display:
                self.mtk.daloader.progress.clear()
            resp = self.get_response()
            byteswritten = 0
            if resp == "OK":
                for pos in range(0, length, packet_length):
                    self.ack_value(0)
                    resp = self.get_response()
                    if "OK" not in resp:
                        msg = get_field(resp, "message")
                        self.error(f"Error on writing stage2 ACK0 at pos {hex(pos)}")
                        self.error(msg)
                        return False
                    tmp = data[pos:pos + packet_length]
                    tmplen = len(tmp)
                    self.xsend(data=tmp)
                    resp = self.get_response()
                    if "OK" not in resp:
                        self.error(f"Error on writing stage2 at pos {hex(pos)}")
                        return False
                    byteswritten += tmplen
                    if display:
                        self.mtk.daloader.progress.show_progress("Written", byteswritten, length, display)
                if raw:
                    self.ack()
                cmd, result = self.get_command_result()
                self.ack()
                if cmd == "CMD:END" and result == "OK":
                    cmd, result = self.get_command_result()
                    if cmd == "CMD:START":
                        return True
                else:
                    cmd, startresult = self.get_command_result()
                    self.error(result)
            return False
        else:
            self.error("No upload data received. Aborting.")
            return False

    def download_raw(self, result, filename: str = "", display: bool = False):
        global rq
        if display:
            self.mtk.daloader.progress.clear()
        if type(result) is upfile:
            # checksum = result.checksum
            # info = result.info
            # target_file = result.target_file
            # packet_length = int(result.packet_length, 16)
            resp = self.get_response()
            if "OK@" in resp:
                tmp = resp.split("@")[1]
                length = int(tmp[2:], 16)
                self.ack()
                sresp = self.get_response()
                if "OK" in sresp:
                    self.ack()
                    data = bytearray()
                    bytesread = 0
                    bytestoread = length
                    worker = None
                    if filename != "":
                        worker = Thread(target=writedata, args=(filename, rq), daemon=True)
                        worker.start()
                    while bytestoread > 0:
                        tmp = self.get_response_data()
                        bytestoread -= len(tmp)
                        bytesread += len(tmp)
                        if filename != "":
                            rq.put(tmp)
                        else:
                            data.extend(tmp)
                        if display:
                            self.mtk.daloader.progress.show_progress("Read", bytesread, length, display)
                        self.ack()
                        sresp = self.get_response()
                        if "OK" not in sresp:
                            break
                        else:
                            self.ack()
                    if filename != "":
                        rq.put(None)
                        worker.join(60)
                        return True
                    return data
            self.error("Error on downloading data:" + resp)
            return False
        else:
            self.error("No download data received. Aborting.")
            return False

    def download(self, result):
        if type(result) is upfile:
            # checksum = result.checksum
            # info = result.info
            # target_file = result.target_file
            # packet_length = int(result.packet_length, 16)
            resp = self.get_response()
            if "OK@" in resp:
                tmp = resp.split("@")[1]
                length = int(tmp[2:], 16)
                self.ack()
                sresp = self.get_response()
                if "OK" in sresp:
                    self.ack()
                    data = bytearray()
                    bytesread = 0
                    bytestoread = length
                    while bytestoread > 0:
                        tmp = self.get_response_data()
                        bytestoread -= len(tmp)
                        bytesread += len(tmp)
                        data.extend(tmp)
                    self.ack()
                    return data
            self.error("Error on downloading data:" + resp)
            return False
        else:
            self.error("No download data received. Aborting.")
            return False

    def boot_to(self, addr, data, display=True, timeout=0.5):
        result = self.send_command(self.Cmd.cmd_boot_to(at_addr=addr, jmp_addr=addr, length=len(data)))
        if type(result) is dwnfile:
            self.info("Uploading stage 2...")
            if self.upload(result, data):
                self.info("Successfully uploaded stage 2.")
                return True
        else:
            self.error("Wrong boot_to response :(")
        return False

    def handle_sla(self, data=b"\x00"*0x100, display=True, timeout=0.5):
        result = self.send_command(self.Cmd.cmd_security_set_flash_policy(host_offset=0x8000000,length=len(data)))
        if type(result) is dwnfile:
            self.info("Running sla auth...")
            if self.upload(result, data):
                self.info("Successfully uploaded sla auth.")
                return True
        return False

    def upload_da(self):
        if self.upload_da1():
            self.info("Stage 1 successfully loaded.")
            da2 = self.daconfig.da2
            da2offset = self.daconfig.da_loader.region[2].m_start_addr
            if not self.mtk.daloader.patch:
                loaded = self.boot_to(da2offset, da2)
                self.daext = False
            else:
                loaded = self.boot_to(da2offset, da2)
                sla_signature = b"\x00" * 0x100
                self.handle_sla(data=sla_signature)
                xmlcmd = self.Cmd.create_cmd("CUSTOM")
                if self.xsend(xmlcmd):
                    # result =
                    data = self.get_response()
                    if data == 'OK':
                        # OUTPUT
                        xdata = self.xmlft.patch()
                        self.xsend(int.to_bytes(len(xdata), 4, 'little'))
                        self.xsend(xdata)
                        # CMD:END
                        # result =
                        self.get_response()
                        self.ack()
                        # CMD:START
                        # result =
                        self.get_response()
                        self.ack()

                        if self.xmlft.ack():
                            self.info("DA XML Extensions successfully loaded.")
                            self.daext = True
                        else:
                            self.error("DA XML Extensions failed.")
                            self.daext = False
                    else:
                        self.error("DA XML Extensions failed.")
                        self.daext = False


            if loaded:
                self.info("Successfully uploaded stage 2")
                self.setup_hw_init()
                self.change_usb_speed()
                res = self.check_sla()
                if isinstance(res, bool):
                    if not res:
                        self.info("SLA is disabled")
                    else:
                        self.info("SLA is enabled")
                else:
                    self.error(res)
                self.storage = self.get_hw_info()
                self.reinit(True)
                self.check_lifecycle()
                # parttbl = self.read_partition_table()
                self.config.hwparam.writesetting("hwcode", hex(self.config.hwcode))
                return True
        return False

    def get_hw_info(self):
        self.send_command(self.Cmd.cmd_get_hw_info(), noack=True)
        cmd, result = self.get_command_result()
        if not isinstance(result, upfile):
            return False
        data = self.download(result)
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da_hw_info>
        <version>1.2</version>
        <ram_size>0x100000000</ram_size>
        <battery_voltage>3810</battery_voltage>
        <random_id>4340bfebf6ace4e325f71f7d37ab15aa</random_id>
        <storage>UFS</storage>
        <ufs>
            <block_size>0x1000</block_size>
            <lua0_size>0x400000</lua0_size>
            <lua1_size>0x400000</lua1_size>
            <lua2_size>0xee5800000</lua2_size>
            <lua3_size>0</lua3_size>
            <id>4D54303634474153414F32553231202000000000</id>
        </ufs>
        <product_id></product_id>
        </da_hw_info>
        """
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                storage = get_field(data, "storage")

                class storage_info:
                    def __init__(self, storagetype, data):
                        self.storagetype = storagetype
                        if self.storagetype == "UFS":
                            self.block_size = int(get_field(data, "block_size"), 16)
                            self.lua0_size = int(get_field(data, "lua0_size"), 16)
                            self.lua1_size = int(get_field(data, "lua1_size"), 16)
                            self.lua2_size = int(get_field(data, "lua2_size"), 16)
                            self.lua3_size = int(get_field(data, "lua3_size"), 16)
                            self.cid = get_field(data, "id")  # this doesn't exists in Xiaomi DA
                            if not self.cid:
                                self.cid = get_field(data, "ufs_cid")
                        elif self.storagetype == "EMMC":
                            self.block_size = int(get_field(data, "block_size"), 16)
                            self.boot1_size = int(get_field(data, "boot1_size"), 16)
                            self.boot2_size = int(get_field(data, "boot2_size"), 16)
                            self.rpmb_size = int(get_field(data, "rpmb_size"), 16)
                            self.user_size = int(get_field(data, "user_size"), 16)
                            self.gp1_size = int(get_field(data, "gp1_size"), 16)
                            self.gp2_size = int(get_field(data, "gp2_size"), 16)
                            self.gp3_size = int(get_field(data, "gp3_size"), 16)
                            self.gp4_size = int(get_field(data, "gp4_size"), 16)
                            self.cid = get_field(data, "id")  # this doesn't exists in Xiaomi DA
                            if not self.cid:
                                self.cid = get_field(data, "emmc_cid")
                        elif self.storagetype == "NAND":
                            self.block_size = int(get_field(data, "block_size"), 16)
                            self.page_size = int(get_field(data, "page_size"), 16)
                            self.spare_size = int(get_field(data, "spare_size"), 16)
                            self.total_size = int(get_field(data, "total_size"), 16)
                            self.cid = get_field(data, "id")
                            self.page_parity_size = int(get_field(data, "page_parity_size"), 16)
                            self.sub_type = get_field(data, "sub_type")
                        else:
                            self.error(f"Unknown storage type: {storage}")

                return storage_info(storagetype=storage, data=data)

    def check_sla(self):
        """
        ;private_key_d="009a3c3d4da0650cef38ed96ef833904c9c13835199367c7b9cb03a55e7aa482016a820dfe597cd54dd1f81fd879cf0
        70ec0c25899ac5a49822db09675a92acf6a01e0f8f538bbe66de48ca9bdca313b616470d9ec2914356d03c95f7d9236549e5a21457e4dd5
        fcaf09046c47ca7436f06cd7b82cb6d2a936fca88b707f6ce28f33110fea1ec363e8482419db901cb0d38e574fe0c02ad117166b40ec78f
        59aaa7f3eafa425010a95614e046651273a6cb1371380c4e6ce81bdb892db6ff4892cc4d8c613a8fb3fec1e72c279052896872fc23da07f
        ba63783374f3be8e16a15e0a04a139108dd6ac239f191135f4a895e27c670de065d2248e3f9c7e920fd001"
        ;public_key_e = "00010001"
        ;public_key_n = "008C8BF38EB2FC7FC06D567DBF70E9C34BE4281C4239ED9C58A6B598C3AE7821815D94D0B463463EEBBD69FF6AF990
        AE0499B6C3B3CADCD91D54499CD66E5314DB610FC0C6CAEEB1F16B6F2D451E3F2B2D515008917FCEC50ADA4CE0699BCF247D5AE2A1DDD34
        C48624A657CCB11CE5F8C6CE92CAB6038EFC2A89E42E029488C02C3CF21947C86D51BBA8EF540A2A7CE85356F431891261D860B518E89DD
        73B2D240461ACB66BCC213403145DE83F6963147E65274EA1E45DB2D231E0774ECC86E4F2328F8A90835C4FDEF1088DDBA1D8F7CA0CA732
        A64BDA6816162C0F88F02CF97634D85530968CBF8B7CE6A8B67D53BBFB4910843EA413135D56FB5074445"

        ROWAN / 0_2048_key.pem / CHIP_TEST_KEY.ini
        e_brom = 010001
        n_brom = D16403466C530EF9BB53C1E8A96A61A4E332E17DC0F55BB46D207AC305BAE9354EAAC2CB3077B33740D275036B822DB268200D
        E17DA3DB7266B27686B8970B85737050F084F8D576904E74CD6C53B31F0BB0CD60686BF67C60DA0EC20F563EEA715CEBDBF76D1C5C10E98
        2AB2955D833DE553C9CDAFD7EA2388C02823CFE7DD9AC83FA2A8EB0685ABDAB56A92DF1A7805E8AC0BD10C0F3DCB1770A9E6BBC3418C5F8
        4A48B7CB2316B2C8F64972F391B116A58C9395A9CE9E743569A367086D7771D39FEC8EBBBA3DD2B519785A76A9F589D36D637AF884543FD
        65BAC75BE823C0C50AA16D58187B97223625C54C66B5A5E4DBAEAB7BE89A4E340A2E241B09B2F
        d_brom = 09976537029b4362591c5b13873f223de5525d55df52dde283e52afa67f6c9dbf1408d2fb586a624efc93426f5f3be981f80e8
        61ddd975a1e5e662db84f5164804a3ae717605d7f15866df9ed1497c38fdd6197243163ef22f958d7b822c57317203e9a1e7d18dad01f15
        054facdbddb9261a1272638da661fe4f9f0714ecf00e6541cc435afb1fd75a27d34b17ad400e9474ba850dafce266799caff32a058ff71e
        4c2daacaf8ba709e9ca4dc87584a7ffe8aa9a0a160ed069c3970b7dae3987ded71bd0bc824356987bd74363d46682c71913c3edbdb2a911
        f701f23aee3f8dd98180b5a138fd5ad74743682d2d2d1bb3d92786710248f316dd8391178ea81

        SetRsaKey in libsla_challenge.so :

        e_brom = 010001
        n_brom = C43469A95B143CDC63CE318FE32BAD35B9554A136244FA74D13947425A32949EE6DC808CDEBF4121687A570B83C51E657303C92
        5EC280B420C757E5A63AD3EC6980AAD5B6CA6D1BBDC50DB793D2FDDC0D0361C06163CFF9757C07F96559A2186322F7ABF1FFC7765F39667
        3A48A4E8E3296427BC5510D0F97F54E5CA1BD7A93ADE3F6A625056426BDFE77B3B502C68A18F08B470DA23B0A2FAE13B8D4DB3746255371F
        43306582C74794D1491E97FDE504F0B1ECAC9DDEF282D674B817B7FFA8522672CF6281790910378FEBFA7DC6C2B0AF9DA03A58509D60AA1A
        D6F9BFDC84537CD0959B8735FE0BB9B471104B458A38DF846366926993097222F90628528F
        d_brom = 8E02CDB389BBC52D5383EBB5949C895B0850E633CF7DD3B5F7B5B8911B0DDF2A80387B46FAF67D22BC2748978A0183B5B420BA
        579B6D847082EA0BD14AB21B6CCCA175C66586FCE93756C2F426C85D7DF07629A47236265D1963B8354CB229AFA2E560B7B3641DDB8A0A83
        9ED8F39BA8C7CDB94104650E8C7790305E2FF6D18206F49B7290B1ADB7B4C523E10EBF53630D438EF49C877402EA3C1BD6DD903892FD662
        FBDF1DFF5D7B095712E58E728BD7F6A8B5621175F4C08EBD6143CDACD65D9284DFFECAB64F70FD63182E4981551522727A2EE9873D0DB78
        180C26553AD0EE1CAAA21BCEBC5A8C0B331FE7FD8710F905A7456AF675A04AF1118CE71E36C9

        d_da = 707C8892D0DE8CE0CA116914C8BD277B821E784D298D00D3473EDE236399435F8541009525C2786CB3ED3D7530D47C9163692B0D5
        88209E7E0E8D06F4A69725498B979599DC576303B5D8D96F874687A310D32E8C86E965B844BC2ACE51DC5E06859EA087BD536C39DCB8E126
        2FDEAF6DA20035F14D3592AB2C1B58734C5C62AC86FE44F98C602BABAB60A6C8D09A199D2170E373D9B9A5D9B6DE852E859DEB1BDF33034
        DCD91EC4EEBFDDBECA88E29724391BB928F40EFD945299DFFC4595BB8D45F426AC15EC8B1C68A19EB51BEB2CC6611072AE5637DF0ABA89ED
        1E9CB8C9AC1EB05B1F01734DB303C23BE1869C9013561B9F6EA65BD2516DE950F08B2E81
        n_da = A243F6694336D527C5B3ED569DDD0386D309C6592841E4C033DCB461EEA7B6F8535FC4939E403060646A970DD81DE367CF003848
        146F19D259F50A385015AF6309EAA71BFED6B098C7A24D4871B4B82AAD7DC6E2856C301BE7CDB46DC10795C0D30A68DD8432B5EE5DA42BA2
        2124796512FCA21D811D50B34C2F672E25BCC2594D9C012B34D473EE222D1E56B90E7D697CEA97E8DD4CCC6BED5FDAECE1A43F96495335F3
        22CCE32612DAB462B024281841F553FF7FF33E0103A7904037F8FE5D9BE293ACD7485CDB50957DB11CA6DB28AF6393C3E78D9FBCD4567DE
        BCA2601622F0F2EB19DA9192372F9EA3B28B1079409C0A09E3D51D64A4C4CE026FAD24CD7
        e_da = 010001

        int RSA_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
                                    0x10,                                                 , 1
        """
        data = self.get_sys_property(key="DA.SLA", length=0x200000)
        data = data.decode('utf-8')
        if "item key=" in data:
            tmp = data[data.find("item key=") + 8:]
            res = tmp[tmp.find(">") + 1:tmp.find("<")]
            return res != "DISABLED"
        else:
            self.error("Couldn't find item key")
        return data

    def get_sys_property(self, key: str = "DA.SLA", length: int = 0x200000):
        self.send_command(self.Cmd.cmd_get_sys_property(key=key, length=length), noack=True)
        cmd, result = self.get_command_result()
        if type(result) is not upfile:
            return False
        data = self.download(result)
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return data
        return None

    def change_usb_speed(self):
        resp = self.send_command(self.Cmd.cmd_can_higher_usb_speed())
        if "Unsupported" in resp:
            return False

    def read_partition_table(self) -> tuple:
        self.send_command(self.Cmd.cmd_read_partition_table(), noack=True)
        cmd, result = self.get_command_result()
        if type(result) is not upfile:
            return b"", None
        data = self.download(result)
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()

            class partitiontable:
                def __init__(self, name, start, size):
                    self.name = name
                    self.start = start
                    self.size = size

            if tresult == "START":
                parttbl = []
                data = data.decode('utf-8')
                for item in data.split("<pt>"):
                    name = get_field(item, "name")
                    if name != '':
                        start = get_field(item, "start")
                        size = get_field(item, "size")
                        if size == "":
                            continue
                        size = int(size, 16)
                        start = int(start, 16)
                        parttbl.append(
                            partitiontable(name, start // self.config.pagesize, size // self.config.pagesize))
                return data, parttbl
        return b"", None

    def partitiontype_and_size(self, storage=None, parttype=None, length=0):
        if length < 0x20000:
            length = 0x20000
        if storage == DaStorage.MTK_DA_STORAGE_EMMC or storage == DaStorage.MTK_DA_STORAGE_SDMMC:
            storage = 1
            if parttype is None or parttype == "user":
                parttype = "EMMC-USER"
            elif parttype == "boot1":
                parttype = "EMMC-BOOT1"
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.boot1_size)
            elif parttype == "boot2":
                parttype = "EMMC-BOOT2"
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.boot2_size)
            elif parttype == "gp1":
                parttype = "EMMC-GP1"
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.gp1_size)
            else:
                self.error("Unknown parttype. Known parttypes are \"boot1\",\"boot2\",\"gp1\"," +
                           "\"gp2\",\"gp3\",\"gp4\",\"rpmb\"")
                return []
        elif storage == DaStorage.MTK_DA_STORAGE_UFS:
            if parttype is None or parttype == "lu3" or parttype == "user":  # USER
                parttype = "UFS-LUA2"
                length = min(length, self.ufs.lu3_size)
            elif parttype in ["lu1", "boot1"]:  # BOOT1
                parttype = "UFS-LUA0"
                length = min(length, self.ufs.lu1_size)
            elif parttype in ["lu2", "boot2"]:  # BOOT2
                parttype = "UFS-LUA1"
                length = min(length, self.ufs.lu2_size)
            elif parttype in ["lu4", "rpmb"]:  # RPMB
                parttype = "UFS-LUA3"
                length = min(length, self.ufs.lu4_size)
            else:
                self.error("Unknown parttype. Known parttypes are \"lu1\",\"lu2\",\"lu3\",\"lu4\"")
                return []
        elif storage in [DaStorage.MTK_DA_STORAGE_NAND, DaStorage.MTK_DA_STORAGE_NAND_MLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SLC, DaStorage.MTK_DA_STORAGE_NAND_TLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SPI, DaStorage.MTK_DA_STORAGE_NAND_AMLC]:
            parttype = "NAND-WHOLE"  # NAND-AREA0
            length = min(length, self.nand.total_size)
        elif storage in [DaStorage.MTK_DA_STORAGE_NOR, DaStorage.MTK_DA_STORAGE_NOR_PARALLEL,
                         DaStorage.MTK_DA_STORAGE_NOR_SERIAL]:
            parttype = "NOR-WHOLE"  # NOR-AREA0
            length = min(length, self.nor.available_size)
        return [storage, parttype, length]

    def getstorage(self, parttype, length):
        if self.daconfig.flashtype == "nor":
            storage = DaStorage.MTK_DA_STORAGE_NOR
        elif self.daconfig.flashtype == "nand":
            storage = DaStorage.MTK_DA_STORAGE_NAND
        elif self.daconfig.flashtype == "ufs":
            storage = DaStorage.MTK_DA_STORAGE_UFS
            if parttype == EMMC_PartitionType.MTK_DA_EMMC_PART_USER:
                parttype = UFS_PartitionType.UFS_LU3
        elif self.daconfig.flashtype == "sdc":
            storage = DaStorage.MTK_DA_STORAGE_SDMMC
        else:
            storage = DaStorage.MTK_DA_STORAGE_EMMC

        part_info = self.partitiontype_and_size(storage, parttype, length)
        return part_info

    def readflash(self, addr, length, filename, parttype=None, display=True) -> (bytes, bool):
        global rq
        if parttype is None:
            if self.daconfig.flashtype == "emmc":
                parttype = "user"
            elif self.daconfig.flashtype == "ufs":
                parttype = "lu3"
        partinfo = self.getstorage(parttype, length)
        if not partinfo:
            return b""
        self.mtk.daloader.progress.clear()
        storage, parttype, length = partinfo

        self.send_command(self.Cmd.cmd_read_flash(parttype, addr, length), noack=True)
        cmd, result = self.get_command_result()
        if type(result) is not upfile:
            return b""
        data = self.download_raw(result=result, filename=filename, display=display)
        scmd, sresult = self.get_command_result()
        if sresult == "START":
            if not filename:
                return data
            else:
                return True
        if not filename:
            return b""
        return False

    def writeflash(self, addr, length, filename, offset=0, parttype=None, wdata=None, display=True):
        self.mtk.daloader.progress.clear()
        fh = None
        fill = 0
        if filename is not None:
            if os.path.exists(filename):
                fsize = os.stat(filename).st_size
                length = min(fsize, length)
                if length % 512 != 0:
                    fill = 512 - (length % 512)
                    length += fill
                fh = open(filename, "rb")
                fh.seek(offset)
            else:
                self.error(f"Filename doesn't exists: {filename}, aborting flash write.")
                return False

        if parttype is None:
            if self.daconfig.flashtype == "emmc":
                parttype = "user"
            elif self.daconfig.flashtype == "ufs":
                parttype = "lu3"
        partinfo = self.getstorage(parttype, length)
        if not partinfo:
            return False
        storage, parttype, rlength = partinfo

        self.send_command(self.Cmd.cmd_write_flash(partition=parttype, offset=addr, mem_length=length), noack=True)
        cmd, fileopresult = self.get_command_result()
        if type(fileopresult) is file_sys_op:
            if fileopresult.key != "FILE-SIZE":
                return False
            self.ack_value(length)
            cmd, result = self.get_command_result()
            if type(result) is dwnfile:
                data = fh.read(length)
                if not self.upload(result, data, raw=True):
                    self.error("Error on writing flash at 0x%08X" % addr)
                    return False
                if fh:
                    fh.close()
                return True
        if fh:
            fh.close()
        return False

    def check_lifecycle(self):
        self.send_command(self.Cmd.cmd_emmc_control(function="LIFE-CYCLE-STATUS"), noack=True)
        cmd, result = self.get_command_result()
        if not isinstance(result, upfile):
            return False
        data = self.download(result)
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return data == b"OK\x00"
        return False

    def reinit(self, display=False):
        """
        self.config.sram, self.config.dram = self.get_ram_info()
        self.emmc = self.get_emmc_info(display)
        self.nand = self.get_nand_info(display)
        self.nor = self.get_nor_info(display)
        self.ufs = self.get_ufs_info(display)
        """
        self.storage = self.get_hw_info()
        if isinstance(self.storage, bool):
            self.error("Error: Cannot Reinit daconfig")
            return
        if self.storage.storagetype == "EMMC":
            self.daconfig.flashtype = "emmc"
            self.daconfig.flashsize = self.storage.user_size
            self.daconfig.rpmbsize = self.storage.rpmb_size
            self.daconfig.boot1size = self.storage.boot1_size
            self.daconfig.boot2size = self.storage.boot2_size

            class EmmcInfo:
                type = 1  # emmc or sdmmc or none
                block_size = 0x200
                boot1_size = 0
                boot2_size = 0
                rpmb_size = 0
                gp1_size = 0
                gp2_size = 0
                gp3_size = 0
                gp4_size = 0
                user_size = 0
                cid = b""
                fwver = 0
                unknown = b""

            self.emmc = EmmcInfo()
            self.emmc.gp1_size = self.storage.gp1_size
            self.emmc.gp2_size = self.storage.gp2_size
            self.emmc.gp3_size = self.storage.gp3_size
            self.emmc.gp4_size = self.storage.gp4_size
            self.emmc.rpmb_size = self.storage.rpmb_size
            self.emmc.boot1_size = self.storage.boot1_size
            self.emmc.boot2_size = self.storage.boot2_size
        elif self.storage.storagetype == "NAND":
            self.daconfig.flashtype = "nand"
            self.daconfig.flashsize = self.storage.total_size
            self.daconfig.rpmbsize = 0
            self.daconfig.boot1size = 0x400000
            self.daconfig.boot2size = 0x400000
        elif self.storage.storagetype == "UFS":
            self.daconfig.flashtype = "ufs"
            self.daconfig.flashsize = self.storage.lua0_size
            self.daconfig.rpmbsize = self.storage.lua1_size
            self.daconfig.boot1size = self.storage.lua1_size
            self.daconfig.boot2size = self.storage.lua2_size
            self.config.pagesize = 4096

            class UfsInfo:
                type = 1  # nor, none
                block_size = 0
                lu1_size = 0
                lu2_size = 0
                lu3_size = 0
                lu4_size = 0
                cid = b""
                fwver = b""
                serial = b""

            self.ufs = UfsInfo()
            self.ufs.lu1_size = self.storage.lua0_size
            self.ufs.lu2_size = self.storage.lua1_size
            self.ufs.lu3_size = self.storage.lua2_size
            self.ufs.lu4_size = self.storage.lua3_size
        """
        self.chipid = self.get_chip_id()
        self.daversion = self.get_da_version()
        self.randomid = self.get_random_id()
        speed = self.get_usb_speed()
        if speed == b"full-speed" and self.daconfig.reconnect:
            self.info("Reconnecting to stage2 with higher speed")
            self.config.set_gui_status(self.config.tr("Reconnecting to stage2 with higher speed"))
            self.set_usb_speed()
            self.mtk.port.close(reset=True)
            time.sleep(2)
            while not self.mtk.port.cdc.connect():
                time.sleep(0.5)
            self.info("Connected to stage2 with higher speed")
            self.mtk.port.cdc.set_fast_mode(True)
            self.config.set_gui_status(self.config.tr("Connected to stage2 with higher speed"))
        """

    def formatflash(self, addr, length, storage=None,
                    parttype=None, display=False):
        self.mtk.daloader.progress.clear()
        part_info = self.getstorage(parttype, length)
        if not part_info:
            return False
        storage, parttype, length = part_info
        self.info(f"Formatting addr {hex(addr)} with length {hex(length)}, please standby....")
        self.mtk.daloader.progress.show_progress("Erasing", 0, length, True)
        self.send_command(self.Cmd.cmd_erase_flash(partition=parttype, offset=addr, length=length))
        result = self.get_response()
        if result == "OK":
            self.info(f"Successsfully formatted addr {hex(addr)} with length {length}.")
            return True

        self.error("Error on format.")
        return False

    def shutdown(self, async_mode: int = 0, dl_bit: int = 0, bootmode: ShutDownModes = ShutDownModes.NORMAL):
        if bootmode == ShutDownModes.FASTBOOT:
            self.send_command(self.Cmd.cmd_set_boot_mode(mode=BootModes.fastboot))
        elif bootmode == ShutDownModes.TEST:
            self.send_command(self.Cmd.cmd_set_boot_mode(mode=BootModes.testmode))
        elif bootmode == ShutDownModes.META:
            self.send_command(self.Cmd.cmd_set_boot_mode(mode=BootModes.meta))
        if self.send_command(self.Cmd.cmd_reboot(disconnect=False)):
            self.mtk.port.close(reset=True)
            return True
        else:
            self.error("Error on sending reboot")
        self.mtk.port.close(reset=True)
        return False
