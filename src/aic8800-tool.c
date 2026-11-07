/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 HeartFlow (mark-cell-520)
 */
/*
 * aic8800-tool.c — AIC8800D80/M80 macOS 用户态协议工具
 *
 * 阶段 0: 1111:1111  虚拟光驱（Windows 驱动盘）
 * 阶段 1: a69c:8d80  Boot ROM（接受 DBG 消息：寄存器读写/固件上传）
 * 阶段 2: a69c:8d83  WiFi+BT 运行态
 *
 * 子命令:
 *   mode-switch              阶段0->1：发送厂商 SCSI CDB (FD...F2)
 *   status                   打印设备/端点/芯片 ID
 *   reg-read  <hexaddr>      读芯片内存/寄存器（DBG_MEM_READ_REQ）
 *   reg-write <hexaddr> <hex> 写芯片内存/寄存器（DBG_MEM_WRITE_REQ）
 *   fw-upload <dir>          完整固件下载序列（阶段1->2）
 *
 * 协议依据: aic8800 Linux 驱动 (gtxaspec/aic8800-wifi)
 *   - 消息头: aicbluetooth_cmds.c aicwf_set_cmd_tx()
 *   - DBG 消息 ID: lmac_msg.h (TASK_DBG=1, LMAC_FIRST_MSG(task)=task<<10)
 *   - 固件序列: aic_compat_8800d80.c aicfw_download_fw_8800d80()
 *   - 模式切换: olamellberg/AIC8800D80 逆向（SCSI CDB FD 00*14 F2）
 *
 * 注意: macOS 上需要 sudo 运行（USB 设备捕获需要 root 或
 *       com.apple.vm.device-access  entitlement；DriverKit DEXT 自带该权限）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <libusb.h>

/* ---------- 设备 ID ---------- */
#define VID_MS        0x1111   /* 阶段0: 虚拟光驱 */
#define PID_MS        0x1111
#define VID_AIC       0xA69C   /* 阶段1/2 */
#define PID_BOOT      0x8D80
#define PID_WIFI      0x8D81   /* 本机实测变体；Pi 上是 0x8D83 */
#define PID_WIFI_ALT  0x8D83

/* ---------- DBG 消息 ID（TASK_DBG=1, <<10） ---------- */
#define DBG_MEM_READ_REQ        0x0400
#define DBG_MEM_READ_CFM        0x0401
#define DBG_MEM_WRITE_REQ       0x0402
#define DBG_MEM_WRITE_CFM       0x0403
#define DBG_MEM_BLOCK_WRITE_REQ 0x040B
#define DBG_MEM_BLOCK_WRITE_CFM 0x040C
#define DBG_START_APP_REQ       0x040D
#define DBG_MEM_MASK_WRITE_REQ  0x0411
#define DBG_MEM_MASK_WRITE_CFM  0x0412

#define TASK_DBG   1
#define DRV_TASK_ID 100
#define HOST_START_APP_AUTO 1

/* ---------- 固件下载地址常量（aic_compat_8800d80.h, U02） ---------- */
#define RAM_FMAC_FW_ADDR_8800D80_U02   0x120000
#define FW_RAM_ADID_BASE_ADDR_U02      0x00201940
#define FW_RAM_PATCH_BASE_ADDR_U02     0x0020B43C

/* ---------- USB 帧类型 ---------- */
#define USB_TYPE_CFG          0x10
#define USB_TYPE_CFG_CMD_RSP  0x11

#define MSG_BUF_MAX   2048
#define CFG_BUF_MAX   4096

/* ================================================================
 * 底层：USB 设备定位与端点探测
 * ================================================================ */

typedef struct {
    libusb_device_handle *h;
    int ep_out;      /* 第一个批量 OUT：DBG 消息/数据 */
    int ep_in;       /* 第一个批量 IN：CFM/数据 */
    int stage;       /* 0=MS 1=BOOT 2=WIFI */
} aic_dev_t;

static int find_device(aic_dev_t *dev, int want_pid)
{
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(NULL, &list);
    libusb_device *match = NULL;
    int found_pid = 0;

    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) < 0) continue;
        if (dd.idVendor != VID_AIC && dd.idVendor != VID_MS) continue;
        int pid = dd.idProduct;
        if (pid != PID_BOOT && pid != PID_WIFI && pid != PID_WIFI_ALT && pid != PID_MS) continue;
        if (want_pid && pid != want_pid) continue;
        match = list[i];
        found_pid = pid;
        break;
    }
    if (!match) {
        libusb_free_device_list(list, 1);
        return 0;
    }
    int rc = libusb_open(match, &dev->h);
    libusb_free_device_list(list, 1);
    if (rc < 0) {
        fprintf(stderr, "打开设备失败: %s（需要 sudo）\n", libusb_error_name(rc));
        return 0;
    }
    dev->stage = (found_pid == PID_MS) ? 0 : (found_pid == PID_BOOT ? 1 : 2);
    return 1;
}

/* 探测端点：优先 WLAN 接口（0xFF/0xFF/0xFF），否则第一个有批量端点的接口 */
static int probe_endpoints(aic_dev_t *dev)
{
    libusb_device *d = libusb_get_device(dev->h);
    struct libusb_config_descriptor *cfg;
    if (libusb_get_active_config_descriptor(d, &cfg) < 0) return -1;

    dev->ep_out = dev->ep_in = -1;
    /* 第一遍：找 vendor-specific (WLAN) 接口 */
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        for (int a = 0; a < itf->num_altsetting; a++) {
            const struct libusb_interface_descriptor *id = &itf->altsetting[a];
            if (id->bInterfaceClass != 0xFF || id->bInterfaceSubClass != 0xFF) continue;
            for (int e = 0; e < id->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
                if ((ed->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                if (ed->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) {
                    if (dev->ep_in < 0) dev->ep_in = ed->bEndpointAddress;
                } else {
                    if (dev->ep_out < 0) dev->ep_out = ed->bEndpointAddress;
                }
            }
        }
    }
    /* 第二遍：兜底任何接口 */
    if (dev->ep_out < 0 || dev->ep_in < 0) {
        for (int i = 0; i < cfg->bNumInterfaces; i++) {
            const struct libusb_interface *itf = &cfg->interface[i];
            for (int a = 0; a < itf->num_altsetting; a++) {
                const struct libusb_interface_descriptor *id = &itf->altsetting[a];
                for (int e = 0; e < id->bNumEndpoints; e++) {
                    const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
                    if ((ed->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                    if (ed->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) {
                        if (dev->ep_in < 0) dev->ep_in = ed->bEndpointAddress;
                    } else {
                        if (dev->ep_out < 0) dev->ep_out = ed->bEndpointAddress;
                    }
                }
            }
        }
    }
    libusb_free_config_descriptor(cfg);
    return (dev->ep_out > 0 && dev->ep_in > 0) ? 0 : -1;
}

/* ================================================================
 * DBG 消息层（对应 aicwf_set_cmd_tx + rwnx_rx_handle_msg）
 * ================================================================ */

static int open_boot(aic_dev_t *dev);   /* 前向声明 */
static void drain_rx(aic_dev_t *dev);  /* 前向声明 */

/* 组消息并发送。param/param_len 为消息参数。返回 0 成功。 */
static int dbg_send(aic_dev_t *dev, uint16_t msg_id, const uint8_t *param, uint16_t param_len)
{
    uint8_t buf[MSG_BUF_MAX];
    /* param_len 是 u16（最大 65535），不校验会直接栈溢出。
     * 当前调用方都是常量长度，但作为公开接口必须自带防线。 */
    if (param_len > sizeof(buf) - 16) {
        fprintf(stderr, "dbg_send 参数过长: %u\n", param_len);
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    uint16_t len = 8 + param_len;   /* sizeof(lmac_msg) + param_len */

    buf[0] = (len + 4) & 0xff;
    buf[1] = ((len + 4) >> 8) & 0x0f;
    buf[2] = USB_TYPE_CFG_CMD_RSP;  /* 0x11 */
    buf[3] = 0x00;
    /* [4..7] dummy word */
    buf[8]  = msg_id & 0xff;  buf[9]  = (msg_id >> 8) & 0xff;
    buf[10] = TASK_DBG & 0xff; buf[11] = (TASK_DBG >> 8) & 0xff;
    buf[12] = DRV_TASK_ID & 0xff; buf[13] = (DRV_TASK_ID >> 8) & 0xff;
    buf[14] = param_len & 0xff; buf[15] = (param_len >> 8) & 0xff;
    if (param_len) memcpy(&buf[16], param, param_len);

    int total = len + 8;
    int xfer = 0;
    {
        const char *d = getenv("AIC_DBGDUMP");
        if (d) {
            printf("[DBGDUMP] id=0x%04x plen=%u param:", msg_id, param_len);
            for (int z = 0; z < param_len && z < 24; z++) printf(" %02x", param[z]);
            printf("\n"); fflush(stdout);
        }
    }
    int rc = libusb_bulk_transfer(dev->h, dev->ep_out, buf, total, &xfer, 5000);
    if (rc < 0) {
        fprintf(stderr, "消息发送失败 (id=0x%04x): %s\n", msg_id, libusb_error_name(rc));
        return -1;
    }
    return 0;
}

/* 读一条 CFM。期望 msg_id（0=任意）。返回 param_len，失败 -1。 */
static int dbg_recv(aic_dev_t *dev, uint16_t expect_id, uint8_t *param_out, int param_cap)
{
    uint8_t buf[CFG_BUF_MAX];
    int xfer = 0;
    int rc = libusb_bulk_transfer(dev->h, dev->ep_in, buf, sizeof(buf), &xfer, 5000);
    if (rc < 0) {
        fprintf(stderr, "CFM 读取失败: %s\n", libusb_error_name(rc));
        return -1;
    }
    if (xfer < 16) {
        fprintf(stderr, "CFM 长度异常: %d\n", xfer);
        return -1;
    }
    /* RX 帧: [0..1]=pkt_len [2]=type(0x11) [3]=? [4..]=ipc_e2a_msg */
    if ((buf[2] & 0x7f) != USB_TYPE_CFG_CMD_RSP) {
        fprintf(stderr, "非 CFM 帧 (type=0x%02x)\n", buf[2]);
        return -1;
    }
    uint16_t id   = buf[4] | (buf[5] << 8);
    uint16_t plen = buf[10] | (buf[11] << 8);
    if (expect_id && id != expect_id) {
        fprintf(stderr, "CFM id 不匹配: 收到 0x%04x, 期望 0x%04x\n", id, expect_id);
        return -1;
    }
    if (param_out && plen > 0) {
        int n = plen;
        if (n > param_cap) n = param_cap;
        if (n > xfer - 16) n = xfer - 16;   /* 只拷实际收到的字节 */
        if (n > 0) memcpy(param_out, &buf[16], (size_t)n);
    }
    return plen;
}

/* 发 REQ 收 CFM 一体 */
static int dbg_call(aic_dev_t *dev, uint16_t req_id, uint16_t cfm_id,
                    const uint8_t *param, uint16_t param_len,
                    uint8_t *cfm_param, int cfm_cap)
{
    if (dbg_send(dev, req_id, param, param_len) < 0) return -1;
    return dbg_recv(dev, cfm_id, cfm_param, cfm_cap);
}


/* ================================================================
 * 固件上传（对应 aic_compat_8800d80.c 的完整下载序列）
 * ================================================================ */

#include <time.h>

#define AIC_PATCH_MAGIG_NUM    0x48435450  /* "PTCH" */
#define AIC_PATCH_MAGIG_NUM_2  0x50544348  /* "HCTP" */

/* aic_patch_t 结构体偏移（AIC_PATCH_OFST） */
#define AIC_PATCH_OFF_MAGIC      0
#define AIC_PATCH_OFF_PAIR_START 4
#define AIC_PATCH_OFF_MAGIC2     8
#define AIC_PATCH_OFF_PAIR_CNT   12
#define AIC_PATCH_OFF_BLOCK_SIZE 48

/* patch_tbl_d80 默认构建（无 USE_5G，非 HI 平台，CFG_PWROFST_COVER_CALIB=1） */
/* 与参考驱动 aicwf_patch_config_8800d80 的 patch_tbl_d80 完全一致（2 项）：
 * 原实现第 1 项值 0xf3010000（参考为 0xf3010001，差最低位）且多第 3 项
 * {0x0188, 0x00000001}——实测这三处差异会让固件 TX 通路异常
 * （DATA_CFM tx_done=1 但 acknowledged=0，AP 收不到握手帧）。 */
static const uint32_t patch_tbl_d80[2][2] = {
    {0x00b4, 0xf3010001},
    {0x0170, 0x0001000A},
};

/* SCANU_START_REQ 全量扫描参数（与参考驱动后台扫描线程发出的逐字节一致）：
 * 39 个频道（14×2.4G 含 2484 + 25×5G），每条 freq(u16)+band(u16)+flags(u16)，
 * 后跟 SSID 数组（全零=不过滤）、wildcard BSSID、尾部 chan_cnt=0x27=39。
 * 实测：SM_CONNECT 前必须先显式扫描并等其完成，否则固件在关联后内部扫描
 * 与握手并发，TX 被抑制（DATA_CFM tx_done=1 但 acknowledged=0）。 */
static const uint8_t scanu_req_param[376] = {
    0x6c, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x71, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x76, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x7b, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x80, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x85, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x8a, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x8f, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x94, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x99, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x9e, 0x09, 0x00, 0x00, 0x1e, 0x00, 0xa3, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0xa8, 0x09, 0x00, 0x00, 0x1e, 0x00, 0xb4, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x3c, 0x14, 0x01, 0x00, 0x1e, 0x00, 0x50, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0x64, 0x14, 0x01, 0x00, 0x1e, 0x00, 0x78, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0x8c, 0x14, 0x01, 0x00, 0x1e, 0x00, 0xa0, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0xb4, 0x14, 0x01, 0x00, 0x1e, 0x00, 0xc8, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0x7c, 0x15, 0x01, 0x00, 0x1e, 0x00, 0x90, 0x15, 0x01, 0x00, 0x1e, 0x00,
    0xa4, 0x15, 0x01, 0x00, 0x1e, 0x00, 0xb8, 0x15, 0x01, 0x00, 0x1e, 0x00,
    0xcc, 0x15, 0x01, 0x00, 0x1e, 0x00, 0xe0, 0x15, 0x01, 0x00, 0x1e, 0x00,
    0xf4, 0x15, 0x01, 0x00, 0x1e, 0x00, 0x08, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x1c, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x30, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x44, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x58, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x71, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x85, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x99, 0x16, 0x01, 0x00, 0x1e, 0x00, 0xad, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0xc1, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

/* BTMODE 记录默认值（aicbluetooth.c, PRODUCT_ID_AIC8800D80） */
#define BSP_HWINFO      (-1)
#define BSP_CPMODE      0    /* AICBSP_CPMODE_WORK */
/* D81 的 BT 默认值：参考驱动 aicbt_info[PRODUCT_ID_AIC8800D81] 是空条目（全零）。
 * 此前用 D80 的非零值（BT_BTMODE=5/txpwr=0x6F2F...）——MODE_T 记录把这些值写进
 * 固件内存的 (addr,value) 对，其中 txpwr_lvl 对应的地址疑似射频控制寄存器，
 * 非零值会导致 TX 通路异常（DATA_CFM tx_done=1 但空口 acknowledged=0）。 */
#define BT_BTMODE       0
#define BT_BTPORT       0
#define BT_UART_BAUD    0
#define BT_UART_FC      0
#define BT_LPM          0
#define BT_TXPWR        0

static int dbg_mem_write(aic_dev_t *dev, uint32_t addr, uint32_t val)
{
    if (getenv("AIC_DBGDUMP")) { printf("[MEMW] 0x%08x <- 0x%08x\n", addr, val); fflush(stdout); }
    uint8_t param[8];
    memcpy(&param[0], &addr, 4);
    memcpy(&param[4], &val, 4);
    return dbg_call(dev, DBG_MEM_WRITE_REQ, DBG_MEM_WRITE_CFM, param, 8, NULL, 0);
}

static int dbg_mem_read(aic_dev_t *dev, uint32_t addr, uint32_t *val)
{
    uint8_t cfm[64] = {0};
    int n = dbg_call(dev, DBG_MEM_READ_REQ, DBG_MEM_READ_CFM,
                     (uint8_t *)&addr, 4, cfm, sizeof(cfm));
    if (n < 8) return -1;
    *val = cfm[4] | (cfm[5]<<8) | (cfm[6]<<16) | ((uint32_t)cfm[7]<<24);
    return 0;
}

/* 1KB 块写（DBG_MEM_BLOCK_WRITE_REQ，memdata[1024/4]） */
static int dbg_block_write(aic_dev_t *dev, uint32_t addr, uint32_t size, const uint8_t *data)
{
    if (size > 1024) size = 1024;
    static uint8_t param[8 + 1024];
    memcpy(&param[0], &addr, 4);
    memcpy(&param[4], &size, 4);
    memcpy(&param[8], data, size);
    return dbg_call(dev, DBG_MEM_BLOCK_WRITE_REQ, DBG_MEM_BLOCK_WRITE_CFM,
                    param, 8 + size, NULL, 0);
}

static uint8_t *load_file(const char *path, long *size_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 64 * 1024 * 1024) {   /* 目录/FIFO 或异常大文件 */
        fclose(f);
        return NULL;
    }
    uint8_t *buf = malloc(sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *size_out = sz;
    return buf;
}

/* 上传整个固件文件到指定地址（1KB/块，复刻驱动循环） */
static int upload_firmware(aic_dev_t *dev, const char *path, uint32_t fw_addr)
{
    long size = 0;
    uint8_t *data = load_file(path, &size);
    if (!data) {
        fprintf(stderr, "  打不开固件文件: %s\n", path);
        return -1;
    }
    printf("  上传 %s (%ld 字节) -> 0x%08x\n", strrchr(path, '/') ? strrchr(path, '/')+1 : path, size, fw_addr);
    long i = 0;
    int err = 0;
    if (size > 1024) {
        for (i = 0; i < size - 1024; i += 1024) {
            if (getenv("AIC_DBGDUMP")) { unsigned cs=0; for (int z=0;z<1024;z++) cs=cs*31+(unsigned char)data[i+z]; printf("[BLK] 0x%08x len=1024 cs=%08x\n", fw_addr+(uint32_t)i, cs); fflush(stdout); }
            if (dbg_block_write(dev, fw_addr + i, 1024, data + i) < 0) {
                fprintf(stderr, "  块写失败 @0x%08x\n", fw_addr + (uint32_t)i);
                err = -1;
                break;
            }
        }
    }
    if (!err && i < size) {
        if (getenv("AIC_DBGDUMP")) { unsigned cs=0; for (int z=0;z<size-i;z++) cs=cs*31+(unsigned char)data[i+z]; printf("[BLK] 0x%08x len=%ld cs=%08x\n", fw_addr+(uint32_t)i, size-i, cs); fflush(stdout); }
        if (dbg_block_write(dev, fw_addr + i, size - i, data + i) < 0) {
            fprintf(stderr, "  尾部块写失败 @0x%08x\n", fw_addr + (uint32_t)i);
            err = -1;
        }
    }
    free(data);
    return err;
}

/* 读小端 u32 */
static uint32_t rd32(const uint8_t *p)
{
    return p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24);
}

/* patch table 记录 */
typedef struct {
    char name[17];
    uint32_t type;
    uint32_t len;
    uint8_t *data;   /* len*8 字节 */
} pt_rec_t;

static int cmd_fw_upload(const char *dir)
{
    aic_dev_t dev = {0};
    char path[512];

    if (open_boot(&dev) < 0) return 1;
    printf("设备: a69c:8d80 (Boot ROM), 端点 OUT=0x%02x IN=0x%02x\n", dev.ep_out, dev.ep_in);

    /* ---- 0. system_config: 读芯片 ID ---- */
    uint32_t chipid_word = 0;
    if (dbg_mem_read(&dev, 0x40500000, &chipid_word) < 0) {
        fprintf(stderr, "读芯片 ID 失败\n");
        libusb_close(dev.h);
        return 1;
    }
    uint8_t chip_id = (uint8_t)(chipid_word >> 16);
    printf("chip_id = 0x%02x (U03=%s)\n", chip_id, chip_id == 0x7 ? "是" : "否");
    if (chip_id != 0x1 && chip_id != 0x3 && chip_id != 0x7) {
        fprintf(stderr, "  警告: 非预期 chip_id，仍按 U02/U03 路径尝试\n");
    }

    /* ---- 1. 读 patch table ---- */
    snprintf(path, sizeof(path), "%s/fw_patch_table_8800d80_u02.bin", dir);
    long pt_size = 0;
    uint8_t *pt = load_file(path, &pt_size);
    if (!pt) { fprintf(stderr, "打不开 %s\n", path); libusb_close(dev.h); return 1; }
    if (memcmp(pt, "AICBT_PT_TAG", 11) != 0) {
        fprintf(stderr, "patch table TAG 错误\n");
        free(pt); libusb_close(dev.h); return 1;
    }
    /* 解析记录流 */
    pt_rec_t recs[32];
    int nrec = 0;
    long off = 16;
    while (off + 24 <= pt_size && nrec < 32) {
        memcpy(recs[nrec].name, pt + off, 16);
        recs[nrec].name[16] = 0;
        recs[nrec].type = rd32(pt + off + 16);
        recs[nrec].len  = rd32(pt + off + 20);
        off += 24;
        if (recs[nrec].type >= 1000 || recs[nrec].len == 0) {
            recs[nrec].data = NULL;
            recs[nrec].len = 0;
        } else {
            /* len*8 用 64 位防回绕；数据必须完整落在文件缓冲内，
             * 否则 recs[].data 指向缓冲外，应用阶段按 len 逐对读取=堆越界读。 */
            uint64_t dlen = (uint64_t)recs[nrec].len * 8;
            if (dlen > 0x10000 || off + dlen > (uint64_t)pt_size) {
                printf("  patch table 记录 %s 长度异常（len=%u），终止解析\n",
                       recs[nrec].name, recs[nrec].len);
                break;
            }
            recs[nrec].data = pt + off;
            off += dlen;
        }
        printf("  patch table 记录: %-16s type=%u len=%u\n", recs[nrec].name, recs[nrec].type, recs[nrec].len);
        nrec++;
    }
    /* 注意: pt 缓冲区保持有效，recs[].data 指向它，全部记录应用完后才能 free */

    /* ---- 2. 找 INF 记录拿地址 ---- */
    uint32_t addr_adid = 0x00201940, addr_patch = 0x0020B43C;
    uint32_t ext_nb = 0;
    uint32_t ext_param[16];
    for (int i = 0; i < nrec; i++) {
        if (recs[i].type == 0x00 && recs[i].len >= 4) {
            const uint8_t *d = recs[i].data;
            /* 复刻 aicbt_patch_info_unpack: memcpy 40 字节进结构体(偏移4起)
             * adid_addrinf=data[0] addr_adid=data[1] patch_addrinf=data[2] addr_patch=data[3]
             * ... ext_patch_nb=data[9]; ext_patch_param = data+10 (id,addr) 对 */
            addr_adid  = rd32(d + 4);
            addr_patch = rd32(d + 12);
            if (recs[i].len > 5) {
                ext_nb = rd32(d + 36);
                for (uint32_t k = 0; k < ext_nb && k < 8; k++) {
                    ext_param[k*2]   = rd32(d + 40 + k*8);
                    ext_param[k*2+1] = rd32(d + 44 + k*8);
                }
            }
            break;
        }
    }
    printf("addr_adid=0x%08x addr_patch=0x%08x ext_patch_nb=%u\n", addr_adid, addr_patch, ext_nb);

    /* ---- 5. 应用 patch table 记录 ---- */
    printf("[3/5] 应用 patch table 记录\n");
    for (int i = 0; i < nrec; i++) {
        if (recs[i].type == 0x06) continue;          /* 版本字符串 */
        if (recs[i].len == 0 || !recs[i].data) continue;
        /* 复刻驱动: BTMODE 记录先就地填默认 BT 配置，再逐对写 */
        uint8_t tmpbuf[512];
        const uint8_t *d = recs[i].data;
        if (recs[i].type == 0x03) {
            uint32_t nwords = recs[i].len * 2;
            if (nwords * 4 > sizeof(tmpbuf)) nwords = sizeof(tmpbuf) / 4;
            memcpy(tmpbuf, recs[i].data, nwords * 4);
            uint32_t *w = (uint32_t *)tmpbuf;
            if (nwords > 1)  w[1]  = (BSP_HWINFO < 0);
            if (nwords > 3)  w[3]  = (uint32_t)BSP_HWINFO;
            if (nwords > 5)  w[5]  = BSP_CPMODE;
            if (nwords > 7)  w[7]  = BT_BTMODE;
            if (nwords > 9)  w[9]  = BT_BTPORT;
            if (nwords > 11) w[11] = BT_UART_BAUD;
            if (nwords > 13) w[13] = BT_UART_FC;
            if (nwords > 15) w[15] = BT_LPM;
            if (nwords > 17) w[17] = BT_TXPWR;
            d = tmpbuf;
            /* 循环上界与 memcpy 用同一个 clamp 值：此前循环用未 clamp 的
             * recs[i].len，len>64 时读穿 tmpbuf[512]（栈越界读）。 */
            recs[i].len = nwords / 2;
        }
        for (uint32_t k = 0; k < recs[i].len; k++) {
            uint32_t a = rd32(d + k*8);
            uint32_t v = rd32(d + k*8 + 4);
            if (dbg_mem_write(&dev, a, v) < 0) {
                fprintf(stderr, "  记录 %s 第 %u 项写失败\n", recs[i].name, k);
                goto fail;
            }
        }
        printf("  记录 %s: %u 项已应用\n", recs[i].name, recs[i].len);
    }

    /* ---- 3. 上传 adid + patch ---- */
    printf("[1/5] 上传 adid/patch 固件\n");
    snprintf(path, sizeof(path), "%s/fw_adid_8800d80_u02.bin", dir);
    if (upload_firmware(&dev, path, addr_adid) < 0) goto fail;
    snprintf(path, sizeof(path), "%s/fw_patch_8800d80_u02.bin", dir);
    if (upload_firmware(&dev, path, addr_patch) < 0) goto fail;

    /* ---- 4. ext patches ---- */
    if (ext_nb > 0) {
        printf("[2/5] 上传 %u 个 ext patch\n", ext_nb);
        for (uint32_t k = 0; k < ext_nb; k++) {
            snprintf(path, sizeof(path), "%s/fw_patch_8800d80_u02_ext%u.bin", dir, ext_param[k*2]);
            if (upload_firmware(&dev, path, ext_param[k*2+1]) < 0) {
                fprintf(stderr, "  ext patch %u 缺失，跳过\n", ext_param[k*2]);
            }
        }
    }

    /* ---- 6. 上传主固件 ---- */
    printf("[4/5] 上传主固件 fmacfw\n");
    snprintf(path, sizeof(path), "%s/fmacfw_8800d80_u02.bin", dir);
    if (upload_firmware(&dev, path, 0x120000) < 0) goto fail;

    /* ---- 7. patch_config ---- */
    printf("[5/5] patch_config + 启动固件\n");
    uint32_t config_base = 0, str_base = 0, start_addr = 0x001D7000;
    if (dbg_mem_read(&dev, 0x120000 + 0x198, &config_base) < 0) goto fail;
    printf("  config_base=0x%08x\n", config_base);
    if (dbg_mem_read(&dev, 0x120000 + 0x198 + 8, &str_base) < 0) goto fail;
    printf("  patch_str_base=0x%08x (fw)\n", str_base);
    /* 实测：把 patch string 写进固件数据区(0x00176000)会破坏 TX 通路，
     * 参考驱动实际写在 0x00000000（其 str_base 读取因 CFM 竞争返回 0）。 */
    if (getenv("AIC_STRBASE0")) { str_base = 0; printf("  patch_str_base -> 0 (AIC_STRBASE0)\n"); }
    uint32_t ver = 0;
    if (dbg_mem_read(&dev, 0x120000 + 0x01C, &ver) == 0) {
        printf("  固件版本字=0x%08x\n", ver);
        if (ver > 0x06090100) {
            uint32_t pb = 0;
            if (dbg_mem_read(&dev, 0x120000 + 0x198 + 12, &pb) == 0 && pb) {
                start_addr = pb;
                printf("  patch_buff_base=0x%08x\n", pb);
            }
        }
    }
    if (dbg_mem_write(&dev, str_base + AIC_PATCH_OFF_MAGIC, AIC_PATCH_MAGIG_NUM) < 0) goto fail;
    if (dbg_mem_write(&dev, str_base + AIC_PATCH_OFF_MAGIC2, AIC_PATCH_MAGIG_NUM_2) < 0) goto fail;
    if (dbg_mem_write(&dev, str_base + AIC_PATCH_OFF_PAIR_START, start_addr) < 0) goto fail;
    if (dbg_mem_write(&dev, str_base + AIC_PATCH_OFF_PAIR_CNT, 2) < 0) goto fail;
    for (int i = 0; i < 2; i++) {
        if (dbg_mem_write(&dev, start_addr + 8*i,   patch_tbl_d80[i][0] + config_base) < 0) goto fail;
        if (dbg_mem_write(&dev, start_addr + 8*i+4, patch_tbl_d80[i][1]) < 0) goto fail;
    }
    for (int i = 0; i < 4; i++) {
        if (dbg_mem_write(&dev, str_base + AIC_PATCH_OFF_BLOCK_SIZE + 4*i, 0) < 0) goto fail;
    }

    /* ---- 7.5 rf_config + wdt_config（必须在启动固件前！）----
     * Linux 驱动 rwnx_platform_on：patch_config → rf_config(0x40344058 清 bit23，
     * "pll trx" 发射 PLL 使能) → start_app；wdt_config(0x4010300c 置 1) 在
     * system_init 里、start_from_bootrom 之前。缺 rf_config = TX PLL 不使能：
     * 固件收帧、DATA_CFM 报 tx_done=1，但空口零辐射、acknowledged=0，
     * AP 收不到握手帧 → 永远重传 Msg1（RX 正常，极易误判为协议问题）。 */
    {
        uint8_t rf[12]; uint32_t a = 0x40344058, m = 0x00800000, d = 0x00000000;
        memcpy(&rf[0], &a, 4); memcpy(&rf[4], &m, 4); memcpy(&rf[8], &d, 4);
        dbg_call(&dev, DBG_MEM_MASK_WRITE_REQ, DBG_MEM_MASK_WRITE_CFM, rf, sizeof(rf), NULL, 0);
        printf("  rf_config(0x40344058 pll_trx bit23<-0) 已发送\n");
        uint8_t wd[12]; a = 0x4010300c; m = 0x00000001; d = 0x00000001;
        memcpy(&wd[0], &a, 4); memcpy(&wd[4], &m, 4); memcpy(&wd[8], &d, 4);
        dbg_call(&dev, DBG_MEM_MASK_WRITE_REQ, DBG_MEM_MASK_WRITE_CFM, wd, sizeof(wd), NULL, 0);
        printf("  wdt_config(0x4010300c <-1) 已发送\n");
    }
    /* ---- 8. 启动固件 ---- */
    {
        uint8_t param[8];
        uint32_t bootaddr = 0x120000, boottype = 1;
        memcpy(&param[0], &bootaddr, 4);
        memcpy(&param[4], &boottype, 4);
        printf("  发送 DBG_START_APP_REQ(0x120000, AUTO)...\n");
        dbg_send(&dev, DBG_START_APP_REQ, param, 8);
        sleep(2);

        /* Windows 驱动在此步之后做显式 soft disconnect（sftdiscon）。
         * 芯片未自发重枚举，主动做 USB 端口重置触发重新枚举。
         * 固件在跑 -> 以 a69c:8d83 回来；没在跑 -> 退回 a69c:8d80。 */
        printf("  执行 USB 端口重置触发重枚举...\n");
        libusb_release_interface(dev.h, 0);
        int rc = libusb_reset_device(dev.h);
        printf("  reset 结果: %s\n", libusb_error_name(rc));
        sleep(3);
        libusb_close(dev.h);

        /* 重新扫描，报告设备新身份 */
        printf("  重扫描 USB 设备...\n");
        libusb_device **list2;
        ssize_t cnt2 = libusb_get_device_list(NULL, &list2);
        int found = 0;
        for (ssize_t i = 0; i < cnt2; i++) {
            struct libusb_device_descriptor dd;
            if (libusb_get_device_descriptor(list2[i], &dd) < 0) continue;
            if (dd.idVendor == 0xA69C || (dd.idVendor == 0x1111 && dd.idProduct == 0x1111)) {
                printf("  -> 设备现在: %04x:%04x\n", dd.idVendor, dd.idProduct);
                found = 1;
            }
        }
        libusb_free_device_list(list2, 1);
        if (!found) printf("  -> 设备不在总线上（可能还在重启）\n");
        free(pt);
        return found ? 0 : 1;
    }

    printf("\n✅ 固件下载序列完成！设备应重枚举为 a69c:8d83。\n");
    printf("   ioreg -p IOUSB | grep -i aic  查看新设备\n");
    free(pt);
    libusb_close(dev.h);
    return 0;

fail:
    fprintf(stderr, "\n!! 固件下载失败\n");
    free(pt);
    libusb_close(dev.h);
    return 1;
}

/* ================================================================
 * 子命令实现
 * ================================================================ */

static int cmd_mode_switch(void)
{
    aic_dev_t dev = {0};
    if (!find_device(&dev, PID_MS)) {
        fprintf(stderr, "未找到 1111:1111 设备（可能已切过模式）\n");
        return 1;
    }
    if (probe_endpoints(&dev) < 0) {
        fprintf(stderr, "端点探测失败\n");
        libusb_close(dev.h);
        return 1;
    }
    printf("设备 1111:1111, 端点 OUT=0x%02x IN=0x%02x\n", dev.ep_out, dev.ep_in);

    libusb_set_auto_detach_kernel_driver(dev.h, 1);
    int cfg = 0;
    libusb_get_configuration(dev.h, &cfg);
    if (cfg != 1) libusb_set_configuration(dev.h, 1);
    int rc = libusb_claim_interface(dev.h, 0);
    if (rc < 0) {
        fprintf(stderr, "claim_interface 失败: %s\n", libusb_error_name(rc));
        libusb_close(dev.h);
        return 1;
    }
    printf("已独占大容量存储接口（内核驱动已剥离）\n");

    /* CBW: USBC + tag + 0 + 00 + 00 + 16 + CDB(FD 00*14 F2) */
    uint8_t cbw[31];
    memset(cbw, 0, sizeof(cbw));
    memcpy(&cbw[0], "USBC", 4);
    cbw[4]=0x78; cbw[5]=0x56; cbw[6]=0x34; cbw[7]=0x12;
    cbw[14] = 0x10;
    cbw[15] = 0xFD;
    cbw[30] = 0xF2;

    int xfer = 0;
    rc = libusb_bulk_transfer(dev.h, dev.ep_out, cbw, sizeof(cbw), &xfer, 5000);
    if (rc < 0) {
        fprintf(stderr, "CBW 发送失败: %s\n", libusb_error_name(rc));
        libusb_release_interface(dev.h, 0);
        libusb_close(dev.h);
        return 1;
    }
    printf("CBW 已发送，读取 CSW...\n");
    uint8_t csw[13];
    rc = libusb_bulk_transfer(dev.h, dev.ep_in, csw, sizeof(csw), &xfer, 5000);
    if (rc == 0 && xfer == 13 && !memcmp(csw, "USBS", 4) && csw[12] == 0) {
        printf("✅ 模式切换成功，设备应重枚举为 a69c:8d80\n");
    } else {
        printf("⚠️ CSW 未确认（设备可能已重枚举，属正常）。ioreg 查看新设备。\n");
    }
    libusb_release_interface(dev.h, 0);
    libusb_close(dev.h);
    return 0;
}

static int open_boot(aic_dev_t *dev)
{
    if (!find_device(dev, PID_BOOT)) {
        fprintf(stderr, "未找到 a69c:8d80 设备。先运行 mode-switch。\n");
        return -1;
    }
    if (probe_endpoints(dev) < 0) {
        fprintf(stderr, "端点探测失败\n");
        libusb_close(dev->h);
        return -1;
    }
    libusb_set_auto_detach_kernel_driver(dev->h, 1);
    int cfg = 0;
    libusb_get_configuration(dev->h, &cfg);
    if (cfg != 1) libusb_set_configuration(dev->h, 1);
    int rc = libusb_claim_interface(dev->h, 0);
    if (rc < 0) {
        fprintf(stderr, "claim_interface 失败: %s\n", libusb_error_name(rc));
        libusb_close(dev->h);
        return -1;
    }
    return 0;
}


static int cmd_dump(void)
{
    aic_dev_t dev = {0};
    if (!find_device(&dev, 0)) {
        fprintf(stderr, "未找到 AIC 设备\n");
        return 1;
    }
    libusb_device *d = libusb_get_device(dev.h);
    struct libusb_config_descriptor *cfg;
    if (libusb_get_active_config_descriptor(d, &cfg) < 0) {
        printf("(读取配置描述符失败)\n");
        return -1;
    }
    printf("设备阶段: %d\n", dev.stage);
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        for (int a = 0; a < itf->num_altsetting; a++) {
            const struct libusb_interface_descriptor *id = &itf->altsetting[a];
            printf("接口 %d (class %02x/%02x/%02x) ep=%d\n", id->bInterfaceNumber,
                   id->bInterfaceClass, id->bInterfaceSubClass, id->bInterfaceProtocol,
                   id->bNumEndpoints);
            for (int e = 0; e < id->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
                const char *t = (ed->bmAttributes & 3) == 2 ? "BULK" :
                                (ed->bmAttributes & 3) == 3 ? "INT" : "ISO";
                printf("  EP 0x%02x %-4s %s maxpkt=%u\n", ed->bEndpointAddress, t,
                       (ed->bEndpointAddress & 0x80) ? "IN " : "OUT", ed->wMaxPacketSize);
            }
        }
    }
    libusb_free_config_descriptor(cfg);
    libusb_close(dev.h);
    return 0;
}


/* WiFi 运行态测试：找 WLAN 接口，实测消息端点通路 */
static int cmd_wifi_test(void)
{
    aic_dev_t dev = {0};
    if (!find_device(&dev, 0)) { fprintf(stderr, "未找到 AIC 设备\n"); return 1; }
    if (dev.stage != 2) { fprintf(stderr, "设备不在 WiFi 运行态（当前 stage=%d）\n", dev.stage); libusb_close(dev.h); return 1; }

    libusb_device *d = libusb_get_device(dev.h);
    struct libusb_config_descriptor *cfg;
    if (libusb_get_active_config_descriptor(d, &cfg) < 0) {
        printf("(读取配置描述符失败)\n");
        return -1;
    }
    int wlan_if = -1;
    int ep_out[4] = {0}, ep_in[4] = {0}, n_out = 0, n_in = 0;
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface_descriptor *id = &cfg->interface[i].altsetting[0];
        if (id->bInterfaceClass != 0xFF) continue;
        wlan_if = id->bInterfaceNumber;
        for (int e = 0; e < id->bNumEndpoints; e++) {
            const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
            if ((ed->bmAttributes & 3) != 2) continue;
            if (ed->bEndpointAddress & 0x80) { if (n_in < 4) ep_in[n_in++] = ed->bEndpointAddress; }
            else { if (n_out < 4) ep_out[n_out++] = ed->bEndpointAddress; }
        }
    }
    libusb_free_config_descriptor(cfg);
    if (wlan_if < 0) { fprintf(stderr, "未找到 WLAN 接口\n"); libusb_close(dev.h); return 1; }
    printf("WLAN 接口=%d, OUT:", wlan_if);
    for (int i = 0; i < n_out; i++) printf(" 0x%02x", ep_out[i]);
    printf(" | IN:");
    for (int i = 0; i < n_in; i++) printf(" 0x%02x", ep_in[i]);
    printf("\n");

    libusb_set_auto_detach_kernel_driver(dev.h, 1);
    int rc = libusb_claim_interface(dev.h, wlan_if);
    if (rc < 0) { fprintf(stderr, "claim 接口 %d 失败: %s\n", wlan_if, libusb_error_name(rc)); libusb_close(dev.h); return 1; }

    /* 对每个 (OUT, IN) 组合试发 DBG_MEM_READ_REQ(0x40500000) */
    uint32_t addr = 0x40500000;
    for (int o = 0; o < n_out; o++) {
        for (int in = 0; in < n_in; in++) {
            dev.ep_out = ep_out[o];
            dev.ep_in = ep_in[in];
            printf("试 OUT=0x%02x IN=0x%02x ... ", ep_out[o], ep_in[in]);
            fflush(stdout);
            uint8_t cfm[64] = {0};
            int n = dbg_call(&dev, DBG_MEM_READ_REQ, DBG_MEM_READ_CFM,
                             (uint8_t *)&addr, 4, cfm, sizeof(cfm));
            if (n >= 8) {
                uint32_t v = cfm[4] | (cfm[5]<<8) | (cfm[6]<<16) | ((uint32_t)cfm[7]<<24);
                printf("✅ 响应! 0x40500000 = 0x%08x (chip_id=0x%02x)\n", v, (uint8_t)(v>>16));
                libusb_release_interface(dev.h, wlan_if);
                libusb_close(dev.h);
                printf("=> 运行态固件消息端点: OUT=0x%02x IN=0x%02x\n", ep_out[o], ep_in[in]);
                return 0;
            }
            printf("无响应\n");
        }
    }
    fprintf(stderr, "所有端点组合均无响应\n");
    libusb_release_interface(dev.h, wlan_if);
    libusb_close(dev.h);
    return 1;
}

static int cmd_status(void)
{
    aic_dev_t dev = {0};
    if (!find_device(&dev, 0)) {
        fprintf(stderr, "未找到 AIC 设备（1111:1111 / a69c:8d80 / a69c:8d83）\n");
        return 1;
    }
    const char *stage_name[] = {"大容量存储(1111:1111)", "Boot ROM(a69c:8d80)", "WiFi运行态(a69c:8d81/8d83)"};
    printf("设备阶段: %s\n", stage_name[dev.stage]);
    if (probe_endpoints(&dev) == 0)
        printf("批量端点: OUT=0x%02x IN=0x%02x\n", dev.ep_out, dev.ep_in);
    if (dev.stage == 0) { libusb_close(dev.h); return 0; }

    /* WiFi 态：WLAN 是接口 2，消息端点 0x02/0x82；Boot ROM：接口 0，0x01/0x82 */
    int claimed = -1;
    if (dev.stage == 2) {
        if (libusb_claim_interface(dev.h, 2) == 0) { claimed = 2; dev.ep_out = 0x02; dev.ep_in = 0x82; }
    } else {
        if (libusb_claim_interface(dev.h, 0) == 0) { claimed = 0; }
    }
    if (claimed < 0) {
        fprintf(stderr, "claim 失败，跳过芯片 ID 读取\n");
        libusb_close(dev.h);
        return 0;
    }
    if (dev.stage == 2) drain_rx(&dev);
    /* 读 0x40500000：chip_id = memdata>>16 */
    uint32_t addr = 0x40500000;
    uint8_t cfm[64] = {0};
    int n = dbg_call(&dev, DBG_MEM_READ_REQ, DBG_MEM_READ_CFM,
                     (uint8_t *)&addr, 4, cfm, sizeof(cfm));
    if (n >= 8) {
        uint32_t memaddr = cfm[0] | (cfm[1]<<8) | (cfm[2]<<16) | ((uint32_t)cfm[3]<<24);
        uint32_t memdata = cfm[4] | (cfm[5]<<8) | (cfm[6]<<16) | ((uint32_t)cfm[7]<<24);
        printf("寄存器 0x%08x = 0x%08x\n", memaddr, memdata);
        printf("chip_id = 0x%02x, chip_mcu_id = %d\n",
               (uint8_t)(memdata >> 16), ((memdata >> 25) & 1) == 0);
        printf("✅ 芯片响应正常，DBG 协议工作\n");
    } else {
        printf("⚠️ 未读到芯片 ID（CFM 解析失败）\n");
    }
    libusb_close(dev.h);
    return 0;
}

static int cmd_reg_read(const char *arg)
{
    aic_dev_t dev = {0};
    if (open_boot(&dev) < 0) return 1;
    uint32_t addr = strtoul(arg, NULL, 16);
    uint8_t cfm[64] = {0};
    int n = dbg_call(&dev, DBG_MEM_READ_REQ, DBG_MEM_READ_CFM,
                     (uint8_t *)&addr, 4, cfm, sizeof(cfm));
    if (n >= 8) {
        uint32_t memdata = cfm[4] | (cfm[5]<<8) | (cfm[6]<<16) | ((uint32_t)cfm[7]<<24);
        printf("0x%08x = 0x%08x\n", addr, memdata);
    }
    libusb_close(dev.h);
    return 0;
}

static int cmd_reg_write(const char *arg1, const char *arg2)
{
    aic_dev_t dev = {0};
    if (open_boot(&dev) < 0) return 1;
    uint32_t addr = strtoul(arg1, NULL, 16);
    uint32_t val  = strtoul(arg2, NULL, 16);
    uint8_t param[8];
    memcpy(&param[0], &addr, 4);
    memcpy(&param[4], &val, 4);
    int n = dbg_call(&dev, DBG_MEM_WRITE_REQ, DBG_MEM_WRITE_CFM,
                     param, 8, NULL, 0);
    printf(n >= 0 ? "写入 OK\n" : "写入失败\n");
    libusb_close(dev.h);
    return 0;
}


/* ================================================================
 * WiFi 命令层（运行态固件）
 * 消息帧格式与 DBG 完全相同（aicwf_set_cmd_tx），换 dest_id 即可
 * 序列: MM_START_REQ -> MM_ADD_IF_REQ -> SCANU_START_REQ -> SM_CONNECT_REQ
 * ================================================================ */

/* ---- lmac 消息 ID = task<<10 ---- */
enum {
    MM_RESET_REQ    = 0x0000, MM_RESET_CFM    = 0x0001,
    MM_START_REQ    = 0x0002, MM_START_CFM    = 0x0003,
    MM_VERSION_REQ  = 0x0004, MM_VERSION_CFM  = 0x0005,
    MM_ADD_IF_REQ   = 0x0006, MM_ADD_IF_CFM   = 0x0007,
    SCANU_START_REQ = 0x1000, SCANU_START_CFM = 0x1001,
    SCANU_JOIN_REQ  = 0x1002, SCANU_JOIN_CFM  = 0x1003,
    SCANU_RESULT_IND= 0x1004,
    SM_CONNECT_REQ  = 0x1800, SM_CONNECT_CFM  = 0x1801,
    SM_CONNECT_IND  = 0x1802, SM_DISCONNECT_REQ = 0x1803,
};

#define TASK_MM    0
#define TASK_ME    5
#define TASK_SCANU 4
#define TASK_SM    6

/* 连接 flags (mac_connection_flags) */
#define CONN_FLAG_CONTROL_PORT_HOST 0x01
#define CONN_FLAG_CONTROL_PORT_NO_ENC 0x02
#define CONN_FLAG_DISABLE_HT      0x04
#define CONN_FLAG_WPA_WPA2_IN_USE 0x08

/* phy_cfg: 全零 + 驱动默认（firmware 有默认值，start 只告知存在） */
struct mm_start_req {
    uint32_t phy_cfg[16];   /* PHY_CFG_BUF_SIZE 参数缓冲 */
    uint32_t uapsd_timeout;
    uint16_t lp_clk_accuracy;
};

struct mm_add_if_req {
    uint8_t type;       /* [0] 0=STA */
    uint8_t pad;        /* [1] */
    uint8_t addr[6];    /* [2-7] MAC——固件从偏移 2 读取！此前放偏移 1 导致
                         * vif MAC 被左移一字节（末字节变 00），AP 关联
                         * 错 MAC、PTK 的 SA 错、hostdesc 源 MAC 与 vif 不匹配，
                         * 表现为 DATA_CFM tx_done=1 但 acknowledged=0。 */
    uint8_t p2p;        /* [8] */
    uint8_t pad2;       /* [9] */
};

/* mac_chan_def: freq(u16) band(u8) flags(u8) tx_power(s8) */
struct mac_chan_def { uint16_t freq; uint8_t band; uint8_t flags; int8_t tx_power; };
/* mac_ssid: length(u8) array[32] */
struct mac_ssid { uint8_t length; uint8_t array[32]; };

#define SCAN_CHANNEL_2G_MAX 14
#define SCAN_SSID_MAX 3

struct scanu_start_req {
    struct mac_chan_def chan[42];   /* SCAN_CHANNEL_MAX = 24G 14 + 5G 28 */
    struct mac_ssid ssid[SCAN_SSID_MAX];
    uint8_t bssid_pad;    /* 对齐：驱动 bssid 在偏移 352 */
    uint8_t bssid[6];
    uint32_t add_ies;
    uint16_t add_ie_len;
    uint8_t vif_idx;
    uint8_t chan_cnt;
    uint8_t ssid_cnt;
    uint8_t no_cck;
    uint32_t duration;
};

struct sm_connect_req {
    struct mac_ssid ssid;
    uint8_t bssid_pad;    /* 对齐：驱动 bssid(mac_addr u16[3]) 在偏移 34 */
    uint8_t bssid[6];
    struct mac_chan_def chan;
    uint32_t flags;
    uint16_t ctrl_port_ethertype;
    uint16_t ie_len;
    uint16_t listen_interval;
    uint8_t dont_wait_bcmc;
    uint8_t auth_type;    /* 0=open */
    uint8_t uapsd_queues;
    uint8_t vif_idx;
    uint8_t pad[2];       /* 对齐：驱动 ie_buf 在偏移 64 */
    uint8_t ie_buf[256];  /* 驱动给 64*u32=256，够放 RSN IE */
};

/* ---- 通用 lmac 消息收发（dest_id 可配）---- */
static int lmac_send(aic_dev_t *dev, uint16_t dest_id, uint16_t msg_id,
                     const uint8_t *param, uint16_t param_len)
{
    uint8_t buf[MSG_BUF_MAX];
    if (param_len > sizeof(buf) - 16) {
        fprintf(stderr, "lmac_send 参数过长: %u\n", param_len);
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    uint16_t len = 8 + param_len;
    buf[0] = (len + 4) & 0xff;
    buf[1] = ((len + 4) >> 8) & 0x0f;
    buf[2] = USB_TYPE_CFG_CMD_RSP;
    buf[3] = 0x00;
    buf[8]  = msg_id & 0xff;  buf[9]  = (msg_id >> 8) & 0xff;
    buf[10] = dest_id & 0xff; buf[11] = (dest_id >> 8) & 0xff;
    buf[12] = DRV_TASK_ID & 0xff; buf[13] = (DRV_TASK_ID >> 8) & 0xff;
    buf[14] = param_len & 0xff; buf[15] = (param_len >> 8) & 0xff;
    if (param_len && param) memcpy(&buf[16], param, param_len);
    int total = len + 8, xfer = 0;
    {
        const char *d = getenv("AIC_MSGDUMP");
        if (d) {
            printf("[MSGDUMP] id=0x%04x plen=%u param:", msg_id, param_len);
            for (int z = 0; z < param_len && z < 96; z++) printf(" %02x", param[z]);
            printf("\n"); fflush(stdout);
        }
    }
    int rc = libusb_bulk_transfer(dev->h, dev->ep_out, buf, total, &xfer, 5000);
    if (rc < 0) { fprintf(stderr, "发送失败 id=0x%04x: %s\n", msg_id, libusb_error_name(rc)); return -1; }
    return 0;
}

/* 读一条 RX 记录。返回 param 实际长度（>=0），超时 -2，其他错误 -1。
 * msg id 经 id_out 回传（曾直接返回 msg id，导致调用方所有长度检查失效）。
 * 拷贝长度三重收紧：min(上报 plen, 调用方缓冲, 实际传输字节数)。 */
static int lmac_recv(aic_dev_t *dev, int timeout_ms, uint16_t *id_out,
                     uint8_t *param_out, int param_cap)
{
    uint8_t buf[CFG_BUF_MAX];
    int xfer = 0;
    int rc = libusb_bulk_transfer(dev->h, dev->ep_in, buf, sizeof(buf), &xfer, timeout_ms);
    if (rc == LIBUSB_ERROR_TIMEOUT) return -2;
    if (rc < 0) return -1;
    if (xfer < 16) return -1;
    uint8_t type = buf[2] & 0x7f;
    if (type != USB_TYPE_CFG_CMD_RSP) return -1;   /* 0x12=TX confirm, 0x13=print 暂不处理 */
    uint16_t id   = buf[4] | (buf[5] << 8);
    uint16_t plen = buf[10] | (buf[11] << 8);
    if (id_out) *id_out = id;
    int n = 0;
    if (param_out && plen > 0) {
        n = plen;
        if (n > param_cap) n = param_cap;
        if (n > xfer - 16) n = xfer - 16;   /* 只拷实际收到的字节，防未初始化栈外泄 */
        if (n > 0) memcpy(param_out, &buf[16], (size_t)n);
    }
    return n;
}


/* 清空 RX 队列：设备端点 FIFO 里可能残留上次会话的响应（跨进程持久） */
static void drain_rx(aic_dev_t *dev)
{
    uint8_t buf[CFG_BUF_MAX];
    int xfer = 0, n = 0;
    while (n < 64) {
        int rc = libusb_bulk_transfer(dev->h, dev->ep_in, buf, sizeof(buf), &xfer, 100);
        if (rc == LIBUSB_ERROR_TIMEOUT) break;
        if (rc < 0) break;
        n++;
    }
    if (n) printf("(已清空 %d 条残留响应)\n", n);
}

/* 等待指定 msg id 的 CFM，最多跳过 max_skip 条无关消息。返回 param_len，失败 -1 */
static int wait_cfm(aic_dev_t *dev, uint16_t want_id, int timeout_ms, int max_skip,
                    uint8_t *param_out, int param_cap)
{
    int skipped = 0;
    while (skipped <= max_skip) {
        uint16_t rid = 0;
        uint8_t param[1024];
        int r = lmac_recv(dev, timeout_ms, &rid, param, sizeof(param));
        if (r == -2) { printf("等 CFM 0x%04x 超时\n", want_id); return -1; }
        if (r < 0) continue;
        if (rid == want_id) {
            if (param_out) {
                int n = r > param_cap ? param_cap : r;
                memcpy(param_out, param, n);
            }
            return r;
        }
        skipped++;
        printf("(跳过无关响应 id=0x%04x param:", rid);
        for (int z = 0; z < 16 && z < r; z++) printf(" %02x", param[z]);
        printf(")\n");
    }
    printf("连续 %d 条无关响应，放弃等待 0x%04x\n", skipped, want_id);
    return -1;
}

/* 打开 WiFi 运行态设备：找 WLAN 接口(0xFF)，消息端点 0x02/0x82 */
static int open_wifi(aic_dev_t *dev)
{
    if (!find_device(dev, PID_WIFI) && !find_device(dev, PID_WIFI_ALT)) {
        fprintf(stderr, "未找到 WiFi 运行态设备（a69c:8d81/8d83）\n");
        fprintf(stderr, "若设备在 1111:1111 或 a69c:8d80，先跑 mode-switch / fw-upload\n");
        return -1;
    }
    libusb_device *d = libusb_get_device(dev->h);
    struct libusb_config_descriptor *cfg;
    if (libusb_get_active_config_descriptor(d, &cfg) < 0) { libusb_close(dev->h); return -1; }
    int wlan_if = -1;
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface_descriptor *id = &cfg->interface[i].altsetting[0];
        if (id->bInterfaceClass == 0xFF && id->bNumEndpoints >= 4) { wlan_if = id->bInterfaceNumber; break; }
    }
    libusb_free_config_descriptor(cfg);
    if (wlan_if < 0) { fprintf(stderr, "未找到 WLAN 接口\n"); libusb_close(dev->h); return -1; }

    libusb_set_auto_detach_kernel_driver(dev->h, 1);
    int rc = libusb_claim_interface(dev->h, wlan_if);
    if (rc < 0) { fprintf(stderr, "claim 接口 %d 失败: %s\n", wlan_if, libusb_error_name(rc)); libusb_close(dev->h); return -1; }
    /* 运行态消息端点：第二对（数据是第一对 0x01/0x81）——wifi-test 实测 */
    dev->ep_out = 0x02;
    dev->ep_in  = 0x82;
    printf("WLAN 接口=%d 消息端点 OUT=0x02 IN=0x82\n", wlan_if);
    drain_rx(dev);   /* 关键：先清残留，否则响应整体错位一条 */
    return 0;
}


/* ================================================================
 * RF 初始化（aicwf_set_rf_config_8800d80 + me_chan_config）
 * 驱动在 MM_START 之前发送：没有它射频不工作，扫描零结果
 * ================================================================ */

#define ME_CONFIG_REQ          0x1400
#define ME_CONFIG_CFM          0x1401
#define ME_CHAN_CONFIG_REQ     0x1402
#define ME_CHAN_CONFIG_CFM     0x1403
#define MM_SET_STACK_START_REQ 0x007b
#define MM_SET_STACK_START_CFM 0x007c
#define MM_SET_TXPWR_OFST_CFM  0x007a
#define MM_SET_TXPWR_LVL_ADJ_CFM 0x008a
#define MM_SET_TXPWR_LVL_REQ   0x0077
#define MM_SET_TXPWR_LVL_CFM   0x0078
#define MM_SET_TXPWR_OFST_REQ  0x0079
#define MM_SET_TXPWR_LVL_ADJ_REQ 0x0089
#define MM_SET_RF_CALIB_REQ    0x0069
#define MM_SET_RF_CALIB_CFM    0x006a
#define MM_VERSION_REQ         0x0004
#define MM_VERSION_CFM         0x0005
#define MM_GET_MAC_ADDR_REQ    0x0073
#define MM_GET_MAC_ADDR_CFM    0x0074
#define MM_GET_FW_VERSION_REQ  0x0080
#define MM_GET_FW_VERSION_CFM  0x0081

struct me_chan_config_req {
    struct mac_chan_def chan2G4[14];
    struct mac_chan_def chan5G[28];
    uint8_t chan2G4_cnt;
    uint8_t chan5G_cnt;
};

/* ME_CHAN_CONFIG_REQ 完整参数（与参考驱动实发逐字节一致，254 字节）：
 * 14×2.4G(2412-2484, band=0) + 25×5G(5180-5805, band=1)，全部 tx_power=30，
 * chan2G4_cnt=14 / chan5G_cnt=25。此前只填 13 条 2.4G、5G 全零且
 * chan5G_cnt=0——固件信道上下文表不完整，关联后 TX 不被 ACK
 * （DATA_CFM tx_done=1、acknowledged=0）。AIC_CHAN13=1 回退旧行为。 */
static const uint8_t me_chan_config_param[254] = {
    0x6c, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x71, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x76, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x7b, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x80, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x85, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x8a, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x8f, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x94, 0x09, 0x00, 0x00, 0x1e, 0x00, 0x99, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x9e, 0x09, 0x00, 0x00, 0x1e, 0x00, 0xa3, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0xa8, 0x09, 0x00, 0x00, 0x1e, 0x00, 0xb4, 0x09, 0x00, 0x00, 0x1e, 0x00,
    0x3c, 0x14, 0x01, 0x00, 0x1e, 0x00, 0x50, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0x64, 0x14, 0x01, 0x00, 0x1e, 0x00, 0x78, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0x8c, 0x14, 0x01, 0x00, 0x1e, 0x00, 0xa0, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0xb4, 0x14, 0x01, 0x00, 0x1e, 0x00, 0xc8, 0x14, 0x01, 0x00, 0x1e, 0x00,
    0x7c, 0x15, 0x01, 0x00, 0x1e, 0x00, 0x90, 0x15, 0x01, 0x00, 0x1e, 0x00,
    0xa4, 0x15, 0x01, 0x00, 0x1e, 0x00, 0xb8, 0x15, 0x01, 0x00, 0x1e, 0x00,
    0xcc, 0x15, 0x01, 0x00, 0x1e, 0x00, 0xe0, 0x15, 0x01, 0x00, 0x1e, 0x00,
    0xf4, 0x15, 0x01, 0x00, 0x1e, 0x00, 0x08, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x1c, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x30, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x44, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x58, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x71, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x85, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0x99, 0x16, 0x01, 0x00, 0x1e, 0x00, 0xad, 0x16, 0x01, 0x00, 0x1e, 0x00,
    0xc1, 0x16, 0x01, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0e, 0x19,
};


/* txpwr_lvl_conf_v3_t（rwnx_platform.h）*/
struct txpwr_lvl_v3 {
    uint8_t enable;
    int8_t pwrlvl_11b_11ag_2g4[12];
    int8_t pwrlvl_11n_11ac_2g4[10];
    int8_t pwrlvl_11ax_2g4[12];
    int8_t pwrlvl_11a_5g[12];
    int8_t pwrlvl_11n_11ac_5g[10];
    int8_t pwrlvl_11ax_5g[12];
};

struct txpwr_lvl_adj {
    uint8_t enable;
    int8_t tbl_2g4[3];
    int8_t tbl_5g[6];
};

struct txpwr_ofst2x {
    uint8_t enable;
    int8_t tbl_2g4[3][3];
    int8_t tbl_5g[3][6];
};

struct mm_set_rf_calib_req {
    uint32_t cal_cfg_24g;
    uint32_t cal_cfg_5g;
    uint32_t param_alpha;
    uint32_t bt_calib_en;
    uint32_t bt_calib_param;
    uint8_t xtal_cap;
    uint8_t xtal_cap_fine;
};

/* 驱动默认 userconfig（rwnx_platform.c userconfig_info）*/
static void fill_txpwr_lvl_v3(struct txpwr_lvl_v3 *p)
{
    /* 数值与 aic_userconfig_8800d80.txt 完全一致（参考驱动真机握手通过的表）*/
    static const int8_t b11ag[] = {18,18,18,18,18,18,18,18,16,16,15,15};
    static const int8_t n11ac[] = {18,18,18,18,16,16,15,15,14,14};
    static const int8_t ax2g[]  = {18,18,18,18,16,16,15,15,14,14,13,13};
    static const int8_t a5g[]   = {18,18,18,18,16,16,15,15,16,16,15,15};
    static const int8_t n5g[]   = {18,18,18,18,16,16,15,15,14,14};
    static const int8_t ax5g[]  = {18,18,18,18,16,16,14,14,13,13,12,12};
    memset(p, 0, sizeof(*p));
    p->enable = 1;
    memcpy(p->pwrlvl_11b_11ag_2g4, b11ag, sizeof(b11ag));
    memcpy(p->pwrlvl_11n_11ac_2g4, n11ac, sizeof(n11ac));
    memcpy(p->pwrlvl_11ax_2g4, ax2g, sizeof(ax2g));
    memcpy(p->pwrlvl_11a_5g, a5g, sizeof(a5g));
    memcpy(p->pwrlvl_11n_11ac_5g, n5g, sizeof(n5g));
    memcpy(p->pwrlvl_11ax_5g, ax5g, sizeof(ax5g));
}

/* 发消息等 CFM，超时不算致命（日志提示继续）*/
static int rf_send_cfm(aic_dev_t *dev, uint16_t dest, uint16_t req, uint16_t cfm,
                       const uint8_t *param, uint16_t plen, const char *name)
{
    (void)name;   /* 仅作调用点可读性标注 */
    if (lmac_send(dev, dest, req, param, plen) < 0) return -1;
    uint8_t c[64] = {0};
    int n = wait_cfm(dev, cfm, 2000, 4, c, sizeof(c));
    if (n < 0) { printf("(无 CFM，继续)\n"); return 0; }
    printf("✅(CFM %d 字节)\n", n);
    return 0;
}

/* STA MAC：优先 AIC_STAMAC 环境变量指定；否则向固件读 efuse 里的真实 MAC
 * （MM_GET_MAC_ADDR_CFM）。绝不再硬编码——硬编码既泄露硬件身份，又让别的
 * 模块用本驱动时 MAC 错误（AP 关联错 MAC、TX 永不 ACK，症状离现场很远）。 */
static uint8_t g_sta_mac[6] = {0};

static int read_sta_mac(aic_dev_t *dev)
{
    const char *env = getenv("AIC_STAMAC");
    if (env && *env) {
        unsigned m[6];
        if (sscanf(env, "%x:%x:%x:%x:%x:%x",
                   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
            for (int i = 0; i < 6; i++) g_sta_mac[i] = (uint8_t)m[i];
            printf("[MAC] 使用 AIC_STAMAC 指定的 STA MAC\n");
            return 0;
        }
        printf("[MAC] AIC_STAMAC 格式错误（应为 xx:xx:xx:xx:xx:xx），改用 efuse\n");
    }
    uint8_t get_flag = 1;
    if (lmac_send(dev, TASK_MM, MM_GET_MAC_ADDR_REQ, &get_flag, 1) < 0) return -1;
    uint8_t mac[128] = {0};
    int n = wait_cfm(dev, MM_GET_MAC_ADDR_CFM, 2000, 4, mac, sizeof(mac));
    if (n < 6) { printf("[MAC] GET_MAC_ADDR 无 CFM\n"); return -1; }
    if (getenv("AIC_DEBUG_MAC")) {
        printf("[MAC] CFM %d 字节:", n);
        for (int i = 0; i < n; i++) printf(" %02x", mac[i]);
        printf("\n");
    }
    /* 优先取 payload 前 6 字节；若前 6 字节不像单播 MAC（首字节 bit0=1 或全零），
     * 在 payload 里找第一个合法单播 MAC——兼容 CFM 带 status 前缀的固件变体。
     * 找不到必须失败：用组播/全零 MAC 建 vif 会让关联与 PTK 全错且症状远离现场。 */
    const uint8_t *p = NULL;
    if (!(mac[0] & 1) && !(mac[0] == 0 && mac[1] == 0 && mac[2] == 0)) {
        p = mac;
    } else {
        for (int off = 1; off + 6 <= n; off++) {
            if (!(mac[off] & 1) && !(mac[off] == 0 && mac[off+1] == 0 && mac[off+2] == 0)) {
                p = mac + off;
                break;
            }
        }
    }
    if (!p) {
        printf("[MAC] CFM 里找不到合法单播 MAC，拒绝继续\n");
        return -1;
    }
    memcpy(g_sta_mac, p, 6);
    printf("[MAC] efuse STA MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_sta_mac[0], g_sta_mac[1], g_sta_mac[2], g_sta_mac[3], g_sta_mac[4], g_sta_mac[5]);
    return 0;
}

static int wifi_rf_init(aic_dev_t *dev)
{
    /* 1. ME_CHAN_CONFIG_REQ：2.4G 13 信道
     * AIC_NO_FIRST_CHANCFG=1 跳过这遍：参考驱动只发一次 ME_CHAN_CONFIG 且在
     * MM_RESET 之后（顺序：STACK_START→GET_FW_VERSION→TXPWR→CALIB→GET_MAC→
     * RESET→VERSION→CHAN_CONFIG→START→ADD_IF）。我们在 RF init 里提前发的这遍
     * 可能在 RF 校准前锁定信道配置。 */
    if (getenv("AIC_NO_FIRST_CHANCFG")) {
        printf("[RF 1/5] ME_CHAN_CONFIG_REQ ... (跳过，AIC_NO_FIRST_CHANCFG)\n");
    } else
    /* 1. ME_CHAN_CONFIG_REQ：2.4G 13 信道 */
    {
    if (getenv("AIC_CHAN13")) {
        struct me_chan_config_req mc; memset(&mc, 0, sizeof(mc));
        for (int ch = 1; ch <= 13; ch++) {
            mc.chan2G4[ch-1].freq = 2407 + ch * 5;
            mc.chan2G4[ch-1].band = 0;
            mc.chan2G4[ch-1].flags = 0;
            mc.chan2G4[ch-1].tx_power = 30;
        }
        mc.chan2G4_cnt = 13;
        mc.chan5G_cnt = 0;
        printf("[RF 1/5] ME_CHAN_CONFIG_REQ(2.4G x13, AIC_CHAN13) ... "); fflush(stdout);
        if (rf_send_cfm(dev, TASK_ME, ME_CHAN_CONFIG_REQ, ME_CHAN_CONFIG_CFM, (uint8_t *)&mc, sizeof(mc), "chan") < 0) return -1;
    } else {
    printf("[RF 1/5] ME_CHAN_CONFIG_REQ(42 频道，参考原参) ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_ME, ME_CHAN_CONFIG_REQ, ME_CHAN_CONFIG_CFM, me_chan_config_param, sizeof(me_chan_config_param), "chan") < 0) return -1;
    }
    }

    /* 2. TXPWR_LVL v3：直接使用参考驱动实发的 95 字节（mm_set_txpwr_lvl_req
     * 联合体大小，v3 数据在前 69 字节 + 26 填充）。此前发 69 字节纯 v3 结构，
     * 固件按联合体长度解析导致功率表错位——TX 功率不足使 AP 收不到握手帧
     * （DATA_CFM tx_done=1 但 acknowledged=0）。AIC_TXPWR69=1 回退旧行为。 */
    static const uint8_t txpwr95[95] = {
        0x01, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x10, 0x10, 0x0f,
        0x0f, 0x12, 0x12, 0x12, 0x12, 0x10, 0x10, 0x0f, 0x0f, 0x0e, 0x0e, 0x12,
        0x12, 0x12, 0x12, 0x10, 0x10, 0x0f, 0x0f, 0x0e, 0x0e, 0x0d, 0x0d, 0x80,
        0x80, 0x80, 0x80, 0x12, 0x12, 0x12, 0x12, 0x10, 0x10, 0x0f, 0x0f, 0x12,
        0x12, 0x12, 0x12, 0x10, 0x10, 0x0f, 0x0f, 0x0e, 0x0e, 0x12, 0x12, 0x12,
        0x12, 0x10, 0x10, 0x0e, 0x0e, 0x0d, 0x0d, 0x0c, 0x0c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    struct txpwr_lvl_v3 lvl; fill_txpwr_lvl_v3(&lvl);
    const uint8_t *txpwr_param = txpwr95;
    uint16_t txpwr_len = sizeof(txpwr95);
    if (getenv("AIC_TXPWR69")) { txpwr_param = (const uint8_t *)&lvl; txpwr_len = sizeof(lvl); }
    /* 参数长度必须 = sizeof(struct txpwr_lvl_conf_v3) = 1+12+10+12+12+10+12 = 69。
     * 此前发 95 字节（按联合体最大值估的），与参考实现（sizeof(union)=69）不一致，
     * 固件可能因长度异常拒收或错位解析功率表。 */
    printf("[RF 2/5] MM_SET_TXPWR_IDX_LVL_REQ(v3, %u 字节) ... ", txpwr_len);
    fflush(stdout);
    if (rf_send_cfm(dev, TASK_MM, MM_SET_TXPWR_LVL_REQ, MM_SET_TXPWR_LVL_CFM,
                    txpwr_param, txpwr_len, "lvl") < 0) return -1;

    /* 3. TXPWR_LVL_ADJ（默认全零）。参考驱动 aicwf_set_rf_config_8800d80 不发
     * 这条——AIC_NO_ADJ=1 跳过（对齐参考的 RF init 序列）。 */
    struct txpwr_lvl_adj adj; memset(&adj, 0, sizeof(adj));
    if (getenv("AIC_NO_ADJ")) {
        printf("[RF 3/5] MM_SET_TXPWR_LVL_ADJ_REQ ... (跳过，AIC_NO_ADJ)\n");
    } else {
    printf("[RF 3/5] MM_SET_TXPWR_LVL_ADJ_REQ ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_MM, MM_SET_TXPWR_LVL_ADJ_REQ, MM_SET_TXPWR_LVL_ADJ_CFM, (uint8_t *)&adj, sizeof(adj), "adj") < 0) return -1;
    }

    /* 4. TXPWR_OFST2X（enable=0）*/
    struct txpwr_ofst2x ofst; memset(&ofst, 0, sizeof(ofst));
    uint8_t ofstbuf[86]; memset(ofstbuf, 0, sizeof(ofstbuf));  /* sizeof(mm_set_txpwr_ofst_req)=86 */
    memcpy(ofstbuf, &ofst, sizeof(ofst));
    if (getenv("AIC_NO_ADJ")) {
        printf("[RF 4/5] MM_SET_TXPWR_OFST_REQ(ofst2x) ... (跳过，AIC_NO_ADJ)\n");
    } else {
    printf("[RF 4/5] MM_SET_TXPWR_OFST_REQ(ofst2x) ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_MM, MM_SET_TXPWR_OFST_REQ, MM_SET_TXPWR_OFST_CFM, ofstbuf, sizeof(ofstbuf), "ofst") < 0) return -1;
    }

    /* 5. RF_CALIB（D81 参数）*/
    struct mm_set_rf_calib_req cal; memset(&cal, 0, sizeof(cal));
    cal.cal_cfg_24g = 0x0f8f;
    cal.cal_cfg_5g  = 0x0f0f;
    cal.param_alpha = 0x0c34c008;
    cal.bt_calib_en = 0;
    cal.bt_calib_param = 0x264203;
    cal.xtal_cap = 0;
    cal.xtal_cap_fine = 0;
    printf("[RF 5/5] MM_SET_RF_CALIB_REQ ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_MM, MM_SET_RF_CALIB_REQ, MM_SET_RF_CALIB_CFM, (uint8_t *)&cal, sizeof(cal), "calib") < 0) return -1;
    return 0;
}


struct mm_set_stack_start_req {
    uint8_t is_stack_start;
    uint8_t efuse_valid;
    uint8_t set_vendor_info;
    uint8_t fwtrace_redir;
};


/* ---- ME_CONFIG_REQ（HT/VHT/HE 能力，驱动默认 2.4G）---- */
struct me_config_req {
    uint8_t ht_cap[32];    /* mac_htcapability */
    uint8_t vht_cap[12];   /* mac_vhtcapability */
    uint8_t he_cap[56];    /* mac_hecapability */
    uint16_t tx_lft;
    uint8_t phy_bw_max;
    uint8_t ht_supp;
    uint8_t vht_supp;
    uint8_t he_supp;
    uint8_t he_ul_on;
    uint8_t ps_on;
    uint8_t ant_div_on;
    uint8_t dpsm;
};

static int send_me_config(aic_dev_t *dev)
{
    struct me_config_req mc;
    memset(&mc, 0, sizeof(mc));
    /* 全零：与参考实现一致（它的 band 静态初始化没设 ht_cap → ht_supp=0/
     * phy_bw_max=0/ps_on=0）。真机握手通过的配置。 */
    mc.tx_lft = 0;
    mc.phy_bw_max = 0;      /* PHY_CHNL_BW_20 */
    mc.ht_supp = 0;
    mc.vht_supp = 0;
    mc.he_supp = 0;
    mc.he_ul_on = 0;
    mc.ps_on = 0;
    mc.ant_div_on = 0;
    mc.dpsm = 0;
    if (lmac_send(dev, TASK_ME, ME_CONFIG_REQ, (uint8_t *)&mc, sizeof(mc)) < 0) return -1;
    uint8_t cfm[64] = {0};
    int n = wait_cfm(dev, ME_CONFIG_CFM, 3000, 8, cfm, sizeof(cfm));
    if (n < 0) { printf("(无 CFM，继续)\n"); return 0; }
    printf("✅\n");
    return 0;
}

/* 完整初始化序列（严格按驱动 rwnx_main.c 顺序）：
 * RF配置 -> STACK_START -> RESET -> CHAN_CONFIG -> MM_START -> ADD_IF */
static int wifi_full_init(aic_dev_t *dev)
{
    printf("=== 完整初始化序列 ===\n");

    /* wdt_config：向固件内存 0x4010300c 写 1（mask 1）。
     * 参考驱动 rwnx_ic_system_init 里必发（rwnx_send_dbg_mem_mask_write_req），
     * 我们此前漏了它——实测缺这条时间谍端固件 TX 通路不发射（帧进队列、
     * DATA_CFM 报 tx_done=1 但 acknowledged=0，AP 永远收不到 → 一直重传 Msg1）。 */
    {
        uint8_t wdt[12];
        uint32_t addr = 0x4010300c, mask = 0x00000001, data = 0x00000001;
        memcpy(&wdt[0], &addr, 4);
        memcpy(&wdt[4], &mask, 4);
        memcpy(&wdt[8], &data, 4);
        printf("[init 0/8] DBG_MEM_MASK_WRITE(0x4010300c <- 1) ... ");
        fflush(stdout);
        int wn = dbg_call(dev, DBG_MEM_MASK_WRITE_REQ, DBG_MEM_MASK_WRITE_CFM,
                          wdt, sizeof(wdt), NULL, 0);
        printf(wn >= 0 ? "✅\n" : "(无 CFM，继续)\n");
        fflush(stdout);
    }

    /* rf_config：清 0x40344058 的 bit23（mask 0x00800000, data 0）——"pll trx"
     * 发射 PLL 使能。Linux 驱动 rwnx_platform_on 里位于 patch_config 之后、
     * DBG_START_APP_REQ 之前（rf_tbl_masked），参考驱动同样在启动固件前发。
     * 缺它 = TX PLL 不使能：固件收下帧、DATA_CFM 报 tx_done=1，但空口零辐射，
     * acknowledged=0，AP 收不到 → 永远重传 Msg1（RX 不受影响，所以beacon/EAPOL
     * 照常能收，极具迷惑性）。固件启动后补写同样有效（PLL 是硬件寄存器）。 */
    {
        uint8_t rf[12];
        uint32_t addr = 0x40344058, mask = 0x00800000, data = 0x00000000;
        memcpy(&rf[0], &addr, 4);
        memcpy(&rf[4], &mask, 4);
        memcpy(&rf[8], &data, 4);
        printf("[init 0/9] rf_config(0x40344058 pll_trx) ... ");
        fflush(stdout);
        int rn = dbg_call(dev, DBG_MEM_MASK_WRITE_REQ, DBG_MEM_MASK_WRITE_CFM,
                          rf, sizeof(rf), NULL, 0);
        printf(rn >= 0 ? "✅\n" : "(无 CFM，继续)\n");
        fflush(stdout);
    }

    /* STACK_START 放在最前（参考实现 rwnx_platform_init 的顺序：
     * STACK_START → VERSION → RF init → RESET → ME_CONFIG → CHAN_CONFIG → MM_START → ADD_IF）。
     * 参数用 D81 分支原值 (1, 0, CO_BIT(5), 0)：efuse_valid=0 让固件采用主机下发的
     * 功率表；传 0x21 会让固件加载 efuse 校准数据、与主机 TXPWR 消息互相冲突。 */
    struct mm_set_stack_start_req ss; memset(&ss, 0, sizeof(ss));
    ss.is_stack_start = 1;
    ss.efuse_valid = 0;
    ss.set_vendor_info = 0x20;   /* CO_BIT(5)，D81 分支原值 */
    ss.fwtrace_redir = 0;
    printf("[init 1/6] MM_SET_STACK_START_REQ ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_MM, MM_SET_STACK_START_REQ, MM_SET_STACK_START_CFM,
                    (uint8_t *)&ss, sizeof(ss), "stack") < 0) return -1;

    /* MM_GET_FW_VERSION_REQ：参考驱动 rwnx_platform_init 在 STACK_START 之后
     * 必发（CFM 64 字节）。此前我们漏了它。 */
    {
        uint8_t gp = 1;
        printf("[init 1.5/8] MM_GET_FW_VERSION_REQ ... ");
        fflush(stdout);
        int gn = rf_send_cfm(dev, TASK_MM, MM_GET_FW_VERSION_REQ, MM_GET_FW_VERSION_CFM,
                             &gp, 1, "fwver");
        printf(gn >= 0 ? "✅\n" : "(无 CFM，继续)\n");
        fflush(stdout);
    }

    if (wifi_rf_init(dev) < 0) { printf("❌ RF 初始化失败\n"); return -1; }

    /* MM_GET_MAC_ADDR_REQ：读 efuse 里的真实 STA MAC（CFM 首 6 字节）。
     * 结果存 g_sta_mac，供 MM_ADD_IF 与 WPA2 上下文使用。 */
    printf("[init 2.5/8] MM_GET_MAC_ADDR_REQ ... ");
    fflush(stdout);
    if (read_sta_mac(dev) < 0) printf("(失败，继续)\n");
    fflush(stdout);

    /* RESET FW */
    printf("[init 3/6] MM_RESET_REQ ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_MM, MM_RESET_REQ, MM_RESET_CFM, NULL, 0, "reset") < 0) return -1;

    /* MM_VERSION_REQ：参考驱动在 RESET 之后必发（无参数，CFM 28 字节）。 */
    {
        printf("[init 3.5/8] MM_VERSION_REQ ... ");
        fflush(stdout);
        int vn = rf_send_cfm(dev, TASK_MM, MM_VERSION_REQ, MM_VERSION_CFM, NULL, 0, "ver");
        printf(vn >= 0 ? "✅\n" : "(无 CFM，继续)\n");
        fflush(stdout);
    }

    /* ME_CONFIG（HT/VHT/HE 能力，关联请求的能力来源）
     * AIC_NO_MECONFIG=1 可跳过：参考驱动（真机握手通过）的初始化序列里
     * 实测没有 ME_CONFIG——它发的 11 条消息是 STACK_START/GET_FW_VERSION/
     * TXPWR_LVL/RF_CALIB/GET_MAC_ADDR/RESET/VERSION/CHAN_CONFIG/START/ADD_IF。 */
    if (getenv("AIC_NO_MECONFIG")) {
        printf("[init 4/7] ME_CONFIG_REQ ... (跳过，AIC_NO_MECONFIG)\n");
    } else {
        printf("[init 4/7] ME_CONFIG_REQ(HT only) ... "); fflush(stdout);
        if (send_me_config(dev) < 0) return -1;
    }

    /* ME_CHAN_CONFIG：与第一处相同，用参考原参（42 频道，含 5G）*/
    printf("[init 4/6] ME_CHAN_CONFIG_REQ(42 频道，参考原参) ... "); fflush(stdout);
    if (rf_send_cfm(dev, TASK_ME, ME_CHAN_CONFIG_REQ, ME_CHAN_CONFIG_CFM,
                    me_chan_config_param, sizeof(me_chan_config_param), "chan") < 0) return -1;

    /* MM_START */
    struct mm_start_req sreq; memset(&sreq, 0, sizeof(sreq));
    sreq.uapsd_timeout = 300;   /* 参考实现默认值（rwnx_mod_params）*/
    sreq.lp_clk_accuracy = 20;
    printf("[init 6/7] MM_START_REQ ... "); fflush(stdout);
    uint8_t cfm[64] = {0};
    if (lmac_send(dev, TASK_MM, MM_START_REQ, (uint8_t *)&sreq, sizeof(sreq)) < 0) return -1;
    int n = wait_cfm(dev, MM_START_CFM, 3000, 8, cfm, sizeof(cfm));
    if (n < 0) { printf("无 CFM\n"); return -1; }
    printf("✅\n");

    /* ADD_IF */
    struct mm_add_if_req areq; memset(&areq, 0, sizeof(areq));
    areq.type = 0;
    if (g_sta_mac[0] == 0 && g_sta_mac[1] == 0 && g_sta_mac[2] == 0) {
        printf("\n❌ 未取到 STA MAC（efuse 读取失败）——拒绝用错误 MAC 建 vif\n");
        return -1;
    }
    memcpy(areq.addr, g_sta_mac, 6);   /* efuse 真实 MAC */
    printf("[init 7/7] MM_ADD_IF_REQ(STA) ... "); fflush(stdout);
    memset(cfm, 0, sizeof(cfm));
    if (lmac_send(dev, TASK_MM, MM_ADD_IF_REQ, (uint8_t *)&areq, sizeof(areq)) < 0) return -1;
    n = wait_cfm(dev, MM_ADD_IF_CFM, 3000, 8, cfm, sizeof(cfm));
    if (n < 0) { printf("无 CFM\n"); return -1; }
    if (cfm[0] != 0) { printf("❌ status=%u\n", cfm[0]); return -1; }
    printf("✅ vif_idx=%u\n", cfm[1]);
    printf("=== 初始化完成 ===\n\n");
    return cfm[1];
}

/* 旧两步启动保留（兼容），新代码走 wifi_full_init */
static int wifi_start(aic_dev_t *dev)
{
    return wifi_full_init(dev);
}

/* 从 beacon/probe-resp 帧解析 SSID */
static void parse_beacon(const uint8_t *frame, uint16_t len, char *ssid_out, int ssid_cap)
{
    ssid_out[0] = 0;
    if (len < 36) return;              /* 24 帧头 + 12 固定参数 */
    const uint8_t *ie = frame + 36;    /* 跳过的固定字段 */
    uint16_t remain = len - 36;
    while (remain >= 2) {
        uint8_t eid = ie[0], elen = ie[1];
        if (elen + 2 > remain) break;
        if (eid == 0 && elen > 0) {    /* SSID */
            int n = elen < ssid_cap - 1 ? elen : ssid_cap - 1;
            memcpy(ssid_out, ie + 2, n);
            ssid_out[n] = 0;
            return;
        }
        ie += 2 + elen;
        remain -= 2 + elen;
    }
}

/* 是否加密（RSN IE id=48 或 WPA IE id=221 vendor MS） */
static int beacon_secured(const uint8_t *frame, uint16_t len)
{
    if (len < 36) return 0;
    const uint8_t *ie = frame + 36;
    uint16_t remain = len - 36;
    while (remain >= 2) {
        uint8_t eid = ie[0], elen = ie[1];
        if (elen + 2 > remain) break;
        if (eid == 48) return 1;       /* RSN */
        if (eid == 221 && elen >= 4 && ie[2] == 0x00 && ie[3] == 0x50 && ie[4] == 0xf2 && ie[5] == 0x01) return 1; /* WPA */
        ie += 2 + elen;
        remain -= 2 + elen;
    }
    return 0;
}

static int cmd_wifi_start(void)
{
    aic_dev_t dev = {0};
    if (open_wifi(&dev) < 0) return 1;
    int vif = wifi_start(&dev);
    libusb_release_interface(dev.h, 2);
    libusb_close(dev.h);
    return vif < 0 ? 1 : 0;
}

static int cmd_scan(int seconds)
{
    aic_dev_t dev = {0};
    if (open_wifi(&dev) < 0) return 1;

    int vif = wifi_start(&dev);
    if (vif < 0) { libusb_close(dev.h); return 1; }

    /* 构造 SCANU_START_REQ：2.4G 全信道，广播 SSID */
    struct scanu_start_req req; memset(&req, 0, sizeof(req));
    for (int ch = 1; ch <= 13; ch++) {
        req.chan[ch-1].freq = 2407 + ch * 5;
        req.chan[ch-1].band = 0;   /* 2.4G */
        req.chan[ch-1].flags = 0;
        req.chan[ch-1].tx_power = 0;
    }
    memset(req.bssid, 0xff, 6);
    req.vif_idx = (uint8_t)vif;
    req.chan_cnt = 13;
    req.ssid_cnt = 0;
    req.duration = 100000;   /* 每信道 100ms */

    printf("扫描 2.4G 13 信道 ...\n");
    if (lmac_send(&dev, TASK_SCANU, SCANU_START_REQ, (uint8_t *)&req, sizeof(req)) < 0) {
        libusb_close(dev.h); return 1;
    }

    time_t start = time(NULL);
    int found = 0;
    while (time(NULL) - start < seconds) {
        uint16_t rid = 0;
        uint8_t param[1024] = {0};
        int r = lmac_recv(&dev, 500, &rid, param, sizeof(param));
        if (r == -2) continue;
        if (r < 0) continue;
        if (rid == SCANU_START_CFM) {
            printf("扫描启动确认 status=%u\n", param[0]);
        } else if (rid == SCANU_RESULT_IND) {
            /* [length:2][framectrl:2][center_freq:2][band:1][sta_idx:1][inst_nbr:1][rssi:1][frame...] */
            if (r >= 12) {
                /* flen 源于设备上报，上界用真实收到的字节数收敛，防 parse_beacon 越界 */
                uint16_t flen = param[0] | (param[1] << 8);
                if (flen > (uint16_t)(r - 12)) flen = (uint16_t)(r - 12);
                uint16_t freq = param[4] | (param[5] << 8);
                int8_t rssi = (int8_t)param[9];   /* offsetof(scanu_result_ind, rssi)=9 */
                const uint8_t *frame = param + 12; /* payload 对齐到 12 */
                char ssid[33] = {0};
                parse_beacon(frame, flen, ssid, sizeof(ssid));
                int sec = beacon_secured(frame, flen);
                int ch = (freq > 2407 && freq < 2500) ? (freq - 2407) / 5 : 0;
                if (ssid[0]) {
                    printf("  [%2d] SSID=%-18s BSSID=%02x:%02x:%02x:%02x:%02x:%02x CH=%2d RSSI=%4d 加密=%s\n",
                           ++found, ssid,
                           frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
                           ch, rssi, sec ? "是" : "否");
                }
            }
        }
    }
    printf("扫描结束，共 %d 个网络\n", found);
    libusb_close(dev.h);
    return 0;
}



/* ================================================================
 * WPA2 连接 + EAPOL 四次握手 + 数据通路
 * 架构：固件做 802.11 auth/assoc + 802.3<->802.11 转换，
 *       主机（本工具）做 EAPOL 4-way 握手（wpa_supplicant 的角色）
 * ================================================================ */

#include <CommonCrypto/CommonCrypto.h>
#include <pthread.h>

#define MM_KEY_ADD_REQ    0x0024   /* 编译驱动头文件验证 */
#define MM_KEY_ADD_CFM    0x0025
#define MAC_CIPHER_CCMP   2

/* DBG 任务（编译驱动 lmac_msg.h 验证：TASK_DBG=1）*/
#define TASK_DBG                  1
#define DBG_SET_MOD_FILTER_REQ    0x0404
#define DBG_SET_SEV_FILTER_REQ    0x0406

/* ---- hostdesc（txdesc_api，驱动 ipc_shared.h）---- */
struct hostdesc {
    uint16_t packet_len;
    uint16_t flags_ext;
    uint32_t status_desc_addr;
    uint8_t  eth_dest_addr[6];
    uint8_t  eth_src_addr[6];
    uint16_t ethertype;
    uint8_t  ac;
    uint8_t  tid;
    uint8_t  vif_idx;
    uint8_t  staid;
    uint16_t flags;
} __attribute__((packed));

/* ---- EAPOL-Key 帧偏移（802.11i）---- */
#define EAPOL_VER        0
#define EAPOL_TYPE       1
#define EAPOL_BODYLEN    2
#define EAPOL_DESCTYPE   4
#define EAPOL_KEYINFO    5
#define EAPOL_KEYLEN     7
#define EAPOL_REPLAY     9
#define EAPOL_NONCE      17
#define EAPOL_IV         49
#define EAPOL_RSC        65
#define EAPOL_ID         73
#define EAPOL_MIC        81
#define EAPOL_DATALEN    97
#define EAPOL_DATA       99

#define KEY_INFO_MIC     0x0100   /* bit 8 */
#define KEY_INFO_ACK     0x0080   /* bit 7 */
#define KEY_INFO_INSTALL 0x0040   /* bit 6 */
#define KEY_INFO_SECURE  0x0200   /* bit 9 */
#define KEY_INFO_ENCDATA 0x1000   /* bit 12 */
#define KEY_INFO_PAIRWISE 0x0008  /* bit 3 */
#define KEY_INFO_VERSION 0x0002   /* bits0-2: Key Descriptor Version 2 = HMAC-SHA1-128 + AES-WRAP（WPA2）。Msg2=0x010a / Msg4=0x030a 是标准值，缺这位 AP 直接判非法 */

/* ---- WPA2 上下文 ---- */
typedef struct {
    aic_dev_t *dev;
    int vif_idx;
    uint8_t sta_mac[6];
    uint8_t ap_mac[6];
    char ssid[33];
    char password[65];
    uint8_t pmk[32];
    uint8_t ptk[48];      /* KCK(16)+KEK(16)+TK(16) for CCMP */
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint64_t replay;
    int got_msg1;
    int got_msg3;
    int handshake_done;
    int ap_idx;           /* SM_CONNECT_IND 返回的 sta_idx */
    pthread_t msg_thread, data_thread;
    int threads_running;
    volatile int msg_pause;   /* =1 时消息线程暂停读 0x82，让主线程同步等 CFM */
    volatile int msg_paused;  /* 消息线程已确认让出端点（pause 握手确认） */
    int data_started, msg_started;   /* 线程是否已创建（决定退出时要不要 join） */
    pthread_mutex_t lock;
    uint8_t gtk[16];
    int gtk_idx;
} wpa2_ctx_t;

/* ---- 密码学原语 ---- */

/* PMK = PBKDF2-HMAC-SHA1(password, ssid, 4096, 32) */
static void wpa2_pmk(const char *pw, const char *ssid, uint8_t *pmk)
{
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, strlen(pw),
                         (const uint8_t *)ssid, strlen(ssid),
                         kCCPRFHmacAlgSHA1, 4096, pmk, 32);
}

/* PRF-X（WPA 用 HMAC-SHA1）: out = PRF(key, label, ctx) */
static void wpa2_prf(const uint8_t *key, int keylen, const char *label,
                     const uint8_t *ctx, int ctxlen, uint8_t *out, int outlen)
{
    int total = 0, counter = 0;   /* WPA PRF 计数器从 0 起（wpa_supplicant 参考实现）*/
    int labellen = (int)strlen(label);
    while (total < outlen) {
        CCHmacContext c;
        CCHmacInit(&c, kCCHmacAlgSHA1, key, keylen);
        CCHmacUpdate(&c, (const void *)label, labellen);
        uint8_t zero = 0;
        CCHmacUpdate(&c, &zero, 1);
        CCHmacUpdate(&c, ctx, ctxlen);
        CCHmacUpdate(&c, &counter, 1);
        uint8_t digest[20];
        CCHmacFinal(&c, digest);
        int n = (outlen - total < 20) ? (outlen - total) : 20;
        memcpy(out + total, digest, n);
        total += n;
        counter++;
    }
}

/* MIC = HMAC-SHA1(KCK, eapol帧, MIC字段清零)[0:16] */
static void wpa2_mic(const uint8_t *kck, const uint8_t *frame, int framelen, uint8_t *mic16)
{
    uint8_t tmp[512];
    if (framelen < EAPOL_MIC + 16 || framelen > (int)sizeof(tmp)) return;
    memcpy(tmp, frame, framelen);
    memset(tmp + EAPOL_MIC, 0, 16);
    CCHmacContext c;
    CCHmacInit(&c, kCCHmacAlgSHA1, kck, 16);
    CCHmacUpdate(&c, tmp, framelen);
    uint8_t digest[20];
    CCHmacFinal(&c, digest);
    memcpy(mic16, digest, 16);
}

/* AES-Key-Unwrap（RFC 3394 §2.2.2），key=KEK(16), in=wrapped(24+8n), out=plain(16+8n)
 * 解包后校验默认 IV A6A6A6A6A6A6A6A6——KEK 错或数据布局错时 IV 必然不匹配。
 * 这是天然的正确性神谕（旧实现结构错+无 IV 校验，错的 KEK 也返回垃圾"成功"）。*/
static int aes_unwrap(const uint8_t *kek, const uint8_t *in, int inlen, uint8_t *out)
{
    if (inlen < 24 || (inlen % 8) != 0) return -1;
    int n = inlen / 8 - 1;
    if (n > 6) return -1;
    uint8_t a[8], b[16], r[6][8];
    memcpy(a, in, 8);
    for (int i = 0; i < n; i++) memcpy(r[i], in + 8 + i * 8, 8);
    size_t moved = 0;
    for (int j = 5; j >= 0; j--) {
        for (int i = n - 1; i >= 0; i--) {
            uint64_t t = (uint64_t)n * j + i + 1;
            memcpy(b, a, 8);
            memcpy(b + 8, r[i], 8);                       /* B = A || R[i] */
            for (int k = 0; k < 8; k++)                   /* A ^= t */
                b[k] ^= (uint8_t)(t >> (8 * (7 - k)));
            CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0,
                                         kek, 16, NULL, b, 16, b, 16, &moved);
            if (st != kCCSuccess) return -1;
            memcpy(a, b, 8);                              /* A = MSB64(B) */
            memcpy(r[i], b + 8, 8);                       /* R[i] = LSB64(B) */
        }
    }
    static const uint8_t kAesWrapIV[8] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
    if (memcmp(a, kAesWrapIV, 8) != 0) return -1;         /* IV 神谕 */
    for (int i = 0; i < n; i++) memcpy(out + i * 8, r[i], 8);
    return n * 8;
}

/* ---- 发送以太网帧（EAPOL/数据）：[len:2][0x01][0x00]+hostdesc+payload ---- */
static int eth_tx(aic_dev_t *dev, const uint8_t *dest, const uint8_t *src,
                  uint16_t ethertype, uint8_t ac, uint8_t staid, uint8_t vif_idx,
                  const uint8_t *payload, uint16_t plen)
{
    struct hostdesc hd;
    memset(&hd, 0, sizeof(hd));
    hd.packet_len = plen;
    hd.flags_ext = 0;
    /* status_desc_addr：驱动对 EAPOL 帧永远写 (1<<31)|txdesc_free_idx（rwnx_tx.c
     * need_cfm 分支），固件据此回传 DATA_CFM 消息；idx 从 0 起，恒 0x80000000 */
    hd.status_desc_addr = 0x80000000u;
    memcpy(hd.eth_dest_addr, dest, 6);
    memcpy(hd.eth_src_addr, src, 6);
    /* ethertype 存「线上字节序原值」：Linux 驱动从 ethhdr.h_proto 原样拷贝
     * （rwnx_tx.c:1340），EAPOL 的 h_proto 内存字节 88 8E → LE u16 值 0x8E88。
     * rwnx_tx.c:646/675 判 EAPOL 的判据就是 ethertype == 0x8e88，固件也按同一
     * 约定与 ctrl_port_ethertype 比对决定控制端口直通（不加密）。 */
    hd.ethertype = (uint16_t)(((ethertype >> 8) & 0xff) | ((ethertype << 8) & 0xff00));
    hd.ac = ac;
    hd.tid = 0;
    hd.vif_idx = vif_idx;
    hd.staid = staid;
    hd.flags = 0;

    /* URB 格式：与参考实现（aic8800-offensive-userspace-driver 的 aicwf_usb_bus_txdata）
     * 逐字节一致——该实现已在真机上完成完整 WPA2 四路握手（Msg2/Msg4 均被 AP 接受）。
     * 要点：transfer_len = 4 + sizeof(hostdesc) + plen，【不做 4 字节填充】；
     * len 字段写 transfer_len 全值（含 4 字节头）；transfer_len 为 512 整数倍时 +1。
     * 此前我们填充到 132 字节且 len=132，固件按 len 校验记录尺寸时与
     * packet_len=99 矛盾（4+28+99=131），整帧被丢——这就是 Msg2 到达不了 AP 的根因。 */
    uint32_t transfer_len = 4 + sizeof(hd) + plen;
    if (transfer_len > 0x0fff) {
        fprintf(stderr, "eth_tx: 帧过长 %u\n", transfer_len);
        return -1;
    }
    uint16_t usb_len = (uint16_t)transfer_len;
    if ((transfer_len % 512) == 0) transfer_len++;
    uint8_t *buf = calloc(1, transfer_len);
    if (!buf) return -1;
    buf[0] = (uint8_t)(usb_len & 0xff);
    buf[1] = (uint8_t)((usb_len >> 8) & 0x0f);
    buf[2] = 0x01;   /* AIC8800_USB_TX_DATA_TYPE */
    buf[3] = 0x00;
    memcpy(buf + 4, &hd, sizeof(hd));
    if (plen) memcpy(buf + 4 + sizeof(hd), payload, plen);

    int xfer = 0;
    printf("[TX] URB %u 字节 ep=0x01:", transfer_len);
    for (uint32_t i = 0; i < transfer_len && i < 80; i++) printf(" %02x", buf[i]);
    printf("\n");
    int rc = libusb_bulk_transfer(dev->h, 0x01, buf, (int)transfer_len, &xfer, 1000);
    printf("[TX] rc=%d xfer=%d/%u\n", rc, xfer, transfer_len);
    free(buf);
    if (rc < 0) {
        fprintf(stderr, "eth_tx 失败: %s\n", libusb_error_name(rc));
        return -1;
    }
    return 0;
}

/* 发 EAPOL 帧（dest=AP, ethertype 0x888E）
 * ac 字段 = 硬件队列号（驱动铁律 ac = rwnx_tid2hwq[tid]）：tid=0 → BE(1)。
 * 曾错配 VI(2) 与 tid=0 组合，驱动永远不会产生这种组合。 */
static int eapol_tx(aic_dev_t *dev, wpa2_ctx_t *ctx, const uint8_t *frame, int framelen)
{
    /* staid 实验：参考驱动成功握手时 hostdesc.staid=1（首次失败连接占掉 0）。
     * 用环境变量 AIC_STAID 覆盖，默认仍用 IND 报的 ap_idx。 */
    {
        const char *s = getenv("AIC_STAID");
        if (s) ctx->ap_idx = (uint8_t)atoi(s);
    }
    /* AIC_TXDEST：强制 TX 目标 MAC（覆盖 IND 报的 AP MAC）。
     * 参考驱动成功握手时 IND 报 a6 而 beacon 是 a4——空口目的地可能不是
     * 关联 BSSID，用此开关验证 dest 对 AP 收包的影响。 */
    uint8_t txdest[6];
    memcpy(txdest, ctx->ap_mac, 6);
    {
        const char *d = getenv("AIC_TXDEST");
        if (d && strlen(d) >= 17) {
            unsigned v[6];
            if (sscanf(d, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) {
                for (int i = 0; i < 6; i++) txdest[i] = (uint8_t)v[i];
                printf("[TX] 强制目标 MAC=%s\n", d);
            }
        }
    }
    return eth_tx(dev, txdest, ctx->sta_mac, 0x888E, 1 /*BE: tid0 对应队列*/, ctx->ap_idx,
                  ctx->vif_idx, frame, framelen);
}

/* RSN IE（WPA2-PSK/CCMP）——SM_CONNECT_REQ 的 ie_buf 与 Msg2/4 的 key_data 共用。
 * 802.11 规范要求 Msg2 的 Key Data 携带 STA 的 RSNE，缺了它 AP 直接丢 Msg2
 * （参考实现 barely_ap RSN IE 22 字节，真机握手验证通过）。 */
static const uint8_t rsn_ie[] = {
    0x30, 0x14,                   /* id=48(RSN), len=20 */
    0x01, 0x00,                   /* version 1 */
    0x00, 0x0F, 0xAC, 0x04,       /* group cipher: CCMP */
    0x01, 0x00,                   /* pairwise count 1 */
    0x00, 0x0F, 0xAC, 0x04,       /* pairwise: CCMP */
    0x01, 0x00,                   /* AKM count 1 */
    0x00, 0x0F, 0xAC, 0x02,       /* AKM: PSK */
    0x00, 0x00,                   /* RSN caps：与参考一致（0x0000） */
};

/* ---- 构造 EAPOL-Key 帧 ---- */
static int build_eapol_key(uint8_t *frame, uint16_t key_info, uint64_t replay,
                           const uint8_t *nonce, const uint8_t *mic /*16 or NULL*/,
                           const uint8_t *data, uint16_t datalen)
{
    /* frame 缓冲固定 256 字节：95 字节 EAPOL-Key 头 + key data。
     * datalen 超界直接拒绝，防止调用方传入过长 IE 时栈溢出。 */
    if (EAPOL_DATA + (int)datalen > 256) return -1;
    memset(frame, 0, 256);
    frame[EAPOL_VER] = 2;
    frame[EAPOL_TYPE] = 3;    /* EAPOL-Key */
    uint16_t bodylen = 95 + datalen;
    frame[EAPOL_BODYLEN] = (bodylen >> 8) & 0xff;
    frame[EAPOL_BODYLEN + 1] = bodylen & 0xff;
    frame[EAPOL_DESCTYPE] = 2;   /* RSN */
    frame[EAPOL_KEYINFO] = (key_info >> 8) & 0xff;
    frame[EAPOL_KEYINFO + 1] = key_info & 0xff;
    /* Key Length：Msg2/4 必须为 0（802.11-2016 12.7.2：仅 Msg3 携带）。
     * 此前填 16 与参考实现（put_be16(key+3, 0)）不一致，AP 侧按规范校验会判
     * Msg2 非法而丢弃——表现为空口收不到（DATA_CFM 无 acknowledged）。 */
    frame[EAPOL_KEYLEN] = 0;
    frame[EAPOL_KEYLEN + 1] = 0;
    for (int i = 0; i < 8; i++) frame[EAPOL_REPLAY + i] = (replay >> (8 * (7 - i))) & 0xff;
    if (nonce) memcpy(frame + EAPOL_NONCE, nonce, 32);
    if (mic) memcpy(frame + EAPOL_MIC, mic, 16);
    frame[EAPOL_DATALEN] = (datalen >> 8) & 0xff;
    frame[EAPOL_DATALEN + 1] = datalen & 0xff;
    if (datalen) memcpy(frame + EAPOL_DATA, data, datalen);
    return EAPOL_DATA + datalen;
}

/* ---- 4-way 握手：处理收到的 EAPOL-Key 帧 ---- */
/* 前向声明：handle_eapol（Msg3 分支）需要在发 Msg4 之前安装密钥 */
static int key_add(aic_dev_t *dev, uint8_t vif_idx, uint8_t sta_idx, int pairwise,
                   const uint8_t *key, int keylen, uint8_t key_idx, uint8_t cipher);
static void handle_eapol(wpa2_ctx_t *ctx, const uint8_t *frame, int framelen)
{
    if (framelen < EAPOL_DATA) return;
    if (frame[EAPOL_TYPE] != 3) return;
    uint16_t key_info = (frame[EAPOL_KEYINFO] << 8) | frame[EAPOL_KEYINFO + 1];
    uint16_t datalen = (frame[EAPOL_DATALEN] << 8) | frame[EAPOL_DATALEN + 1];
    /* Key Data Length 必须与真实帧长一致：datalen 是设备/AP 可控字段，
     * 不校验则后续 IE 遍历/解密会按伪造长度越界读（流氓 AP 可无线远程触发）。 */
    if (framelen < EAPOL_DATA + (int)datalen) {
        printf("[WPA2] EAPOL 帧 Key Data Length 异常（datalen=%u framelen=%d），丢弃\n",
               datalen, framelen);
        return;
    }
    const uint8_t *nonce = frame + EAPOL_NONCE;

    if ((key_info & KEY_INFO_ACK) && !(key_info & KEY_INFO_MIC)) {
        /* Msg 1/4：拿 ANonce，回 Msg 2/4 */
        if (ctx->got_msg1) return;
        ctx->got_msg1 = 1;
        memcpy(ctx->anonce, nonce, 32);
        for (int i = 0; i < 8; i++)
            ctx->replay = (ctx->replay << 8) | frame[EAPOL_REPLAY + i];
        printf("[WPA2] 收到 Msg1/4（ANonce, key_info=0x%04x）\n", key_info);
        printf("[WPA2] Msg1 全文（%d 字节）:", framelen);
        for (int i = 0; i < framelen && i < 128; i++) printf(" %02x", frame[i]);
        printf("\n");

        /* 生成 SNonce（随机）*/
        for (int i = 0; i < 32; i += 4) {
            uint32_t r = arc4random();
            memcpy(ctx->snonce + i, &r, 4);
        }
        /* PMK = PBKDF2-HMAC-SHA1(password, ssid, 4096, 32)
         * 此前整个工程漏了对 wpa2_pmk() 的调用——pmk 全零 → PTK/MIC 全错 → AP 丢 Msg2 */
        wpa2_pmk(ctx->password, ctx->ssid, ctx->pmk);
        printf("[WPA2] PMK:");
        for (int i = 0; i < 32; i++) printf(" %02x", ctx->pmk[i]);
        printf("\n");
        /* PTK = PRF-512(PMK, "Pairwise key expansion", Min/Max...) */
        uint8_t ctxdata[6 + 6 + 32 + 32];
        int p = 0;
        const uint8_t *aa = ctx->ap_mac, *sa = ctx->sta_mac;
        if (memcmp(aa, sa, 6) <= 0) { memcpy(ctxdata, aa, 6); memcpy(ctxdata + 6, sa, 6); }
        else { memcpy(ctxdata, sa, 6); memcpy(ctxdata + 6, aa, 6); }
        p = 12;
        if (memcmp(ctx->anonce, ctx->snonce, 32) <= 0) {
            memcpy(ctxdata + p, ctx->anonce, 32); memcpy(ctxdata + p + 32, ctx->snonce, 32);
        } else {
            memcpy(ctxdata + p, ctx->snonce, 32); memcpy(ctxdata + p + 32, ctx->anonce, 32);
        }
        wpa2_prf(ctx->pmk, 32, "Pairwise key expansion", ctxdata, 76, ctx->ptk, 48);
        printf("[WPA2] PTK 输入 ctxdata:");
        for (int i = 0; i < 76; i++) printf(" %02x", ctxdata[i]);
        printf("\n[WPA2] PTK 输入 pmk:");
        for (int i = 0; i < 32; i++) printf(" %02x", ctx->pmk[i]);
        printf("\n");
        printf("[WPA2] PTK 已推导\n");
        printf("[WPA2] SNonce:");
        for (int i = 0; i < 32; i++) printf(" %02x", ctx->snonce[i]);
        printf("\n[WPA2] PTK:");
        for (int i = 0; i < 48; i++) printf(" %02x", ctx->ptk[i]);
        printf("\n");

        /* Msg 2/4：key_info 标准值 = PAIRWISE|MIC|VERSION(2) = 0x010a。
         * key_data 必须带 RSN IE（22 字节）——802.11 规范 Msg2 的 Key Data 含 STA RSNE，
         * 且 MIC 覆盖含 key_data 的全帧；缺了它 AP 判无效直接丢（此前卡了两个月的根因）。 */
        uint8_t msg2[256];
        int len = build_eapol_key(msg2, KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_VERSION, ctx->replay,
                                  ctx->snonce, NULL, rsn_ie, sizeof(rsn_ie));
        uint8_t mic[16];
        wpa2_mic(ctx->ptk, msg2, len, mic);
        memcpy(msg2 + EAPOL_MIC, mic, 16);
        printf("[WPA2] Msg2 全文（%d 字节）:", len);
        for (int i = 0; i < len; i++) printf(" %02x", msg2[i]);
        printf("\n");
        if (eapol_tx(ctx->dev, ctx, msg2, len) == 0)
            printf("[WPA2] 已发 Msg2/4（SNonce+MIC）\n");
    } else if ((key_info & KEY_INFO_ACK) && (key_info & KEY_INFO_MIC) && (key_info & KEY_INFO_INSTALL)) {
        /* Msg 3/4：解 GTK，回 Msg 4/4 */
        if (ctx->got_msg3) return;
        ctx->got_msg3 = 1;
        printf("[WPA2] 收到 Msg3/4（key_info=0x%04x）\n", key_info);
        /* replay counter 以 msg3 帧里的为准（AP 可能递增，msg4 必须回显 msg3 的值）*/
        for (int i = 0; i < 8; i++)
            ctx->replay = (ctx->replay << 8) | frame[EAPOL_REPLAY + i];

        const uint8_t *kd = frame + EAPOL_DATA;
        printf("[WPA2] key_data 原文（%u 字节）:", datalen);
        for (int i = 0; i < datalen && i < 96; i++) printf(" %02x", kd[i]);
        printf("\n");

        /* Encrypted Key Data 位置位时，整段 key data 用 KEK 做 RFC 3394 解包，
         * 解开后是明文 IE 链：[RSN IE][GTK KDE]，KDE 里 GTK 是明文 16 字节。
         * aes_unwrap 自带 IV(A6*8) 神谕：KEK 错或布局错必然返回 -1。*/
        uint8_t plain[512];
        /* kdilen 的真实上界：帧内实际存在的 key data 字节数。
         * 入口已校验 framelen >= EAPOL_DATA + datalen，此处再收敛一次，
         * 保证 aes_unwrap/IE 遍历不越过帧缓冲。 */
        int kd_bound = framelen - EAPOL_DATA;
        if (kd_bound > (int)sizeof(plain)) kd_bound = (int)sizeof(plain);
        if (kd_bound < 0) kd_bound = 0;
        const uint8_t *kdi = kd;
        int kdilen = datalen > kd_bound ? kd_bound : datalen;
        if ((key_info & KEY_INFO_ENCDATA) && datalen >= 24 && datalen % 8 == 0 &&
            datalen <= (int)sizeof(plain) + 8) {
            int plen = aes_unwrap(ctx->ptk + 16, kd, datalen, plain);
            if (plen > 0) {
                printf("[WPA2] key data 整段解包成功（%d 字节，IV 校验通过 = KEK 正确）\n", plen);
                printf("[WPA2] key_data 明文:");
                for (int i = 0; i < plen && i < 96; i++) printf(" %02x", plain[i]);
                printf("\n");
                kdi = plain; kdilen = plen;
            } else {
                printf("[WPA2] ⚠️ key data 整段解包失败（IV 不匹配——KEK 错或并非整段加密，按明文解析）\n");
            }
        }

        /* 遍历 IE 链找 GTK KDE: [0xDD][len][00:0F:AC][01][keyid][GTK 16(明文)] */
        int off = 0;
        while (off + 2 <= kdilen) {
            uint8_t ie = kdi[off], ielen = kdi[off + 1];
            if (off + 2 + ielen > kdilen) {
                printf("[WPA2] IE 链截断: off=%d ie=0x%02x len=%d\n", off, ie, ielen);
                break;
            }
            printf("[WPA2] key data IE: id=0x%02x len=%d\n", ie, ielen);
            if (ie == 0xDD && ielen >= 6 &&
                kdi[off + 2] == 0x00 && kdi[off + 3] == 0x0F && kdi[off + 4] == 0xAC &&
                kdi[off + 5] == 0x01) {
                const uint8_t *body = kdi + off + 6;   /* [keyid(1)][GTK 16] */
                int bodylen = ielen - 4;
                printf("[WPA2] 找到 GTK KDE：keyid=0x%02x body=%d 字节\n", body[0], bodylen);
                if (bodylen >= 17) {
                    ctx->gtk_idx = body[0] & 0x03;
                    memcpy(ctx->gtk, body + 1, 16);
                    printf("[WPA2] GTK 已取得（key_id=%d）:", ctx->gtk_idx);
                    for (int i = 0; i < 16; i++) printf(" %02x", ctx->gtk[i]);
                    printf("\n");
                } else if (bodylen > 1 && (bodylen - 1) % 8 == 0) {
                    /* 兜底：KDE 内 GTK 单独被 wrap 的情况 */
                    uint8_t p[64];
                    int plen = aes_unwrap(ctx->ptk + 16, body + 1, bodylen - 1, p);
                    if (plen >= 16) {
                        ctx->gtk_idx = body[0] & 0x03;
                        memcpy(ctx->gtk, p + plen - 16, 16);
                        printf("[WPA2] GTK 单独解包成功（key_id=%d）\n", ctx->gtk_idx);
                    } else {
                        printf("[WPA2] ⚠️ GTK 单独解包失败\n");
                    }
                }
            }
            off += 2 + ielen;
        }
        if (ctx->gtk[0] == 0 && ctx->gtk[15] == 0)
            printf("[WPA2] GTK 未取得（全零）——装钥匙前必须解决\n");
        /* 装密钥（PTK+GTK）——必须在发 Msg4 之前！
         * 参考驱动 aic8800_wpa_install_keys 在 Msg3 处理中调用（Msg4 之前）；
         * 实测握手完成后再装 PTK，固件不再回 CFM（超时）。 */
        if (!getenv("AIC_NO_KEYADD")) {
            ctx->msg_pause = 1;
            /* 等消息线程确认已让出 0x82（它可能正阻塞在最多 1s 的 bulk_transfer 里，
             * 之前只睡 50ms 就假定让出，会把 KEY_ADD 的 CFM 吃掉导致装钥匙超时）。 */
            for (int w = 0; w < 150 && !ctx->msg_paused; w++) usleep(20000);
            ctx->msg_paused = 0;
            int k1 = key_add(ctx->dev, ctx->vif_idx, ctx->ap_idx, 1, ctx->ptk + 32, 16, 0, MAC_CIPHER_CCMP);
            printf("[WPA2] PTK 安装 status=%d\n", k1);
            int k2 = key_add(ctx->dev, ctx->vif_idx, 0xFF, 0, ctx->gtk, 16, ctx->gtk_idx, MAC_CIPHER_CCMP);
            printf("[WPA2] GTK 安装 status=%d\n", k2);
            ctx->msg_pause = 0;
        }
        /* Msg 4/4：key_info 标准值 = PAIRWISE|MIC|SECURE|VERSION(2) = 0x030a */
        uint8_t msg4[256];
        int len = build_eapol_key(msg4, KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE | KEY_INFO_VERSION,
                                  ctx->replay, NULL, NULL, NULL, 0);
        uint8_t mic[16];
        wpa2_mic(ctx->ptk, msg4, len, mic);
        memcpy(msg4 + EAPOL_MIC, mic, 16);
        if (eapol_tx(ctx->dev, ctx, msg4, len) == 0)
            printf("[WPA2] 已发 Msg4/4 —— 握手完成\n");
        ctx->handshake_done = 1;
    }
}

/* ---- 802.11 数据帧解析 ----
 * 真机 2026-11-05 验证：数据端点 0x81 的记录 = [hw_rxhdr 60][裸 802.11 帧]，
 * 没有 2B pad，固件不做 802.11→802.3 转换（此前按 802.3@62 解析是错的：
 * ethertype 正好落在 802.11 头 A2[4..5] = AP BSSID 尾部，日志里 5 帧
 * 「ethertype」全是 0x1ca4 = 某 BSSID 尾字节的巧合值，EAPOL 全漏）。
 * 长度佐证：193 = 60 + 26(802.11 QoS 头) + 8(SNAP) + 99(EAPOL Msg1)。 */
typedef struct {
    uint8_t  da[6], sa[6], bssid[6];
    uint16_t ethertype;
    const uint8_t *payload;
    int      plen;
} dot11_t;

static int dot11_parse(const uint8_t *f, int flen, dot11_t *out)
{
    if (flen < 24) return -1;
    uint16_t fc = f[0] | (f[1] << 8);
    if (((fc >> 2) & 0x3) != 2) return -1;          /* 只要 data 帧 */
    uint8_t subtype = (fc >> 4) & 0xf;
    int to_ds = (fc >> 8) & 1, from_ds = (fc >> 9) & 1;
    int hlen = 24;
    if (subtype & 0x08) hlen += 2;                   /* QoS */
    if (fc & 0x8000) hlen += 4;                      /* HT Control */
    if (to_ds && from_ds) hlen += 6;                 /* 4 地址 */
    if (flen < hlen + 8) return -1;

    memcpy(out->da, f + 4, 6);
    if (to_ds && from_ds) { memcpy(out->sa, f + 24, 6); memcpy(out->bssid, f + 16, 6); }
    else if (to_ds)       { memcpy(out->sa, f + 10, 6); memcpy(out->bssid, f + 4, 6); }
    else if (from_ds)     { memcpy(out->sa, f + 16, 6); memcpy(out->bssid, f + 10, 6); }
    else                  { memcpy(out->sa, f + 10, 6); memcpy(out->bssid, f + 16, 6); }

    const uint8_t *snap = f + hlen;
    if (!(snap[0] == 0xAA && snap[1] == 0xAA && snap[2] == 0x03)) return -2;
    out->ethertype = (snap[6] << 8) | snap[7];
    out->payload = snap + 8;
    out->plen = flen - hlen - 8;
    return 0;
}

static void hex_dump(const char *tag, const uint8_t *p, int n)
{
    printf("%s", tag);
    for (int i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}

/* A-MSDU 子帧链（QoS 控制位7 置位）：[DA6][SA6][len2 LE][MSDU 以 ethertype 开头] */
/* 未识别帧 dump 计数：封顶防日志爆炸（固件话痧时曾刷出 25GB 日志） */
static int dbg_unrec_cnt = 0;

static void handle_amsdu(wpa2_ctx_t *ctx, const uint8_t *p, int plen)
{
    int off = 0;
    while (off + 16 <= plen) {
        uint16_t slen = p[off + 12] | (p[off + 13] << 8);
        if (slen < 2 || off + 16 + slen > plen) break;
        uint16_t et = (p[off + 14] << 8) | p[off + 15];
        if (et == 0x888E) {
            printf("[数据] A-MSDU 内 EAPOL 帧（%d 字节）\n", slen - 2);
            handle_eapol(ctx, p + off + 16, slen - 2);
        } else {
            printf("[数据] A-MSDU 子帧 ethertype=0x%04x len=%d\n", et, slen - 2);
        }
        off += (16 + slen + 3) & ~3;    /* 子帧 4 字节对齐 */
    }
}

/* ---- 数据帧回调：[hw_rxhdr 60][裸 802.11 帧] ---- */
static void handle_data_frame(wpa2_ctx_t *ctx, const uint8_t *rec, int reclen)
{
    if (reclen < 60 + 24) return;
    const uint8_t *f = rec + 60;
    int flen = reclen - 60;

    /* hw_rxhdr 首字：len(bits0-15) + type(bits16-23) + mpdu_cnt(24-29) + ampdu_cnt(30-31) */
    uint32_t w0 = (uint32_t)rec[0] | ((uint32_t)rec[1] << 8) |
                  ((uint32_t)rec[2] << 16) | ((uint32_t)rec[3] << 24);
    uint16_t fc = f[0] | (f[1] << 8);
    printf("[数据] hdr: pkt_len=%u type=0x%02x mpdu=%u ampdu=%u fc=0x%04x reclen=%d\n",
           w0 & 0xffff, (w0 >> 16) & 0xff, (w0 >> 24) & 0x3f, (w0 >> 30) & 3, fc, reclen);

    dot11_t d;
    int r = dot11_parse(f, flen, &d);
    if (r == 0) {
        if (d.ethertype == 0x888E) {
            /* 802.11 头诊断：addr1=我们 / addr2=AP源 / addr3=BSSID。
             * 用于验证 Msg1 的真正来源（此前发现参考的 SM_CONNECT_IND 报
             * BSSID 末字节 a6 而 beacon 是 a4——需确认空口源到底是哪个）。 */
            printf("[数据] EAPOL 802.11 头: addr1=%02x:%02x:%02x:%02x:%02x:%02x addr2=%02x:%02x:%02x:%02x:%02x:%02x addr3=%02x:%02x:%02x:%02x:%02x:%02x seq=%u\n",
                   f[4],f[5],f[6],f[7],f[8],f[9],
                   f[10],f[11],f[12],f[13],f[14],f[15],
                   f[16],f[17],f[18],f[19],f[20],f[21],
                   (f[22] >> 4) | (f[23] << 4));
            printf("[数据] 收到 EAPOL 帧（%d 字节）\n", d.plen);
            handle_eapol(ctx, d.payload, d.plen);
            return;
        }
        printf("[数据] 802.11 数据帧 ethertype=0x%04x len=%d\n", d.ethertype, d.plen);
        if ((((fc >> 4) & 0xf) & 0x08) && (f[24] & 0x80))
            handle_amsdu(ctx, d.payload, d.plen);   /* A-MSDU 聚合 */
        return;
    }
    if (r == -2) {
        /* 802.11 头合法但 SNAP 不匹配：管理帧/加密帧/聚合帧——dump 定位 */
        if (dbg_unrec_cnt < 20) {
            hex_dump("[数据] 非 SNAP 帧 dump:", f, flen < 48 ? flen : 48);
        } else if (dbg_unrec_cnt == 20) {
            printf("[数据] 帧 dump 已达 20 条上限，后续静默\n");
        }
        dbg_unrec_cnt++;
        return;
    }
    /* 兜底：万一某些帧固件确实转了 802.3，按旧偏移再试一次 */
    if (reclen >= 62 + 14) {
        const uint8_t *eth = rec + 62;
        uint16_t et = (eth[12] << 8) | eth[13];
        if (et == 0x888E) {
            printf("[数据] 收到 EAPOL 帧（802.3 通路，%d 字节）\n", reclen - 62 - 14);
            handle_eapol(ctx, eth + 14, reclen - 62 - 14);
            return;
        }
    }
    if (dbg_unrec_cnt < 20) {
        hex_dump("[数据] 未识别帧 dump:", f, flen < 48 ? flen : 48);
    } else if (dbg_unrec_cnt == 20) {
        printf("[数据] 未识别帧 dump 已达 20 条上限，后续静默\n");
    }
    dbg_unrec_cnt++;
}

/* ---- 消息端点线程（0x82）：SM_CONNECT_IND 等 ---- */
/* SCANU_RESULT_IND(0x1004) 到达标志：显式扫描完成的判据 */
static volatile int scan_result_seen = 0;
static void *msg_thread_fn(void *arg)
{
    wpa2_ctx_t *ctx = arg;
    uint8_t buf[4096];
    int consec_err = 0;
    while (ctx->threads_running) {
        int xfer = 0;
        if (ctx->msg_pause) {
            /* 进入暂停分支时确认一次（整个暂停期间保持），主线程据此判定
             * 端点已让出，再发 key_add 等同步消息。 */
            if (!ctx->msg_paused) ctx->msg_paused = 1;
            usleep(20000); continue;
        }
        int rc = libusb_bulk_transfer(ctx->dev->h, 0x82, buf, sizeof(buf), &xfer, 1000);
        if (rc == LIBUSB_ERROR_TIMEOUT) { consec_err = 0; continue; }
        if (rc < 0) {
            if (++consec_err >= 20) {
                printf("[MSG] 连续错误 %d 次，停止线程（设备可能已掉线）\n", consec_err);
                ctx->threads_running = 0;
                break;
            }
            continue;
        }
        consec_err = 0;
        if (xfer >= 4) {
            uint8_t mtype = buf[2] & 0x7f;
            if (mtype != 0x11) {
                /* 非 CMD_RSP 消息。DATA_CFM(0x12) = 固件确认已处理我们发出的帧——
                 * TX 路径是否被固件接受的铁证。0x13=PRINT(固件日志) */
                printf("[MSG] type=0x%02x pkt_len=%d xfer=%d:", mtype,
                       buf[0] | (buf[1] << 8), xfer);
                for (int i = 0; i < xfer && i < 24; i++) printf(" %02x", buf[i]);
                printf("\n");
            }
        }
        if (xfer >= 16 && (buf[2] & 0x7f) == 0x11) {
            uint16_t id = buf[4] | (buf[5] << 8);
            if (getenv("AIC_MSGDUMP")) { printf("[MSGRX] id=0x%04x xfer=%d\n", id, xfer); fflush(stdout); }
            if (id == SCANU_RESULT_IND) {
                scan_result_seen = 1;
                printf("[scan] 收到 SCANU_RESULT_IND（扫描结果）\n");
                fflush(stdout);
            }
            if (id == SM_CONNECT_IND) {
                /* IND 至少要有 20 字节头（status/ap_mac/idx/两个 ie_len）。
                 * 之前的 xfer>=16 放行了 16..19 字节的帧导致越界读。 */
                if (xfer < 20 + 16) {
                    printf("[WPA2] SM_CONNECT_IND 长度异常（xfer=%d），丢弃\n", xfer);
                    continue;
                }
                const uint8_t *p = buf + 16;
                uint16_t status_code = p[0] | (p[1] << 8);
                uint16_t req_ie_len = p[14] | (p[15] << 8);
                uint16_t rsp_ie_len = p[16] | (p[17] << 8);
                memcpy(ctx->ap_mac, p + 2, 6);
                ctx->ap_idx = p[10];
                printf("[WPA2] IND param[0..15]:");
                for (int i = 0; i < 16; i++) printf(" %02x", p[i]);
                printf("\n");
                printf("[WPA2] SM_CONNECT_IND: status=%u AP=%02x:%02x:%02x:%02x:%02x:%02x sta_idx=%d ch_idx=%d qos=%d\n",
                       status_code, p[2], p[3], p[4], p[5], p[6], p[7], p[10], p[11], p[12]);
                printf("[WPA2] assoc_req_ie_len=%u assoc_rsp_ie_len=%u\n", req_ie_len, rsp_ie_len);
                /* 打印关联请求/响应 IE 原文（定位 AP 拒绝原因）*/
                const uint8_t *ie = p + 20;   /* assoc_ie_buf 在偏移 20（4字节对齐后）*/
                /* IE dump 上界取 min(上报长度, 真实可用字节数)：req_ie_len/rsp_ie_len
                 * 是设备可控字段，不收敛会越界读 buf 外内存。 */
                int avail = xfer - 16 - 20;   /* p 之后可用的字节 */
                if (avail < 0) avail = 0;
                int dump_req = req_ie_len > 200 ? 200 : req_ie_len;
                int dump_rsp = rsp_ie_len > 200 ? 200 : rsp_ie_len;
                if (dump_req > avail) dump_req = avail;
                if (dump_req + dump_rsp > avail) dump_rsp = avail - dump_req;
                if (dump_rsp < 0) dump_rsp = 0;
                printf("[WPA2] 关联请求 IE（前 %d 字节）:", dump_req);
                for (int i = 0; i < dump_req; i++) printf(" %02x", ie[i]);
                printf("\n");
                if (rsp_ie_len > 0) {
                    printf("[WPA2] 关联响应 IE（前 %d 字节）:", dump_rsp);
                    for (int i = 0; i < dump_rsp; i++) printf(" %02x", ie[req_ie_len + i]);
                    printf("\n");
                }
                if (status_code == 0) {
                    printf("[WPA2] ✅ 已关联，等待 EAPOL 握手\n");
                } else {
                    printf("[WPA2] ❌ 关联失败 status=%u\n", status_code);
                    ctx->threads_running = 0;
                }
            }
        }
    }
    return NULL;
}

/* ---- 数据端点线程（0x81）：EAPOL + 数据帧 ---- */
static void *data_thread_fn(void *arg)
{
    wpa2_ctx_t *ctx = arg;
    uint8_t buf[4096];
    int consec_err = 0;
    /* AIC_EPDUMP=1 才打印端点记录（默认关：固件话痧时会把磁盘刷爆） */
    static int ep_dump = -1, ep_dump_cnt = 0;
    if (ep_dump < 0) ep_dump = getenv("AIC_EPDUMP") ? 1 : 0;
    while (ctx->threads_running) {
        int xfer = 0;
        int rc = libusb_bulk_transfer(ctx->dev->h, 0x81, buf, sizeof(buf), &xfer, 1000);
        if (rc == LIBUSB_ERROR_TIMEOUT) { consec_err = 0; continue; }
        if (rc < 0) {
            /* 错误熔断：设备掉线时 libusb 会疯狂报错（曾刷出 24GB 日志），
             * 连续 20 次错误即停线程并通知主循环退出。 */
            if (++consec_err >= 20) {
                printf("[数据EP] 连续错误 %d 次，停止线程（设备可能已掉线）\n", consec_err);
                ctx->threads_running = 0;
                break;
            }
            continue;
        }
        consec_err = 0;
        /* 别再按 64 字节下限丢包：DATA_CFM 只有 12 字节（固件的 TX 确认），
         * 曾因 xfer<64 被静默丢弃，导致整个 TX 诊断盲飞 */
        if (xfer >= 4) {
            uint8_t t = buf[2] & 0x7f;
            if (t != 0x00) {
                /* 端点 dump 必须显式开（AIC_EPDUMP=1）：此前无条件打印，
                 * 固件话痧状态下一分钟能刷出几十 GB 日志打满磁盘。 */
                if (ep_dump) {
                    if (ep_dump_cnt < 200) {
                        printf("[数据EP] 记录 type=0x%02x pkt_len=%d xfer=%d:", t,
                               buf[0] | (buf[1] << 8), xfer);
                        for (int i = 0; i < xfer && i < 24; i++) printf(" %02x", buf[i]);
                        printf("\n");
                    } else if (ep_dump_cnt == 200) {
                        printf("[数据EP] dump 已达 200 条上限，后续静默（防日志爆炸）\n");
                    }
                    ep_dump_cnt++;
                }
                if ((t & 0x10) == 0x10) continue;   /* 配置类记录（CFM/PRINT）*/
            }
        }
        if (xfer < 60 + 24) continue;
        /* 记录起始即 hw_rxhdr；首 u32: len(16)+type(8)+... */
        uint16_t pkt_len = buf[0] | (buf[1] << 8);
        uint8_t type = buf[2];
        if ((type & 0x10) == 0x10) {
            /* 配置类记录也可能混在数据端点上来（驱动的 0x81 处理器同样解析
             * CMD_RSP/DATA_CFM）。此前直接丢弃 = 把固件的 TX 确认扔了——盲点。 */
            if (ep_dump) {
                if (ep_dump_cnt < 200) {
                    printf("[数据EP] 配置记录 type=0x%02x pkt_len=%d xfer=%d:", type, pkt_len, xfer);
                    for (int i = 0; i < xfer && i < 24; i++) printf(" %02x", buf[i]);
                    printf("\n");
                }
                ep_dump_cnt++;
            }
            continue;
        }
        (void)pkt_len;
        handle_data_frame(ctx, buf, xfer);
    }
    return NULL;
}

/* ---- 安装密钥（MM_KEY_ADD_REQ）---- */
static int key_add_tmo(aic_dev_t *dev, uint8_t vif_idx, uint8_t sta_idx, int pairwise,
                   const uint8_t *key, int keylen, uint8_t key_idx, uint8_t cipher, int tmo_ms)
{
    /* 参数布局与参考驱动实发逐字节一致（44 字节）：
     * [0-3]=00 00 00 00  [4-7]=key_len(u32 LE)  [8-39]=key[32]（前 key_len 有效）
     * [40]=cipher(02=CCMP)  [41-42]=00  [43]=pairwise(1/0)
     * 此前用另一套布局（key_idx/sta_idx/keylen 前置）发 39 字节，固件解析错位
     * 直接掉线（错误刷屏）。key_idx 通过 sta_idx 传入路径由调用方处理。 */
    uint8_t param[44];
    memset(param, 0, sizeof(param));
    uint32_t klen = (uint32_t)keylen;
    memcpy(param + 4, &klen, 4);
    if (keylen > 32) keylen = 32;
    memcpy(param + 8, key, keylen);
    param[40] = cipher;
    param[43] = pairwise ? 1 : 0;
    (void)key_idx; (void)vif_idx; (void)sta_idx;
    if (lmac_send(dev, TASK_MM, MM_KEY_ADD_REQ, param, sizeof(param)) < 0) return -1;
    uint8_t cfm[64] = {0};
    int n = wait_cfm(dev, MM_KEY_ADD_CFM, tmo_ms, 8, cfm, sizeof(cfm));
    return n >= 0 ? cfm[0] : -1;
}
static int key_add(aic_dev_t *dev, uint8_t vif_idx, uint8_t sta_idx, int pairwise,
                   const uint8_t *key, int keylen, uint8_t key_idx, uint8_t cipher)
{
    int tmo = 500;   /* 默认 500ms：AP 的四路握手超时约 1s，等待太久会拖到
                      * AP 放弃（SM_DISCONNECT_IND reason=15）；参考实现的 CFM 是毫秒级 */
    const char *t = getenv("AIC_KEYADD_TIMEOUT");
    if (t) tmo = atoi(t);
    return key_add_tmo(dev, vif_idx, sta_idx, pairwise, key, keylen, key_idx, cipher, tmo);
}

/* ---- cmd_connect：完整连接流程 ---- */
static int cmd_connect(const char *ssid, const char *password)
{
    aic_dev_t dev = {0};
    if (open_wifi(&dev) < 0) return 1;

    wpa2_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.dev = &dev;
    /* STA MAC：来自 efuse（init 时已读入 g_sta_mac）；AIC_NO_REINIT 跳过初始化
     * 时这里补读一次。 */
    if (g_sta_mac[0] == 0 && g_sta_mac[1] == 0 && g_sta_mac[2] == 0) {
        printf("[MAC] 初始化被跳过，补读 efuse MAC ...\n");
        read_sta_mac(&dev);
    }
    memcpy(ctx.sta_mac, g_sta_mac, 6);
    strncpy(ctx.ssid, ssid, sizeof(ctx.ssid) - 1);
    strncpy(ctx.password, password, sizeof(ctx.password) - 1);
    pthread_mutex_init(&ctx.lock, NULL);

    /* AIC_NO_REINIT=1：跳过全量初始化（设备已在 8d81 运行态时）。
     * 参考实现的 connect 只发 SM_CONNECT_REQ 不重初始化；我们的每次 connect
     * 都全量重初始化（STACK_START→RESET→...），实测会重新触发固件后台扫描，
     * 导致关联后 TX 撞扫描发不出（DATA_CFM tx_done=1 但 acknowledged=0）。
     * 用法：第一次带初始化跑（握手会失败），第二次 AIC_NO_REINIT=1 再连。 */
    /* 数据 RX 线程提前到初始化之前启动（AIC_EARLY_RX=1，默认开）：
     * 参考驱动在 fdrv_probe 里就排队 20 个异步 RX URB。我们的 RX 线程原先在
     * 初始化之后才启动——初始化期间（尤其 MM_START 之后）固件持续下发 beacon，
     * 数据端点 0x81 无消费者会积压，可能堵死固件 TX 流控/credit，表现为
     * 主机 TX 帧 DATA_CFM tx_done=1 但 acknowledged=0（空口零辐射）。
     * 消息端点线程仍等在初始化之后（避免抢 CFM）。 */
    int early_rx = getenv("AIC_EARLY_RX") ? atoi(getenv("AIC_EARLY_RX")) : 1;
    if (early_rx) {
        ctx.threads_running = 1;
        if (pthread_create(&ctx.data_thread, NULL, data_thread_fn, &ctx) == 0)
            ctx.data_started = 1;
        else
            printf("[RX] 数据线程创建失败（不影响后续流程）\n");
        printf("[RX] 数据端点消费线程已提前启动\n");
    }

    int vif;
    if (getenv("AIC_NO_REINIT")) {
        printf("=== 跳过初始化（AIC_NO_REINIT）===\n");
        vif = 0;
        ctx.vif_idx = 0;
    } else {
        vif = wifi_full_init(&dev);
        if (vif < 0) {
            /* 必须 join 已启动的线程再返回：ctx/dev 都是本函数栈变量，
             * 线程循环里还有最多 1s 的 bulk_transfer，直接返回=栈帧 UAF。 */
            ctx.threads_running = 0;
            if (ctx.data_started) pthread_join(ctx.data_thread, NULL);
            libusb_close(dev.h);
            return 1;
        }
        ctx.vif_idx = vif;
    }

    /* AIC_FWDEBUG=1：打开固件全量日志（PRINT 消息 type 0x13，消息线程已记录）——
     * 拿固件内部决策的地面真相（比如为什么丢主机发的 TX 帧）*/
    if (getenv("AIC_FWDEBUG")) {
        uint32_t sev = 0x0F, mod = 0xFFFFFFFF;   /* ERR|INFO|TRACE|DEBUG + 全模块 */
        printf("[DBG] 打开固件全量日志\n");
        lmac_send(&dev, TASK_DBG, DBG_SET_SEV_FILTER_REQ, (uint8_t *)&sev, 4);
        usleep(100000);
        lmac_send(&dev, TASK_DBG, DBG_SET_MOD_FILTER_REQ, (uint8_t *)&mod, 4);
        usleep(100000);
    }

    /* SCANU_START_REQ：SM_CONNECT 前先显式全量扫描并等其完成。
     * 参考驱动的后台扫描线程（aic8800_sta_scan_thread，间隔 10s）在 connect
     * 前已完成一次扫描；我们的工具此前直接 SM_CONNECT，固件关联后内部扫描
     * 与握手并发导致 TX 不被 ACK（DATA_CFM tx_done=1、acknowledged=0）。
     * 等 SCANU_RESULT_IND 到达或超时即认为扫描完成。 */
    if (!getenv("AIC_NO_SCANU")) {
        int sdelay = 15;
        const char *sd = getenv("AIC_SCANU_DELAY");
        if (sd) sdelay = atoi(sd);
        if (sdelay > 0) {
            printf("[scan] 等 %ds（对齐参考后台扫描线程的时序）...\n", sdelay);
            fflush(stdout);
            sleep(sdelay);
        }
        printf("[scan] 发送 SCANU_START_REQ（%zu 字节，39 频道全量扫描）...\n", sizeof(scanu_req_param));
        fflush(stdout);
        lmac_send(&dev, TASK_SCANU, SCANU_START_REQ, (uint8_t *)scanu_req_param, sizeof(scanu_req_param));
        /* 等扫描完成：消息线程此时尚未启动（在线程创建前），必须用同步
         * lmac_recv 消费 0x82 上的 SCANU CFM(0x1009)/RESULT_IND(0x1004)，
         * 否则这些消息会滞留端点、干扰后续 SM_CONNECT_IND 的同步接收。 */
        /* 39 频道扫描约 4-20s，期间固件持续推 SCANU_RESULT_IND（实测 60+ 条）。
         * 必须排空到静默（连续 3 次 200ms 超时）才算扫描真正结束，
         * 否则积压消息会堵死后续 SM_CONNECT_IND 的同步接收。 */
        int quiet = 0, drained = 0;
        int nodrain = getenv("AIC_SCANU_NODRAIN") != NULL;
        if (getenv("AIC_SCANU_SLEEPONLY")) {
            /* 完全不消费 0x82：让固件的扫描结果自然堆积（与参考驱动 RX 线程
             * 持续消费的行为区分开），只按固定时长等待后直接连接。 */
            int sl = 5;
            const char *sv = getenv("AIC_SCANU_SLEEPONLY");
            if (*sv) sl = atoi(sv);
            printf("[scan] 只等 %ds 不消费消息（扫描仍在跑）...\n", sl);
            sleep(sl);
            scan_result_seen = 1;
            printf("[scan] 等待结束，直接连接\n");
            goto scanu_done;
        }
        int maxiter = nodrain ? 10 : 300;   /* nodrain: 只消费 2s，扫描仍在跑就连 */
        for (int i = 0; i < maxiter && quiet < 3; i++) {
            uint16_t id = 0; uint8_t p[512] = {0};
            int n = lmac_recv(&dev, 200, &id, p, sizeof(p));
            if (n >= 4) {
                drained++;
                quiet = 0;
                if (id == SCANU_RESULT_IND) {
                    scan_result_seen = 1;
                    /* scanu_result_ind: length(2)+framectrl(2)+freq(2)+band(1)+
                     * sta_idx(1)+inst_nbr(1)+rssi(1)=10 字节头，之后是 802.11 管理帧：
                     * FC(2)+dur(2)+da(6)+sa(6)+bssid(6)+seq(2)+ts(8)+interval(2)+cap(2)
                     * =36，BSSID 在 payload+16，IE 链在 payload+36。 */
                    if (n >= 46) {
                        printf("[scan] 结果 BSSID=%02x:%02x:%02x:%02x:%02x:%02x freq=%u",
                               p[12+16], p[12+17], p[12+18], p[12+19], p[12+20], p[12+21],
                               p[4] | (p[5] << 8));
                        for (int off = 12 + 36; off + 2 <= n; ) {
                            uint8_t eid = p[off], elen = p[off+1];
                            if (off + 2 + elen > n) break;
                            if (eid == 0 && elen > 0 && elen <= 32) {
                                printf(" ssid=\"");
                                for (int q = 0; q < elen; q++) {
                                    uint8_t c = p[off+2+q];
                                    putchar((c >= 0x20 && c <= 0x7e) ? c : '.');
                                }
                                printf("\"");
                                break;
                            }
                            off += 2 + elen;
                        }
                        printf("\n"); fflush(stdout);
                    }
                }
                if (getenv("AIC_MSGDUMP") && drained <= 3) { printf("[scan] RX id=0x%04x n=%d\n", id, n); fflush(stdout); }
            } else {
                quiet++;
            }
        }
        if (getenv("AIC_MSGDUMP")) { printf("[scan] 排空 %d 条消息\n", drained); fflush(stdout); }
        printf("[scan] 扫描%s\n", scan_result_seen ? "完成（收到 RESULT_IND）" : "等待超时（继续连接）");
        fflush(stdout);
    }
    scanu_done: ;
    /* SM_CONNECT_REQ */
    struct sm_connect_req req;
    memset(&req, 0, sizeof(req));
    size_t slen = strlen(ssid);
    if (slen > 32) slen = 32;
    memcpy(req.ssid.array, ssid, slen);
    req.ssid.length = (uint8_t)slen;
    memset(req.bssid, 0xff, 6);
    req.chan.freq = 0xffff;
    /* AIC_BSSID/AIC_FREQ：显式指定 AP 与信道，固件不必扫描找 AP。
     * 例：AIC_BSSID=aa:bb:cc:dd:ee:ff AIC_FREQ=2412 */
    {
        const char *b = getenv("AIC_BSSID");
        const char *f = getenv("AIC_FREQ");
        if (b && strlen(b) >= 17) {
            unsigned v[6];
            if (sscanf(b, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) {
                for (int i = 0; i < 6; i++) req.bssid[i] = (uint8_t)v[i];
                printf("[WPA2] 显式 BSSID=%s\n", b);
            }
        }
        if (f) { int fq = atoi(f); if (fq > 0) { req.chan.freq = (uint16_t)fq; printf("[WPA2] 显式 freq=%d\n", fq); } }
    }
    int secured = password && password[0];
    /* flags 对照用户态参考驱动（aic8800-offensive-userspace-driver rwnx_send_sm_connect_req）：
     * CONTROL_PORT_HOST | CONTROL_PORT_NO_ENC | WPA_WPA2_IN_USE = 0x0B。
     * 缺 CONTROL_PORT_NO_ENC(0x02) 是 Msg2 被固件静默丢弃的根因——固件在
     * 控制端口认为该帧需加密但握手期无钥匙，丢弃且不回 DATA_CFM。 */
    req.flags = CONN_FLAG_CONTROL_PORT_HOST | CONN_FLAG_CONTROL_PORT_NO_ENC |
                (secured ? CONN_FLAG_WPA_WPA2_IN_USE : 0);
    /* ctrl_port_ethertype：与 Linux 驱动/参考实现一致——cpu_to_be16(ETH_P_PAE)，
     * LE 机 u16 值 0x8E88（内存字节 88 8E）。rwnx_tx.c 判 EAPOL 的判据就是
     * ethertype == 0x8e88，固件按同一约定与入站帧比对决定控制端口直通。 */
    req.ctrl_port_ethertype = (uint16_t)(((0x888e >> 8) & 0xff) | ((0x888e << 8) & 0xff00));
    req.listen_interval = 10;
    req.auth_type = 0;
    req.vif_idx = (uint8_t)vif;

    /* RSN IE（WPA2-PSK/CCMP）——固件自己只发 WMM，WPA2 AP 没有 RSN IE 拒关联。
     * 驱动的 ie_buf 就是给 wpa_supplicant 的关联 IEEs 用的，固件会附加。
     * 用文件级常量（与 Msg2 key_data 同一份）。 */
    if (secured) {
        memcpy(req.ie_buf, rsn_ie, sizeof(rsn_ie));
        req.ie_len = sizeof(rsn_ie);
    } else {
        req.ie_len = 0;
    }

    printf("连接 \"%s\"（%s）...\n", ssid, secured ? "WPA2-PSK" : "开放");
    /* 固件 boot 后自带后台扫描周期：扫描期间固件离AP信道，TX 发不出去
     * （DATA_CFM tx_done=1 但 acknowledged=0，AP 重传 Msg1）。参考驱动
     * 连接前固定 sleep 20s 避开。AIC_PRECONNECT_SLEEP 可调（秒）。 */
    {
        const char *s = getenv("AIC_PRECONNECT_SLEEP");
        int wait = s ? atoi(s) : 20;
        if (wait > 0) { printf("[WPA2] 等待 %ds 避开固件扫描周期...\n", wait); sleep(wait); }
    }
    /* 连接重试：我们的固件 boot 后后台扫描周期很长，单次连接经常撞扫描
     * （SM_CONNECT_IND status=1、ie_len=0）。参考驱动的成功路径实测就是
     * "失败一次 → 等 25s → 再连"（ourfw 判决实验：单连 3/3 全挂，二连必成）。
     * AIC_CONNECT_RETRIES 控制次数（默认 3），AIC_RETRY_WAIT 控制间隔（默认 12s），
     * AIC_PRECONNECT_SLEEP=0 可跳过连接前等待。 */
    {
        int retries = getenv("AIC_CONNECT_RETRIES") ? atoi(getenv("AIC_CONNECT_RETRIES")) : 3;
        int rwait   = getenv("AIC_RETRY_WAIT") ? atoi(getenv("AIC_RETRY_WAIT")) : 12;
        /* AIC_BOGUS_FIRST=1：先连一个不存在的 SSID（必然失败）再连真的。
         * 复现参考驱动的成功路径（ourfw 判决实验：失败首连+二次连接=握手成功）；
         * 失败的尝试会让固件停掉 boot 后的后台扫描，TX 随后才能真正上线。 */
        if (getenv("AIC_BOGUS_FIRST")) {
            struct sm_connect_req bogus = req;
            bogus.ssid.length = 7;
            memcpy(bogus.ssid.array, "NOSUCHN", 7);
            printf("[WPA2] 先连 bogus SSID 触发一次失败（停固件扫描）...\n");
            lmac_send(&dev, TASK_SM, SM_CONNECT_REQ, (uint8_t *)&bogus, sizeof(bogus));
            sleep(3);
            for (int t = 0; t < 40; t++) {
                uint16_t id = 0; uint8_t p[64] = {0};
                /* p[0..11] 全会被读（status/ap_mac/ap_idx/vif_idx），长度必须 >=12 */
                if (lmac_recv(&dev, 200, &id, p, sizeof(p)) >= 12 && id == SM_CONNECT_IND) {
                    printf("[WPA2] bogus 连接 status=%u（预期非0）\n", p[0] | (p[1] << 8));
                    break;
                }
            }
            sleep(rwait);
        }
        for (int attempt = 0; ; attempt++) {
            if (attempt > 0) {
                printf("[WPA2] 第 %d 次连接尝试（等 %ds）...\n", attempt + 1, rwait);
                sleep(rwait);
            }
            if (lmac_send(&dev, TASK_SM, SM_CONNECT_REQ, (uint8_t *)&req, sizeof(req)) < 0) {
                libusb_close(dev.h); return 1;
            }
            int got = 0;
            for (int t = 0; t < 60 && !got; t++) {
                uint16_t id = 0; uint8_t p[64] = {0};
                int n = lmac_recv(&dev, 200, &id, p, sizeof(p));
                if (n >= 4 && id == SM_CONNECT_IND) {
                    uint16_t st = p[0] | (p[1] << 8);
                    memcpy(ctx.ap_mac, p + 2, 6);
                    ctx.vif_idx = p[9];
                    ctx.ap_idx  = p[10];
                    printf("[WPA2] 连接尝试 %d: SM_CONNECT_IND status=%u ap_idx=%u ch_idx=%u\n",
                           attempt + 1, st, p[10], p[11]);
                    got = 1;
                    if (st == 0) break;
                }
            }
            if (got && ctx.ap_mac[0]) break;
            if (attempt >= retries) {
                printf("[WPA2] ❌ %d 次连接均失败\n", attempt + 1);
                libusb_close(dev.h); return 1;
            }
        }
    }

    /* 启动消息 RX 线程（数据线程可能已提前启动）*/
    if (!early_rx) ctx.threads_running = 1;
    if (pthread_create(&ctx.msg_thread, NULL, msg_thread_fn, &ctx) == 0)
        ctx.msg_started = 1;
    if (!early_rx) {
        if (pthread_create(&ctx.data_thread, NULL, data_thread_fn, &ctx) == 0)
            ctx.data_started = 1;
    }

    /* AIC_TXTEST=1：TX 端点探针——关联后经数据端点注入一个 802.11 deauth 帧
     * （mgmt 风格 hostdesc：flags=TXU_CNTRL_MGMT, staid=0xff, tid=0xff,
     * status=0x40000000，即参考驱动验证可用的注入路径）。
     * 若观察到 AP 回 deauth / SM_DISCONNECT_IND / DATA_CFM → 固件数据 TX 端点通，
     * 问题在 EAPOL/AP 侧；若无任何反应 → 数据端点 TX 本身就是死的。 */
    if (getenv("AIC_TXTEST")) {
        usleep(2500000);   /* 等 SM_CONNECT_IND */
        const char *eps = getenv("AIC_TXTEST_EP");
        uint8_t tstep = eps ? (uint8_t)atoi(eps) : 0x01;
        printf("[TXTEST] 注入 deauth 帧（经 0x%02x，mgmt 风格）...\n", tstep);
        uint8_t deauth[26] = {0};
        deauth[0] = 0xC0; deauth[1] = 0x00;          /* FC = deauth */
        memcpy(deauth + 4, ctx.ap_mac, 6);           /* A1 = AP */
        memcpy(deauth + 10, ctx.sta_mac, 6);         /* A2 = 我们 */
        memcpy(deauth + 16, ctx.ap_mac, 6);          /* A3 = BSSID */
        deauth[24] = 0x01;                           /* reason = 1 */
        struct hostdesc hd;
        memset(&hd, 0, sizeof(hd));
        hd.packet_len = sizeof(deauth);
        hd.status_desc_addr = 0x40000000u;           /* MGMT_CFM */
        memcpy(hd.eth_dest_addr, ctx.ap_mac, 6);
        memcpy(hd.eth_src_addr, ctx.sta_mac, 6);
        hd.ethertype = 0;
        hd.ac = 1; hd.tid = 0xFF; hd.vif_idx = ctx.vif_idx; hd.staid = 0xFF;
        hd.flags = 0x0008;                           /* TXU_CNTRL_MGMT = BIT(3)，编译驱动 rwnx_tx.h 验证 */
        uint16_t blen = 4 + sizeof(hd) + sizeof(deauth);
        uint8_t *b = calloc(1, blen + 8);
        b[0] = blen & 0xff; b[1] = (blen >> 8) & 0x0f; b[2] = 0x01; b[3] = 0;
        memcpy(b + 4, &hd, sizeof(hd));
        memcpy(b + 4 + sizeof(hd), deauth, sizeof(deauth));
        int xf = 0;
        int rc = libusb_bulk_transfer(dev.h, tstep, b, blen, &xf, 5000);
        printf("[TXTEST] deauth 注入 rc=%d xfer=%d/%d，观察 6 秒...\n", rc, xf, blen);
        free(b);
        for (int i = 0; i < 30; i++) usleep(200000);
        ctx.threads_running = 0;
        pthread_join(ctx.msg_thread, NULL);
        pthread_join(ctx.data_thread, NULL);
        libusb_close(dev.h);
        return 0;
    }

    /* 等握手完成（最多 20 秒）*/
    int waited = 0;
    while (waited < 100 && ctx.threads_running) {
        usleep(200000);
        waited++;
        if (ctx.handshake_done) break;
    }

    if (ctx.handshake_done) {
        /* 密钥已在 Msg3 处理中安装（参考时序：Msg4 之前），此处只报告。 */
        printf("[WPA2] 密钥安装情况见上（PTK/GTK 在 Msg4 前已装）\n");
        printf("✅ WPA2 连接建立完成！\n");
        printf("（数据通路已验证到「收到数据帧」级别，utun 注入是下一步）\n");
        /* 再观察 5 秒数据流 */
        for (int i = 0; i < 25; i++) usleep(200000);
    } else {
        printf("❌ 握手未完成（got_msg1=%d got_msg3=%d）\n", ctx.got_msg1, ctx.got_msg3);
    }

    ctx.threads_running = 0;
    if (ctx.msg_started)  pthread_join(ctx.msg_thread, NULL);
    if (ctx.data_started) pthread_join(ctx.data_thread, NULL);
    libusb_close(dev.h);
    return ctx.handshake_done ? 0 : 1;
}

/* ================================================================ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("用法: %s <mode-switch|status|reg-read|reg-write>\n", argv[0]);
        printf("  mode-switch                 1111:1111 -> a69c:8d80\n");
        printf("  status                      设备状态 + 芯片 ID\n");
        printf("  reg-read <hexaddr>          读寄存器\n");
        printf("  reg-write <hexaddr> <hex>   写寄存器\n");
        printf("  fw-upload <dir>              完整固件下载（阶段1->2）\n");
        printf("  dump                         打印全部接口和端点\n");
        printf("  wifi-test                    WiFi运行态消息端点实测\n");
        printf("  wifi-start                   MM_START + MM_ADD_IF（建立 STA 接口）\n");
        printf("  scan [秒]                    扫描 2.4G WiFi 网络（默认 8 秒）\n");
        printf("  connect <SSID> [密码]        连接网络\n");
        return 1;
    }
    int rc = libusb_init(NULL);
    if (rc < 0) { fprintf(stderr, "libusb_init 失败\n"); return 1; }
    libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_ERROR);

    int ret = 1;
    if (!strcmp(argv[1], "mode-switch"))       ret = cmd_mode_switch();
    else if (!strcmp(argv[1], "status"))       ret = cmd_status();
    else if (!strcmp(argv[1], "reg-read") && argc >= 3)  ret = cmd_reg_read(argv[2]);
    else if (!strcmp(argv[1], "reg-write") && argc >= 4) ret = cmd_reg_write(argv[2], argv[3]);
    else if (!strcmp(argv[1], "fw-upload") && argc >= 3) ret = cmd_fw_upload(argv[2]);
    else if (!strcmp(argv[1], "dump"))       ret = cmd_dump();
    else if (!strcmp(argv[1], "wifi-test"))  ret = cmd_wifi_test();
    else if (!strcmp(argv[1], "wifi-start")) ret = cmd_wifi_start();
    else if (!strcmp(argv[1], "scan"))       ret = cmd_scan(argc >= 3 ? atoi(argv[2]) : 8);
    else if (!strcmp(argv[1], "connect") && argc >= 3) {
        /* 密码优先取 argv[3]；缺省时回退到 AIC_PASS 环境变量——GUI app 用
         * 环境变量传密可避免密码出现在进程命令行（ps 可见）。 */
        const char *pw = (argc >= 4 && argv[3][0]) ? argv[3] : getenv("AIC_PASS");
        ret = cmd_connect(argv[2], pw ? pw : "");
    }
    else printf("未知子命令或缺参数\n");

    libusb_exit(NULL);
    return ret;
}
