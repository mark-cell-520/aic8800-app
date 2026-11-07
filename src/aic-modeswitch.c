/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 HeartFlow (mark-cell-520)
 */
/*
 * aic-modeswitch.c — AIC8800D80/M80 USB WiFi 网卡 macOS 模式切换工具
 *
 * 原理：设备出厂是 1111:1111 虚拟光驱（Windows 驱动盘）。
 * 向大容量存储接口的 BOT 批量端点发送厂商特定 SCSI CDB：
 *     FD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 F2
 * 设备收到后重枚举为 a69c:8d80（Boot ROM），随后由固件加载器上传固件。
 *
 * 协议来源：olamellberg/AIC8800D80 逆向工程（对 Usb_Driver.dll 的分析）
 *   Set_CS1_0() -> IOCTL_SCSI_PASS_THROUGH -> 16 字节 CDB，FD...F2
 *   Linux 等价实现：sg_raw /dev/sgX fd 00 ... f2（树莓派实测成功）
 *
 * 编译：见 build.sh
 * 用法：./aic-modeswitch            （自动找 1111:1111 并切换）
 *       ./aic-modeswitch --status   （只打印设备信息和端点，不切换）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>

#define AIC_VID           0x1111
#define AIC_PID           0x1111

/* BOT (Bulk-Only Transport) CBW：USBC 签名 + tag + 长度 + 标志 + LUN + CB长度 + CDB */
static const unsigned char CDB[16] = {
    0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF2
};

static void print_hex(const char *label, const unsigned char *buf, int len)
{
    printf("%s", label);
    for (int i = 0; i < len; i++)
        printf("%02x ", buf[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    int status_only = (argc > 1 && strcmp(argv[1], "--status") == 0);
    int rc;

    rc = libusb_init(NULL);
    if (rc < 0) {
        fprintf(stderr, "libusb_init 失败: %s\n", libusb_error_name(rc));
        return 1;
    }
    libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_WARNING);

    /* 找设备 */
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(NULL, &list);
    libusb_device *dev = NULL;
    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) < 0) continue;
        if (dd.idVendor == AIC_VID && dd.idProduct == AIC_PID) {
            dev = list[i];
            printf("找到设备: %04x:%04x (bus %d, addr %d)\n",
                   dd.idVendor, dd.idProduct,
                   libusb_get_bus_number(list[i]),
                   libusb_get_device_address(list[i]));
            break;
        }
    }
    if (!dev) {
        fprintf(stderr, "未找到 %04x:%04x 设备。\n"
                        "如果设备已经是 a69c:8d80 或 a69c:8d83，说明已经切过模式了。\n",
                AIC_VID, AIC_PID);
        libusb_free_device_list(list, 1);
        libusb_exit(NULL);
        return 1;
    }

    libusb_device_handle *h = NULL;
    rc = libusb_open(dev, &h);
    if (rc < 0 || !h) {
        fprintf(stderr, "打开设备失败: %s\n"
                        "（macOS 上可能需要 sudo）\n",
                libusb_error_name(rc));
        libusb_free_device_list(list, 1);
        libusb_exit(NULL);
        return 1;
    }

    /* 打印活动配置和接口的端点，自动定位 BOT 批量端点 */
    struct libusb_config_descriptor *cfg;
    /* 返回值必须检查：设备未配置（bConfigurationValue=0）时 cfg 不被赋值，
     * 下面直接解引用即崩溃。 */
    if (libusb_get_active_config_descriptor(dev, &cfg) < 0) {
        printf("  (读取配置描述符失败，无法枚举端点)\n");
        libusb_close(dev);
        libusb_exit(NULL);
        return 1;
    }
    int ep_out = -1, ep_in = -1;
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *itf = &cfg->interface[i];
        for (int a = 0; a < itf->num_altsetting; a++) {
            const struct libusb_interface_descriptor *id = &itf->altsetting[a];
            printf("  接口 %d (class %02x/%02x/%02x), %d 端点\n",
                   id->bInterfaceNumber, id->bInterfaceClass,
                   id->bInterfaceSubClass, id->bInterfaceProtocol,
                   id->bNumEndpoints);
            for (int e = 0; e < id->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
                printf("    EP 0x%02x %s maxpkt=%u\n", ed->bEndpointAddress,
                       (ed->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) ? "IN " : "OUT",
                       ed->wMaxPacketSize);
                if ((ed->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_BULK) {
                    if (ed->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) {
                        if (ep_in < 0) ep_in = ed->bEndpointAddress;
                    } else {
                        if (ep_out < 0) ep_out = ed->bEndpointAddress;
                    }
                }
            }
        }
    }
    printf("选用批量端点: OUT=0x%02x IN=0x%02x\n", ep_out, ep_in);
    libusb_free_config_descriptor(cfg);

    if (status_only) {
        libusb_close(h);
        libusb_free_device_list(list, 1);
        libusb_exit(NULL);
        return 0;
    }

    if (ep_out < 0 || ep_in < 0) {
        fprintf(stderr, "未找到批量端点，设备状态异常\n");
        libusb_close(h);
        libusb_free_device_list(list, 1);
        libusb_exit(NULL);
        return 1;
    }

    /* 确保配置 1 活动，驱逐内核大容量存储驱动，独占接口 0 */
    libusb_set_auto_detach_kernel_driver(h, 1);
    int cfg0 = 0;
    if (libusb_get_configuration(h, &cfg0) == 0 && cfg0 != 1) {
        rc = libusb_set_configuration(h, 1);
        printf("set_configuration(1) -> %s\n", libusb_error_name(rc));
    }
    rc = libusb_claim_interface(h, 0);
    if (rc < 0) {
        fprintf(stderr, "claim_interface 失败: %s\n", libusb_error_name(rc));
        libusb_close(h);
        libusb_free_device_list(list, 1);
        libusb_exit(NULL);
        return 1;
    }
    printf("接口 0 已独占（内核存储驱动已剥离）\n");

    /* 组 CBW：31 字节 = 31-byte header + 16-byte CDB */
    unsigned char cbw[31];
    memset(cbw, 0, sizeof(cbw));
    memcpy(&cbw[0],  "USBC", 4);          /* 签名 */
    cbw[4]=0x78; cbw[5]=0x56; cbw[6]=0x34; cbw[7]=0x12;  /* tag，任意 */
    cbw[8]=0; cbw[9]=0; cbw[10]=0; cbw[11]=0;           /* DataTransferLength = 0 */
    cbw[12]=0x00;                                        /* Flags: OUT */
    cbw[13]=0x00;                                        /* LUN 0 */
    cbw[14]=0x10;                                        /* cbLength = 16 */
    memcpy(&cbw[15], CDB, 16);
    print_hex("发送 CBW: ", cbw, sizeof(cbw));

    int transferred = 0;
    rc = libusb_bulk_transfer(h, ep_out, cbw, sizeof(cbw), &transferred, 5000);
    if (rc < 0) {
        fprintf(stderr, "CBW 发送失败: %s (已传 %d 字节)\n", libusb_error_name(rc), transferred);
        libusb_release_interface(h, 0);
        libusb_close(h);
        libusb_free_device_list(list, 1);
        libusb_exit(NULL);
        return 1;
    }
    printf("CBW 已发送 (%d 字节)\n", transferred);

    /* 读 13 字节 CSW 确认 */
    unsigned char csw[13];
    rc = libusb_bulk_transfer(h, ep_in, csw, sizeof(csw), &transferred, 5000);
    if (rc == 0 && transferred == 13) {
        print_hex("收到 CSW: ", csw, transferred);
        if (memcmp(csw, "USBS", 4) == 0 && csw[12] == 0) {
            printf("✅ 模式切换命令被设备接受 (bCSWStatus=0 Good)\n");
            printf("   设备应重枚举为 a69c:8d80。用 ioreg -p IOUSB 查看。\n");
        } else {
            printf("⚠️ CSW 状态异常 (signature=%02x%02x%02x%02x status=%02x)，命令可能未生效\n",
                   csw[0], csw[1], csw[2], csw[3], csw[12]);
        }
    } else {
        printf("CSW 读取: %s (已传 %d) — 重枚举可能已发生，属正常\n",
               libusb_error_name(rc), transferred);
    }

    libusb_release_interface(h, 0);
    libusb_close(h);
    libusb_free_device_list(list, 1);
    libusb_exit(NULL);
    return 0;
}
