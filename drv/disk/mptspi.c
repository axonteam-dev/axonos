/*
 * Fusion-MPT SPI host (LSI Logic Parallel / 53c1030 — VMware default SCSI).
 *
 * Bring-up follows Linux drivers/message/fusion/mptbase.c:
 *   MessageUnitReset → GetIocFacts → IOCInit → PortEnable → OPERATIONAL
 * Doorbell handshake uses per-word Int/Ack waits (SeaBIOS QEMU shortcut is
 * insufficient for VMware firmware).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <pci.h>
#include <scsi.h>
#include <disk.h>
#include <heap.h>
#include <klog.h>
#include <serial.h>
#include <mmio.h>
#include <pit.h>
#include <mptspi.h>

#define LSI_VENDOR_ID       0x1000u
#define LSI_DEVICE_53C1030  0x0030u
#define LSI_DEVICE_SAS1068  0x0054u
#define LSI_DEVICE_SAS1068E 0x0058u

#define MPT_REG_DOORBELL    0x00u
#define MPT_REG_WRITE_SEQ   0x04u
#define MPT_REG_HOST_DIAG   0x08u
#define MPT_REG_ISTATUS     0x30u
#define MPT_REG_IMASK       0x34u
#define MPT_REG_REQ_Q       0x40u
#define MPT_REG_REP_Q       0x44u

#define MPT_DOORBELL_MSG_RESET  0x40u
#define MPT_DOORBELL_HANDSHAKE  0x42u

#define MPT_HIS_DOORBELL_INT    0x00000001u
#define MPT_HIS_REPLY_INT       0x00000008u
#define MPT_HIS_IOP_DOORBELL    0x80000000u

#define MPT_IOC_STATE_MASK      0xF0000000u
#define MPT_IOC_STATE_RESET     0x00000000u
#define MPT_IOC_STATE_READY     0x10000000u
#define MPT_IOC_STATE_OPERATIONAL 0x20000000u
#define MPT_IOC_STATE_FAULT     0x40000000u

#define MPT_FUNC_SCSI_IO        0x00u
#define MPT_FUNC_IOC_INIT       0x02u
#define MPT_FUNC_IOC_FACTS      0x03u
#define MPT_FUNC_PORT_FACTS     0x05u
#define MPT_FUNC_PORT_ENABLE    0x06u

#define MPT_WHOINIT_HOST_DRIVER 0x04u

#define MPT_CTRL_WRITE          (1u << 24)
#define MPT_CTRL_READ           (2u << 24)

#define MPT_SGE_FLAGS_BASE      0xD1000000u
#define MPT_SGE_FLAGS_WRITE     0x04000000u

#define MPT_REPLY_FRAME_SIZE    0x50u
#define MPT_HS_REPLY_U16        64
#define MPT_MAX_HBAS            2
#define MPT_MAX_TARGET          7
#define MPT_POLL_ITERS          4000000
#define MPT_BOUNCE_BYTES        (128u * 512u) /* matches scsi_core 128-sector cap */

#define MPI_IOCSTATUS_SUCCESS   0x0000u
#define MPI_IOCSTATUS_BUSY      0x0002u
#define MPI_VERSION             0x0105u
#define MPI_HEADER_VERSION      0x0000u

typedef struct mpt_sge_simple_union {
	uint32_t FlagsLength;
	uint32_t AddressLow;
	uint32_t AddressHigh;
} __attribute__((packed)) mpt_sge_simple_union_t;

typedef struct mpt_ioc_facts_req {
	uint8_t Reserved[2];
	uint8_t ChainOffset;
	uint8_t Function;
	uint8_t Reserved1[3];
	uint8_t MsgFlags;
	uint32_t MsgContext;
} __attribute__((packed)) mpt_ioc_facts_req_t;

typedef struct mpt_ioc_facts_reply {
	uint16_t MsgVersion;
	uint8_t MsgLength;
	uint8_t Function;
	uint16_t HeaderVersion;
	uint8_t IOCNumber;
	uint8_t MsgFlags;
	uint32_t MsgContext;
	uint16_t IOCExceptions;
	uint16_t IOCStatus;
	uint32_t IOCLogInfo;
	uint8_t MaxChainDepth;
	uint8_t WhoInit;
	uint8_t BlockSize;
	uint8_t Flags;
	uint16_t ReplyQueueDepth;
	uint16_t RequestFrameSize;
	uint16_t Reserved_FWVersion;
	uint16_t ProductID;
	uint32_t CurrentHostMfaHighAddr;
	uint16_t GlobalCredits;
	uint8_t NumberOfPorts;
	uint8_t EventState;
	uint32_t CurrentSenseBufferHighAddr;
	uint16_t CurReplyFrameSize;
	uint8_t MaxDevices;
	uint8_t MaxBuses;
	uint32_t FWImageSize;
	uint32_t IOCCapabilities;
	uint32_t FWVersion;
	uint16_t HighPriorityQueueDepth;
	uint16_t Reserved2;
	mpt_sge_simple_union_t HostPageBufferSGE;
	uint32_t ReplyFifoHostSignalingAddr;
} __attribute__((packed)) mpt_ioc_facts_reply_t;

typedef struct mpt_ioc_init_req {
	uint8_t WhoInit;
	uint8_t Reserved;
	uint8_t ChainOffset;
	uint8_t Function;
	uint8_t Flags;
	uint8_t MaxDevices;
	uint8_t MaxBuses;
	uint8_t MsgFlags;
	uint32_t MsgContext;
	uint16_t ReplyFrameSize;
	uint8_t Reserved1[2];
	uint32_t HostMfaHighAddr;
	uint32_t SenseBufferHighAddr;
	uint32_t ReplyFifoHostSignalingAddr;
	mpt_sge_simple_union_t HostPageBufferSGE;
	uint16_t MsgVersion;
	uint16_t HeaderVersion;
} __attribute__((packed)) mpt_ioc_init_req_t;

typedef struct mpt_port_enable_req {
	uint8_t Reserved[2];
	uint8_t ChainOffset;
	uint8_t Function;
	uint8_t Reserved1;
	uint8_t PortNumber;
	uint8_t Reserved2;
	uint8_t MsgFlags;
	uint32_t MsgContext;
} __attribute__((packed)) mpt_port_enable_req_t;

typedef struct mpt_default_reply {
	uint8_t Reserved[2];
	uint8_t MsgLength;
	uint8_t Function;
	uint8_t Reserved1[3];
	uint8_t MsgFlags;
	uint32_t MsgContext;
	uint16_t Reserved2;
	uint16_t IOCStatus;
	uint32_t IOCLogInfo;
} __attribute__((packed)) mpt_default_reply_t;

typedef struct mpt_scsi_io_req {
	uint8_t TargetID;
	uint8_t Bus;
	uint8_t ChainOffset;
	uint8_t Function;
	uint8_t CDBLength;
	uint8_t SenseBufferLength;
	uint8_t Reserved;
	uint8_t MessageFlags;
	uint32_t MessageContext;
	uint8_t LUN[8];
	uint32_t Control;
	uint8_t CDB[16];
	uint32_t DataLength;
	uint32_t SenseBufferLowAddr;
} __attribute__((packed)) mpt_scsi_io_req_t;

typedef struct mpt_sge32 {
	uint32_t FlagsLength;
	uint32_t DataBufferAddressLow;
} __attribute__((packed)) mpt_sge32_t;

typedef struct mpt_dma_req {
	mpt_scsi_io_req_t scsi_io;
	mpt_sge32_t sge;
} __attribute__((packed, aligned(16))) mpt_dma_req_t;

typedef struct mpt_hba {
	int used;
	uint16_t io_base;
	volatile uint32_t *mmio;
	uint32_t msg_ctx;
	uint16_t reply_sz;
	uint16_t reply_depth;
	uint8_t *reply_pool_raw;
	uint8_t *reply_pool;
	uint32_t reply_pool_pa;
	uint8_t *sense_raw;
	uint8_t *sense;
	uint32_t sense_pa;
	mpt_dma_req_t *req_raw;
	mpt_dma_req_t *req;
	uint32_t req_pa;
	uint8_t *bounce_raw;
	uint8_t *bounce;
	uint32_t bounce_pa;
	uint16_t hs_reply[MPT_HS_REPLY_U16];
	mpt_ioc_facts_reply_t facts;
} mpt_hba_t;

typedef struct mpt_target {
	mpt_hba_t *hba;
	uint8_t target;
	uint8_t lun;
} mpt_target_t;

extern uint64_t virt_to_phys(uint64_t va);

static mpt_hba_t g_hbas[MPT_MAX_HBAS];
static mpt_target_t g_targets[MPT_MAX_HBAS * MPT_MAX_TARGET];
static int g_target_count;

static void *mpt_alloc_aligned(size_t size, size_t align, void **out_raw) {
	void *raw = kmalloc(size + align);
	if (!raw)
		return NULL;
	*out_raw = raw;
	uintptr_t a = ((uintptr_t)raw + align - 1u) & ~(uintptr_t)(align - 1u);
	return (void *)a;
}

/* Push CPU cache lines to RAM (and invalidate) so device DMA sees/writes host memory. */
static void mpt_dma_sync(void *va, size_t len) {
	uintptr_t start = (uintptr_t)va & ~63ull;
	uintptr_t end = ((uintptr_t)va + len + 63ull) & ~63ull;
	uintptr_t p;
	if (!va || len == 0)
		return;
	for (p = start; p < end; p += 64)
		asm volatile("clflush (%0)" :: "r"(p) : "memory");
	asm volatile("mfence" ::: "memory");
}

static inline void mpt_writel(mpt_hba_t *h, uint32_t reg, uint32_t val) {
	if (h->mmio)
		h->mmio[reg / 4] = val;
	else
		outportl((uint16_t)(h->io_base + (uint16_t)reg), val);
}

static inline uint32_t mpt_readl(mpt_hba_t *h, uint32_t reg) {
	if (h->mmio)
		return h->mmio[reg / 4];
	return inportl((uint16_t)(h->io_base + (uint16_t)reg));
}

static uint32_t mpt_ioc_state(mpt_hba_t *h) {
	return mpt_readl(h, MPT_REG_DOORBELL) & MPT_IOC_STATE_MASK;
}

static int mpt_wait_doorbell_int(mpt_hba_t *h, int seconds) {
	int cntdn = seconds * 1000;
	while (cntdn-- > 0) {
		if (mpt_readl(h, MPT_REG_ISTATUS) & MPT_HIS_DOORBELL_INT)
			return 0;
		pit_sleep_ms(1);
	}
	return -1;
}

static int mpt_wait_doorbell_ack(mpt_hba_t *h, int seconds) {
	int cntdn = seconds * 1000;
	while (cntdn-- > 0) {
		if (!(mpt_readl(h, MPT_REG_ISTATUS) & MPT_HIS_IOP_DOORBELL))
			return 0;
		pit_sleep_ms(1);
	}
	return -1;
}

static int mpt_wait_doorbell_reply(mpt_hba_t *h, int seconds) {
	int u16cnt = 0;
	uint16_t *hs = h->hs_reply;
	mpt_default_reply_t *hdr = (mpt_default_reply_t *)h->hs_reply;

	memset(h->hs_reply, 0, sizeof(h->hs_reply));

	if (mpt_wait_doorbell_int(h, seconds) != 0)
		return -1;
	hs[u16cnt++] = (uint16_t)(mpt_readl(h, MPT_REG_DOORBELL) & 0xFFFFu);
	mpt_writel(h, MPT_REG_ISTATUS, 0);

	if (mpt_wait_doorbell_int(h, 5) != 0)
		return -1;
	hs[u16cnt++] = (uint16_t)(mpt_readl(h, MPT_REG_DOORBELL) & 0xFFFFu);
	mpt_writel(h, MPT_REG_ISTATUS, 0);

	for (u16cnt = 2; u16cnt < (int)(2u * hdr->MsgLength) && u16cnt < MPT_HS_REPLY_U16; u16cnt++) {
		if (mpt_wait_doorbell_int(h, 5) != 0)
			return -1;
		hs[u16cnt] = (uint16_t)(mpt_readl(h, MPT_REG_DOORBELL) & 0xFFFFu);
		mpt_writel(h, MPT_REG_ISTATUS, 0);
	}

	/* Final doorbell interrupt after reply payload */
	(void)mpt_wait_doorbell_int(h, 5);
	mpt_writel(h, MPT_REG_ISTATUS, 0);
	return (int)(u16cnt / 2);
}

/* Linux mpt_handshake_req_reply_wait */
static int mpt_handshake(mpt_hba_t *h, const void *req, int req_bytes,
                         void *reply, int reply_bytes, int maxwait_sec) {
	const uint8_t *req_bytes_p = (const uint8_t *)req;
	int ii;

	if (!req || req_bytes <= 0 || (req_bytes % 4) != 0)
		return -1;

	mpt_writel(h, MPT_REG_ISTATUS, 0);
	mpt_writel(h, MPT_REG_DOORBELL,
	           ((uint32_t)MPT_DOORBELL_HANDSHAKE << 24) |
	           (((uint32_t)req_bytes / 4u) << 16));

	if (mpt_wait_doorbell_int(h, 5) != 0) {
		klogprintf("mptspi: handshake start INT timeout istatus=0x%x\n",
		           (unsigned)mpt_readl(h, MPT_REG_ISTATUS));
		return -1;
	}
	mpt_writel(h, MPT_REG_ISTATUS, 0);
	if (mpt_wait_doorbell_ack(h, 5) != 0) {
		klogprintf("mptspi: handshake start ACK timeout\n");
		return -1;
	}

	for (ii = 0; ii < req_bytes / 4; ii++) {
		uint32_t word = (uint32_t)req_bytes_p[ii * 4 + 0] |
		                ((uint32_t)req_bytes_p[ii * 4 + 1] << 8) |
		                ((uint32_t)req_bytes_p[ii * 4 + 2] << 16) |
		                ((uint32_t)req_bytes_p[ii * 4 + 3] << 24);
		mpt_writel(h, MPT_REG_DOORBELL, word);
		if (mpt_wait_doorbell_ack(h, 5) != 0) {
			klogprintf("mptspi: handshake dword %d ACK timeout\n", ii);
			return -1;
		}
	}

	if (mpt_wait_doorbell_reply(h, maxwait_sec) < 0) {
		klogprintf("mptspi: handshake reply timeout\n");
		return -1;
	}

	if (reply && reply_bytes > 0) {
		int copy = reply_bytes;
		if (copy > (int)sizeof(h->hs_reply))
			copy = (int)sizeof(h->hs_reply);
		memcpy(reply, h->hs_reply, (size_t)copy);
	}
	return 0;
}

static int mpt_wait_ioc_state(mpt_hba_t *h, uint32_t want, int seconds) {
	int cntdn = seconds * 1000;
	while (cntdn-- > 0) {
		uint32_t st = mpt_ioc_state(h);
		if (st == want)
			return 0;
		if (st == MPT_IOC_STATE_FAULT) {
			klogprintf("mptspi: IOC FAULT state=0x%x\n", (unsigned)st);
			return -1;
		}
		pit_sleep_ms(1);
	}
	klogprintf("mptspi: wait state 0x%x timeout (now 0x%x)\n",
	           (unsigned)want, (unsigned)mpt_ioc_state(h));
	return -1;
}

static int mpt_message_unit_reset(mpt_hba_t *h) {
	mpt_writel(h, MPT_REG_DOORBELL, (uint32_t)MPT_DOORBELL_MSG_RESET << 24);
	mpt_writel(h, MPT_REG_IMASK, MPT_HIS_DOORBELL_INT | MPT_HIS_REPLY_INT);
	mpt_writel(h, MPT_REG_ISTATUS, 0);
	/* Give FW time, then require READY before Facts/Init. */
	pit_sleep_ms(50);
	return mpt_wait_ioc_state(h, MPT_IOC_STATE_READY, 15);
}

static int mpt_get_ioc_facts(mpt_hba_t *h) {
	mpt_ioc_facts_req_t req;
	mpt_ioc_facts_reply_t *f = &h->facts;

	memset(&req, 0, sizeof(req));
	memset(f, 0, sizeof(*f));
	req.Function = MPT_FUNC_IOC_FACTS;

	if (mpt_handshake(h, &req, (int)sizeof(req), f, (int)sizeof(*f), 5) != 0)
		return -1;

	if (f->IOCStatus != MPI_IOCSTATUS_SUCCESS && f->IOCStatus != 0) {
		klogprintf("mptspi: IOCFacts status=0x%x log=0x%x\n",
		           (unsigned)f->IOCStatus, (unsigned)f->IOCLogInfo);
		/* Some FW leave status 0 in handshake; continue if MsgLength looks sane. */
		if (f->MsgLength < 8)
			return -1;
	}

	h->reply_sz = MPT_REPLY_FRAME_SIZE;
	if (f->CurReplyFrameSize > h->reply_sz)
		h->reply_sz = f->CurReplyFrameSize;
	h->reply_depth = f->ReplyQueueDepth ? f->ReplyQueueDepth : 4;
	if (h->reply_depth > 16)
		h->reply_depth = 16;
	if (h->reply_depth < 1)
		h->reply_depth = 1;

	klogprintf("mptspi: facts MsgVer=0x%x ReplyFrame=%u depth=%u ReqFrame=%u credits=%u\n",
	           (unsigned)f->MsgVersion, (unsigned)h->reply_sz, (unsigned)h->reply_depth,
	           (unsigned)(f->RequestFrameSize * 4u), (unsigned)f->GlobalCredits);
	return 0;
}

static int mpt_send_ioc_init(mpt_hba_t *h) {
	mpt_ioc_init_req_t init;
	mpt_default_reply_t reply;

	memset(&init, 0, sizeof(init));
	memset(&reply, 0, sizeof(reply));
	init.WhoInit = MPT_WHOINIT_HOST_DRIVER;
	init.Function = MPT_FUNC_IOC_INIT;
	init.MaxDevices = h->facts.MaxDevices ? h->facts.MaxDevices : 8;
	init.MaxBuses = h->facts.MaxBuses ? h->facts.MaxBuses : 1;
	init.ReplyFrameSize = h->reply_sz;
	init.HostMfaHighAddr = 0;
	init.SenseBufferHighAddr = 0;
	if (h->facts.MsgVersion >= 0x0105u) {
		init.MsgVersion = MPI_VERSION;
		init.HeaderVersion = MPI_HEADER_VERSION;
	}

	if (mpt_handshake(h, &init, (int)sizeof(init), &reply, (int)sizeof(reply), 10) != 0)
		return -1;

	if (reply.IOCStatus != MPI_IOCSTATUS_SUCCESS) {
		klogprintf("mptspi: IOCInit status=0x%x log=0x%x MsgLen=%u\n",
		           (unsigned)reply.IOCStatus, (unsigned)reply.IOCLogInfo,
		           (unsigned)reply.MsgLength);
		return -1;
	}
	return 0;
}

static int mpt_port_enable(mpt_hba_t *h) {
	mpt_port_enable_req_t pe;
	mpt_default_reply_t reply;

	memset(&pe, 0, sizeof(pe));
	memset(&reply, 0, sizeof(reply));
	pe.Function = MPT_FUNC_PORT_ENABLE;
	pe.PortNumber = 0;

	if (mpt_handshake(h, &pe, (int)sizeof(pe), &reply, (int)sizeof(reply), 30) != 0)
		return -1;
	if (reply.IOCStatus != MPI_IOCSTATUS_SUCCESS) {
		klogprintf("mptspi: PortEnable status=0x%x log=0x%x\n",
		           (unsigned)reply.IOCStatus, (unsigned)reply.IOCLogInfo);
		return -1;
	}
	return mpt_wait_ioc_state(h, MPT_IOC_STATE_OPERATIONAL, 60);
}

static void mpt_post_reply_frames(mpt_hba_t *h) {
	uint16_t i;
	for (i = 0; i < h->reply_depth; i++) {
		uint32_t pa = h->reply_pool_pa + (uint32_t)i * (uint32_t)h->reply_sz;
		mpt_writel(h, MPT_REG_REP_Q, pa);
	}
}

static int mpt_wait_reply(mpt_hba_t *h, uint32_t expect_ctx) {
	int i;
	for (i = 0; i < MPT_POLL_ITERS; i++) {
		uint32_t ist = mpt_readl(h, MPT_REG_ISTATUS);
		if (ist & MPT_HIS_REPLY_INT) {
			uint32_t resp = mpt_readl(h, MPT_REG_REP_Q);
			(void)mpt_readl(h, MPT_REG_REP_Q);
			if (resp == expect_ctx)
				return 0;
			if (resp & 0x80000000u) {
				/* Address of reply frame — repost that frame */
				mpt_writel(h, MPT_REG_REP_Q, resp & 0x7fffffffu);
				return -1;
			}
		}
		asm volatile("pause" ::: "memory");
	}
	return -1;
}

static int mpt_execute(void *priv, const uint8_t *cdb, size_t cdb_len,
                       void *data, size_t data_len, int direction) {
	mpt_target_t *t = (mpt_target_t *)priv;
	mpt_hba_t *h;
	uint32_t ctx;
	uint32_t data_pa = 0;
	int use_bounce = 0;
	int rc;

	if (!t || !t->hba || !cdb || cdb_len == 0 || cdb_len > 16)
		return -1;
	h = t->hba;
	if (!h->req || !h->sense)
		return -1;
	if (data_len > 0 && (!data || !h->bounce || !h->bounce_pa))
		return -1;
	if (data_len > MPT_BOUNCE_BYTES)
		return -1;

	memset(h->req, 0, sizeof(*h->req));
	memset(h->sense, 0, 18);
	ctx = (++h->msg_ctx) & 0x7fffffffu;
	if (ctx == 0)
		ctx = 1;

	h->req->scsi_io.TargetID = t->target;
	h->req->scsi_io.Bus = 0;
	h->req->scsi_io.Function = MPT_FUNC_SCSI_IO;
	h->req->scsi_io.CDBLength = 16;
	h->req->scsi_io.SenseBufferLength = 18;
	h->req->scsi_io.MessageContext = ctx;
	h->req->scsi_io.LUN[1] = t->lun;
	h->req->scsi_io.DataLength = (uint32_t)data_len;
	h->req->scsi_io.SenseBufferLowAddr = h->sense_pa;
	memcpy(h->req->scsi_io.CDB, cdb, cdb_len);

	/*
	 * Always DMA through a dedicated bounce buffer and clflush it.
	 * VMware LSI MPT does not reliably snoop WB heap/stack — without this,
	 * WRITE ships zeros and READ leaves the CPU looking at stale cache
	 * (mkfs "succeeds", xxd still all-zero).
	 */
	if (data_len > 0) {
		use_bounce = 1;
		if (direction == SCSI_DATA_OUT)
			memcpy(h->bounce, data, data_len);
		else
			memset(h->bounce, 0, data_len);
		mpt_dma_sync(h->bounce, data_len);
		data_pa = h->bounce_pa;
	}

	if (direction == SCSI_DATA_IN && data_len > 0) {
		h->req->scsi_io.Control = MPT_CTRL_READ;
		h->req->sge.FlagsLength = (uint32_t)data_len | MPT_SGE_FLAGS_BASE;
		h->req->sge.DataBufferAddressLow = data_pa;
	} else if (direction == SCSI_DATA_OUT && data_len > 0) {
		h->req->scsi_io.Control = MPT_CTRL_WRITE;
		h->req->sge.FlagsLength = (uint32_t)data_len | MPT_SGE_FLAGS_BASE | MPT_SGE_FLAGS_WRITE;
		h->req->sge.DataBufferAddressLow = data_pa;
	} else {
		h->req->scsi_io.Control = 0;
		h->req->scsi_io.DataLength = 0;
		h->req->sge.FlagsLength = MPT_SGE_FLAGS_BASE;
		h->req->sge.DataBufferAddressLow = 0;
	}

	mpt_dma_sync(h->req, sizeof(*h->req));
	mpt_dma_sync(h->sense, 18);
	mpt_writel(h, MPT_REG_REQ_Q, h->req_pa);
	rc = mpt_wait_reply(h, ctx);
	if (rc != 0)
		return -1;

	if (use_bounce && direction == SCSI_DATA_IN) {
		mpt_dma_sync(h->bounce, data_len);
		memcpy(data, h->bounce, data_len);
	}
	return 0;
}

static const scsi_transport_ops_t mpt_ops = {
	.execute_command = mpt_execute,
};

static void mpt_hba_free_partial(mpt_hba_t *h) {
	if (h->reply_pool_raw)
		kfree(h->reply_pool_raw);
	if (h->sense_raw)
		kfree(h->sense_raw);
	if (h->req_raw)
		kfree(h->req_raw);
	if (h->bounce_raw)
		kfree(h->bounce_raw);
	memset(h, 0, sizeof(*h));
}

static int mpt_bringup(mpt_hba_t *h) {
	size_t pool_sz;

	if (mpt_message_unit_reset(h) != 0) {
		/* Some VMware adapters already READY — try Facts anyway. */
		if (mpt_ioc_state(h) != MPT_IOC_STATE_READY &&
		    mpt_ioc_state(h) != MPT_IOC_STATE_OPERATIONAL) {
			klogprintf("mptspi: MessageUnitReset failed state=0x%x\n",
			           (unsigned)mpt_ioc_state(h));
			return -1;
		}
	}

	if (mpt_get_ioc_facts(h) != 0)
		return -1;

	pool_sz = (size_t)h->reply_sz * (size_t)h->reply_depth;
	h->reply_pool = (uint8_t *)mpt_alloc_aligned(pool_sz, 16, (void **)&h->reply_pool_raw);
	h->sense = (uint8_t *)mpt_alloc_aligned(18, 4, (void **)&h->sense_raw);
	h->req = (mpt_dma_req_t *)mpt_alloc_aligned(sizeof(mpt_dma_req_t), 16, (void **)&h->req_raw);
	h->bounce = (uint8_t *)mpt_alloc_aligned(MPT_BOUNCE_BYTES, 4096, (void **)&h->bounce_raw);
	if (!h->reply_pool || !h->sense || !h->req || !h->bounce)
		return -1;
	memset(h->reply_pool, 0, pool_sz);
	memset(h->bounce, 0, MPT_BOUNCE_BYTES);
	h->reply_pool_pa = (uint32_t)virt_to_phys((uint64_t)(uintptr_t)h->reply_pool);
	h->sense_pa = (uint32_t)virt_to_phys((uint64_t)(uintptr_t)h->sense);
	h->req_pa = (uint32_t)virt_to_phys((uint64_t)(uintptr_t)h->req);
	h->bounce_pa = (uint32_t)virt_to_phys((uint64_t)(uintptr_t)h->bounce);
	if (!h->reply_pool_pa || !h->sense_pa || !h->req_pa || !h->bounce_pa)
		return -1;

	if (mpt_send_ioc_init(h) != 0)
		return -1;
	if (mpt_port_enable(h) != 0)
		return -1;

	mpt_post_reply_frames(h);
	return 0;
}

static int mpt_probe_one(pci_device_t *pdev) {
	mpt_hba_t *h = NULL;
	uint32_t bar0, cmd;
	int hi, tgt, found = 0;

	for (hi = 0; hi < MPT_MAX_HBAS; hi++) {
		if (!g_hbas[hi].used) {
			h = &g_hbas[hi];
			break;
		}
	}
	if (!h)
		return -1;

	memset(h, 0, sizeof(*h));
	bar0 = pdev->bar[0];
	cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
	cmd |= (1u << 0) | (1u << 1) | (1u << 2);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

	if (bar0 & 1u) {
		h->io_base = (uint16_t)(bar0 & ~3u);
	} else if (bar0 != 0) {
		uint64_t pa = (uint64_t)(bar0 & ~0xFull);
		h->mmio = (volatile uint32_t *)mmio_map_phys(pa, 0x1000);
		if (!h->mmio) {
			klogprintf("mptspi: mmio map failed %02x:%02x.%x\n",
			           pdev->bus, pdev->device, pdev->function);
			return -1;
		}
	} else {
		klogprintf("mptspi: no BAR0 on %02x:%02x.%x\n",
		           pdev->bus, pdev->device, pdev->function);
		return -1;
	}

	klogprintf("mptspi: LSI %04x:%04x at %02x:%02x.%x %s=0x%x state=0x%x\n",
	           pdev->vendor_id, pdev->device_id,
	           pdev->bus, pdev->device, pdev->function,
	           h->mmio ? "mmio" : "io",
	           h->mmio ? (unsigned)(pdev->bar[0] & ~0xFu) : (unsigned)h->io_base,
	           (unsigned)mpt_ioc_state(h));

	if (mpt_bringup(h) != 0) {
		mpt_hba_free_partial(h);
		return -1;
	}

	h->used = 1;
	klogprintf("mptspi: OPERATIONAL — scanning targets 0..%d\n", MPT_MAX_TARGET - 1);

	for (tgt = 0; tgt < MPT_MAX_TARGET; tgt++) {
		mpt_target_t *t;
		int id, sd;
		if (g_target_count >= (int)(sizeof(g_targets) / sizeof(g_targets[0])))
			break;
		t = &g_targets[g_target_count];
		t->hba = h;
		t->target = (uint8_t)tgt;
		t->lun = 0;
		id = scsi_register_lun(t, &mpt_ops, 0);
		if (id < 0)
			continue;
		g_target_count++;
		sd = disk_sd_index(id);
		klogprintf("mptspi: target %d lun 0 → disk_id=%d /dev/sd%c\n",
		           tgt, id, (sd >= 0 && sd < 26) ? (char)('a' + sd) : '?');
		found++;
	}
	if (!found)
		klogprintf("mptspi: no disks on targets 0..%d\n", MPT_MAX_TARGET - 1);
	return found;
}

int mptspi_init(void) {
	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	int total = 0;
	int i;

	if (!devs || count <= 0)
		return 0;

	for (i = 0; i < count; i++) {
		if (devs[i].vendor_id != LSI_VENDOR_ID)
			continue;
		if (devs[i].device_id != LSI_DEVICE_53C1030 &&
		    devs[i].device_id != LSI_DEVICE_SAS1068 &&
		    devs[i].device_id != LSI_DEVICE_SAS1068E)
			continue;
		{
			int n = mpt_probe_one(&devs[i]);
			if (n > 0)
				total += n;
		}
	}
	return total;
}
