#include <scsi.h>
#include <disk.h>
#include <devfs.h>
#include <string.h>
#include <klog.h>
#include <heap.h>
#include <vga.h>  /* snprintf */

#define SCSI_MAX_LUNS  8
#define SCSI_SECTOR_SIZE 512
#define SCSI_VENDOR_LEN  8
#define SCSI_PRODUCT_LEN 16
#define SCSI_REVISION_LEN 4

typedef struct scsi_lun {
	void *transport_priv;
	const scsi_transport_ops_t *ops;
	int lun_id;
	uint32_t sector_count;  /* от READ CAPACITY(10): последний LBA + 1 */
	int disk_id;            /* id из disk_register */
	int pdt;                /* SPC peripheral device type */
	int in_use;
	char vendor[SCSI_VENDOR_LEN + 1];
	char product[SCSI_PRODUCT_LEN + 1];
	char revision[SCSI_REVISION_LEN + 1];
} scsi_lun_t;

static scsi_lun_t g_luns[SCSI_MAX_LUNS];
static int g_lun_count = 0;

/* --- CDB builders (SPC-4 / SBC-3) --- */

static void cdb_test_unit_ready(uint8_t *cdb) {
	memset(cdb, 0, 6);
	cdb[0] = SCSI_TEST_UNIT_READY;
}

static void cdb_request_sense(uint8_t *cdb, size_t alloc_len) {
	memset(cdb, 0, 6);
	cdb[0] = SCSI_REQUEST_SENSE;
	cdb[4] = (uint8_t)(alloc_len > 255 ? 255 : alloc_len);
}

static void cdb_inquiry(uint8_t *cdb, size_t alloc_len) {
	memset(cdb, 0, 6);
	cdb[0] = SCSI_INQUIRY;
	cdb[4] = (uint8_t)(alloc_len > 255 ? 255 : alloc_len);
}

static void cdb_read_capacity_10(uint8_t *cdb) {
	memset(cdb, 0, 10);
	cdb[0] = SCSI_READ_CAPACITY_10;
	/* LBA=0, PMI=0 */
}

static void cdb_read_10(uint8_t *cdb, uint32_t lba, uint32_t blocks) {
	memset(cdb, 0, 10);
	cdb[0] = SCSI_READ_10;
	cdb[2] = (uint8_t)(lba >> 24);
	cdb[3] = (uint8_t)(lba >> 16);
	cdb[4] = (uint8_t)(lba >> 8);
	cdb[5] = (uint8_t)(lba);
	cdb[7] = (uint8_t)(blocks >> 8);
	cdb[8] = (uint8_t)(blocks);
}

static void cdb_write_10(uint8_t *cdb, uint32_t lba, uint32_t blocks) {
	memset(cdb, 0, 10);
	cdb[0] = SCSI_WRITE_10;
	cdb[2] = (uint8_t)(lba >> 24);
	cdb[3] = (uint8_t)(lba >> 16);
	cdb[4] = (uint8_t)(lba >> 8);
	cdb[5] = (uint8_t)(lba);
	cdb[7] = (uint8_t)(blocks >> 8);
	cdb[8] = (uint8_t)(blocks);
}

/* Парсинг READ CAPACITY(10) response: bytes 0-3 = last LBA (big-endian), 4-7 = block size. */
static int parse_read_capacity(const uint8_t *buf, uint32_t *out_last_lba, uint32_t *out_block_size) {
	if (!buf || !out_last_lba || !out_block_size) return -1;
	*out_last_lba  = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
	*out_block_size = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) | ((uint32_t)buf[6] << 8) | buf[7];
	return 0;
}

/* Копировать поле INQUIRY с обрезкой пробелов и null-terminate */
static void inquiry_str_copy(char *dst, size_t dst_size, const uint8_t *src, size_t src_len) {
	if (!dst || dst_size == 0 || !src) return;
	size_t i = 0;
	while (i < src_len && src[i] == ' ') i++;
	size_t end = src_len;
	while (end > i && src[end - 1] == ' ') end--;
	size_t cp = end - i;
	if (cp >= dst_size) cp = dst_size - 1;
	memcpy(dst, src + i, cp);
	dst[cp] = '\0';
}

static scsi_lun_t *scsi_lun_by_disk_id(int device_id) {
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (g_luns[i].in_use && g_luns[i].disk_id == device_id)
			return &g_luns[i];
	}
	return NULL;
}

static int scsi_disk_read(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	scsi_lun_t *lun = scsi_lun_by_disk_id(device_id);
	if (!lun || !lun->ops || !lun->ops->execute_command) return -1;
	if (sectors == 0) return 0;
	if (lba + sectors > lun->sector_count) return -1;

	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint32_t done = 0;
	uint8_t *p = (uint8_t *)buf;

	while (done < sectors) {
		uint32_t chunk = sectors - done;
		/* Cap to 128 sectors (64 KiB): HBA bounce buffers and PRDT limits. */
		if (chunk > 128u) chunk = 128u;
		cdb_read_10(cdb, lba + done, chunk);
		size_t len = (size_t)chunk * SCSI_SECTOR_SIZE;
		int r = lun->ops->execute_command(lun->transport_priv, cdb, 10, p + (size_t)done * SCSI_SECTOR_SIZE, len, SCSI_DATA_IN);
		if (r != 0) return -1;
		done += chunk;
	}
	return 0;
}

static int scsi_disk_write(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	scsi_lun_t *lun = scsi_lun_by_disk_id(device_id);
	if (!lun || !lun->ops || !lun->ops->execute_command) return -1;
	if (sectors == 0) return 0;
	if (lba + sectors > lun->sector_count) return -1;

	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint32_t done = 0;
	const uint8_t *p = (const uint8_t *)buf;

	while (done < sectors) {
		uint32_t chunk = sectors - done;
		if (chunk > 128u) chunk = 128u;
		cdb_write_10(cdb, lba + done, chunk);
		size_t len = (size_t)chunk * SCSI_SECTOR_SIZE;
		int r = lun->ops->execute_command(lun->transport_priv, cdb, 10, (void *)(p + (size_t)done * SCSI_SECTOR_SIZE), len, SCSI_DATA_OUT);
		if (r != 0) return -1;
		done += chunk;
	}
	return 0;
}

/* Clear UNIT ATTENTION / Not Ready, then retry TUR (common on first open). */
static int scsi_tur_with_ua_retry(void *priv, const scsi_transport_ops_t *ops, int lun_id) {
	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint8_t sense[32];
	(void)lun_id;
	for (int attempt = 0; attempt < 3; attempt++) {
		cdb_test_unit_ready(cdb);
		if (ops->execute_command(priv, cdb, 6, NULL, 0, SCSI_DATA_NONE) == 0)
			return 0;
		memset(sense, 0, sizeof(sense));
		cdb_request_sense(cdb, sizeof(sense));
		(void)ops->execute_command(priv, cdb, 6, sense, sizeof(sense), SCSI_DATA_IN);
	}
	return -1;
}

int scsi_register_lun(void *transport_priv, const scsi_transport_ops_t *ops, int lun_id) {
	if (!ops || !ops->execute_command || g_lun_count >= SCSI_MAX_LUNS) return -1;

	int slot = -1;
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (!g_luns[i].in_use) { slot = i; break; }
	}
	if (slot < 0) return -1;

	scsi_lun_t *lun = &g_luns[slot];
	memset(lun, 0, sizeof(*lun));
	lun->transport_priv = transport_priv;
	lun->ops = ops;
	lun->lun_id = lun_id;
	lun->pdt = SCSI_PDT_UNKNOWN;

	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint8_t cap_buf[8];

	if (scsi_tur_with_ua_retry(transport_priv, ops, lun_id) != 0) {
		klogprintf("scsi: lun %d TEST UNIT READY failed\n", lun_id);
		return -1;
	}

	uint8_t inq_buf[96];
	memset(inq_buf, 0, sizeof(inq_buf));
	cdb_inquiry(cdb, sizeof(inq_buf));
	if (ops->execute_command(transport_priv, cdb, 6, inq_buf, sizeof(inq_buf), SCSI_DATA_IN) == 0) {
		lun->pdt = (int)(inq_buf[0] & 0x1fu);
		inquiry_str_copy(lun->vendor, sizeof(lun->vendor), inq_buf + 8, 8);
		inquiry_str_copy(lun->product, sizeof(lun->product), inq_buf + 16, 16);
		inquiry_str_copy(lun->revision, sizeof(lun->revision), inq_buf + 32, 4);
	} else {
		lun->vendor[0] = lun->product[0] = lun->revision[0] = '\0';
		lun->pdt = SCSI_PDT_DIRECT_ACCESS; /* assume disk if INQUIRY fails */
	}

	if (lun->pdt == SCSI_PDT_CDROM) {
		/* Optical nodes are /dev/sr* from ATAPI; avoid a second broken sd* alias. */
		klogprintf("scsi: lun %d PDT=CD-ROM — skipped (use /dev/sr* from ATAPI)\n", lun_id);
		return -1;
	}
	if (lun->pdt != SCSI_PDT_DIRECT_ACCESS) {
		klogprintf("scsi: lun %d PDT=0x%02x unsupported (want Direct-Access)\n", lun_id, lun->pdt);
		return -1;
	}

	cdb_read_capacity_10(cdb);
	memset(cap_buf, 0, sizeof(cap_buf));
	if (ops->execute_command(transport_priv, cdb, 10, cap_buf, sizeof(cap_buf), SCSI_DATA_IN) != 0) {
		klogprintf("scsi: lun %d READ CAPACITY failed\n", lun_id);
		return -1;
	}

	uint32_t last_lba, block_size;
	if (parse_read_capacity(cap_buf, &last_lba, &block_size) != 0) {
		klogprintf("scsi: lun %d invalid READ CAPACITY response\n", lun_id);
		return -1;
	}
	if (block_size != SCSI_SECTOR_SIZE) {
		klogprintf("scsi: lun %d block size %u unsupported, expect 512\n", lun_id, block_size);
		return -1;
	}
	uint64_t sc = (uint64_t)last_lba + 1ull;
	lun->sector_count = sc > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)sc;

	disk_ops_t *dops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
	if (!dops) return -1;
	memset(dops, 0, sizeof(*dops));
	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "scsi_%d", lun_id);
	dops->name = (const char *)kmalloc(strlen(namebuf) + 1);
	if (dops->name) strcpy((char *)dops->name, namebuf);
	dops->init = NULL;
	dops->read = scsi_disk_read;
	dops->write = scsi_disk_write;

	int id = disk_register(dops);
	if (id < 0) {
		kfree((void *)dops->name);
		kfree(dops);
		return -1;
	}

	lun->disk_id = id;
	lun->in_use = 1;
	g_lun_count++;

	if (disk_publish_sd(id, lun->sector_count) < 0)
		klogprintf("scsi: lun %d failed to publish /dev/sd*\n", lun_id);

	uint32_t size_mb = lun->sector_count / 2048;
	int sd = disk_sd_index(id);
	klogprintf("scsi: %s disk_id=%d lun=%d PDT=0x%02x\n", dops->name, id, lun_id, lun->pdt);
	klogprintf("  vendor=\"%.8s\" model=\"%.16s\" rev=\"%.4s\"\n",
	           lun->vendor, lun->product, lun->revision);
	klogprintf("  sectors=%u (%u MiB) /dev/sd%c\n",
	           lun->sector_count, size_mb,
	           (sd >= 0 && sd < 26) ? (char)('a' + sd) : '?');

	return id;
}

/* --- API для вывода информации (например /proc/scsi/scsi) --- */
int scsi_lun_count(void) {
	return g_lun_count;
}

int scsi_lun_get_info(int index, char *vendor, size_t vlen, char *product, size_t plen,
                      char *revision, size_t rlen, uint32_t *out_sectors, int *out_disk_id,
                      char *out_dev_name, size_t out_dev_name_len, int *out_pdt) {
	if (index < 0 || index >= g_lun_count) return -1;
	int slot = -1;
	int n = 0;
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (!g_luns[i].in_use) continue;
		if (n == index) { slot = i; break; }
		n++;
	}
	if (slot < 0) return -1;
	scsi_lun_t *lun = &g_luns[slot];
	if (vendor && vlen) { strncpy(vendor, lun->vendor, vlen - 1); vendor[vlen - 1] = '\0'; }
	if (product && plen) { strncpy(product, lun->product, plen - 1); product[plen - 1] = '\0'; }
	if (revision && rlen) { strncpy(revision, lun->revision, rlen - 1); revision[rlen - 1] = '\0'; }
	if (out_sectors) *out_sectors = lun->sector_count;
	if (out_disk_id) *out_disk_id = lun->disk_id;
	if (out_pdt) *out_pdt = lun->pdt;
	if (out_dev_name && out_dev_name_len) {
		int sd = disk_sd_index(lun->disk_id);
		int sr = disk_sr_index(lun->disk_id);
		if (sr >= 0)
			snprintf(out_dev_name, out_dev_name_len, "sr%d", sr);
		else if (sd >= 0 && sd < 26)
			snprintf(out_dev_name, out_dev_name_len, "sd%c", (char)('a' + sd));
		else
			snprintf(out_dev_name, out_dev_name_len, "?");
	}
	return 0;
}

int scsi_register_disk_as_lun(int disk_id, uint32_t sectors,
                              const char *vendor, const char *product, const char *revision) {
	if (disk_id < 0 || g_lun_count >= SCSI_MAX_LUNS) return -1;
	/* Optical must not appear as Direct-Access in /proc/scsi/scsi. */
	if (disk_sr_index(disk_id) >= 0)
		return -1;
	int slot = -1;
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (!g_luns[i].in_use) { slot = i; break; }
	}
	if (slot < 0) return -1;
	scsi_lun_t *lun = &g_luns[slot];
	memset(lun, 0, sizeof(*lun));
	lun->transport_priv = NULL;
	lun->ops = NULL;  /* alias: I/O via disk layer; /dev/sdX already published */
	lun->lun_id = disk_id;
	lun->sector_count = sectors;
	lun->disk_id = disk_id;
	lun->pdt = SCSI_PDT_DIRECT_ACCESS;
	lun->in_use = 1;
	if (vendor) { strncpy(lun->vendor, vendor, SCSI_VENDOR_LEN); lun->vendor[SCSI_VENDOR_LEN] = '\0'; }
	if (product) { strncpy(lun->product, product, SCSI_PRODUCT_LEN); lun->product[SCSI_PRODUCT_LEN] = '\0'; }
	if (revision) { strncpy(lun->revision, revision, SCSI_REVISION_LEN); lun->revision[SCSI_REVISION_LEN] = '\0'; }
	g_lun_count++;
	int sd = disk_sd_index(disk_id);
	klogprintf("scsi: disk %d aliased as SCSI LUN (vendor=%s model=%s) /dev/sd%c\n",
	           disk_id, lun->vendor, lun->product,
	           (sd >= 0 && sd < 26) ? (char)('a' + sd) : '?');
	return 0;
}

void scsi_init(void) {
	memset(g_luns, 0, sizeof(g_luns));
	g_lun_count = 0;
	klogprintf("scsi: core ready (transports register LUNs via scsi_register_lun)\n");
}
