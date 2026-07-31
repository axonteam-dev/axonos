/* Fusion-MPT SPI (LSI Logic Parallel / 53c1030) — VMware default SCSI HBA. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Probe PCI 1000:0030 (and known MPT cousins), register SCSI LUNs via scsi_core. */
int mptspi_init(void);

#ifdef __cplusplus
}
#endif
