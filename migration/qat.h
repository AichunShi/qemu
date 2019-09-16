#ifndef QEMU_MIGRATION_QAT_H
#define QEMU_MIGRATION_QAT_H

#include "ram.h"

typedef enum QatSetupType {
    QAT_SETUP_COMPRESS = 0,
    QAT_SETUP_DECOMPRESS = 1,
    QAT_SETUP_MAX,
} QatSetupType;

extern int qat_setup(QatSetupType type);
extern void qat_cleanup(void);
extern int qat_compress_page(RAMBlock *block, MultiPageAddr *mpa);
extern int qat_decompress_page(QEMUFile *f, RAMBlock *block, int bytes,
                                MultiPageAddr *mpa, uint32_t checksum);
extern void qat_flush_data(void);

#endif
