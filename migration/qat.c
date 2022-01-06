#include <sys/epoll.h>
#include <cpa.h>
#include <cpa_dc.h>
#include <quickassist/lookaside/access_layer/include/icp_sal_poll.h>

#include "qemu/osdep.h"
#include "cpu.h"
#include "qemu/thread.h"
#include "qemu/log.h"
#include "qat.h"
#include "exec/ram_addr.h"
#include "migration.h"
#include "qemu-file.h"
#include <Osal.h>

#define QAT_REQ_BUF_SIZE (RAM_SAVE_MULTI_PAGE_NUM << TARGET_PAGE_BITS)

#define QAT_INSTANCE_REQ_CACHE_NUM 512

#define PAGEMAP_GFN_MASK 0x7fffffffffffff

#define MAX_PROCESS_NUM 64

extern int32_t qaeMemInit(void);
extern void qaeMemDestroy(void);
extern void *qaeMemAlloc(size_t memsize);
extern void *qaeMemAllocNUMA(size_t size, int node,
            size_t phys_alignment_byte);
extern void qaeMemFree(void **ptr);
extern void qaeMemFreeNUMA(void **ptr);
extern uint64_t qaeVirtToPhysNUMA(void *pVirtAddress);
extern CpaStatus icp_sal_userStart(const char *pProcessName);
extern CpaStatus icp_sal_userStartMultiProcess(
            const char *pProcessName, CpaBoolean limitDevAccess);
extern CpaStatus icp_sal_userStop(void);

bool epoll_thread_running = false;

typedef struct QatInstance QatInstance;

typedef struct QatReq {
    /*
     * For decompression, stores the checkum passed from the compression side.
     * For compresssion, not used.
     */
    uint32_t checksum;
    unsigned long id; // debug purpose
    QatInstance *instance;
    RAMBlock *block;
    ram_addr_t offset;
    MultiPageAddr mpa;
    CpaBufferList *src_buf_list;
    CpaBufferList *dst_buf_list;
    CpaDcRqResults result;
    QLIST_ENTRY(QatReq) node;
} QatReq;

struct QatInstance {
    uint16_t id; // debug purpose
    uint16_t intermediate_buf_num;
    int fd;
    uint32_t node_affinity;
    uint32_t req_cache_num;
    CpaInstanceHandle instance_handle;
    CpaDcSessionHandle session_handle;
    CpaBufferList *session_ctx_buf_list;
    CpaBufferList **intermediate_buf_list;
    QLIST_HEAD(, QatReq) req_cache_list;
    QemuSpin lock;
};

typedef struct QatDev {
    bool zero_copy;
    QEMUFile *f;
    uint16_t instance_num;
    uint32_t meta_buf_size;
    QatInstance *instances;
    QemuThread epoll_thread;
    QemuThread qemu_file_thread;
    int efd;
    /* Fill instances in round robin */
    int rr_instance_id;
    uint64_t requests;
    uint64_t responses;
    uint64_t overflow;
    int64_t start_time;
    uint64_t consumed_bytes;
    uint64_t produced_bytes;
} QatDev;

static QatDev *qat_dev;

void qat_flush_data(void)
{
    while (qat_dev->responses != qat_dev->requests)
        cpu_relax();
}

static uint64_t qat_virt_to_phy(void *vaddr)
{
    RAMBlock *block;
    ram_addr_t offset = 0;
    uint64_t paddr;

    block = qemu_ram_block_from_host(vaddr, false, &offset);
    if (block) {
        offset >>= TARGET_PAGE_BITS;
        paddr = (block->virt_to_phys_table[offset] & PAGEMAP_GFN_MASK) <<
                TARGET_PAGE_BITS;
        if (!paddr)
            qemu_log("%s: fail to get pa for vaddr=%p \n", __func__, vaddr);
    } else {
        paddr = qaeVirtToPhysNUMA(vaddr);
        if(!paddr)
            qemu_log("%s: meta_buf fail to get pa for vaddr=%p \n", __func__, vaddr);
    }

    return paddr;
}

static CpaBufferList *qat_buf_list_alloc(int nodeid, int bytes)
{
    int i = 0, buf_size, buf_num;
    CpaBufferList *buf_list;
    Cpa8U *meta_buf;
    CpaFlatBuffer *flat_buf = NULL;
    Cpa32U buf_list_size, meta_buf_size;

    if (bytes) {
       buf_num = QEMU_ALIGN_UP(bytes, TARGET_PAGE_SIZE) / TARGET_PAGE_SIZE;
    } else {
       /*
        * bytes = 0 indicates this is a request with no buffer to allocate for now.
        * Prepare for QAT_REQ_BUF_SIZE to be set to this req soon.
        */
       buf_num = QEMU_ALIGN_UP(QAT_REQ_BUF_SIZE, TARGET_PAGE_SIZE) / TARGET_PAGE_SIZE;
    }
    buf_list_size = sizeof(CpaBufferList) + sizeof(CpaFlatBuffer) * buf_num;

    if (!qat_dev->meta_buf_size) {
        CpaStatus status;
        CpaInstanceHandle instance_handle =
                          qat_dev->instances[0].instance_handle;

        status = cpaDcBufferListGetMetaSize(instance_handle, 1,
                                            &meta_buf_size);
        if (status != CPA_STATUS_SUCCESS) {
            qemu_log("%s: fail to get memory size for meta data\n", __func__);
            return NULL;
        }
        qat_dev->meta_buf_size = meta_buf_size;
    } else {
        meta_buf_size = qat_dev->meta_buf_size;
    }

    buf_list = g_malloc0(buf_list_size);
    if (!buf_list) {
        qemu_log("%s: unable to alloc buf list\n", __func__);
        return NULL;
    }

    meta_buf = qaeMemAllocNUMA(meta_buf_size, nodeid, 64); //BYTE_ALIGNMENT_64
    if (!meta_buf) {
        qemu_log("%s: unable to alloc src_meta_buf \n", __func__);
        goto err_free_buf_list;
    }

    flat_buf = (CpaFlatBuffer *)(buf_list + 1);
    while (bytes > 0) {
        if (bytes < TARGET_PAGE_SIZE) {
            buf_size = bytes;
        } else {
            buf_size = TARGET_PAGE_SIZE;
        }

        flat_buf[i].pData = qaeMemAllocNUMA(buf_size, nodeid, 64);
        if (!flat_buf[i].pData) {
            qemu_log("%s: unable to alloc src buf \n", __func__);
            goto err_free_meta_buf;
        }
        flat_buf[i++].dataLenInBytes = buf_size;
        bytes -= buf_size;
    }

    if (bytes && (i != buf_num)) {
        qemu_log("%s: unmatched buf num \n", __func__);
    }

    buf_list->pPrivateMetaData = meta_buf;
    buf_list->pBuffers = flat_buf;
    buf_list->numBuffers = buf_num;

    return buf_list;
err_free_buf_list:
    g_free(buf_list);
err_free_meta_buf:
    qaeMemFreeNUMA((void **)&meta_buf);
    return NULL;
}

/* Set how many bytes are valid for qat to do compression */
static void qat_buf_list_set_valid_bytes(CpaBufferList *buf_list, int bytes)
{
    CpaFlatBuffer *flat_buf;
    int i, buf_num;

    if (!bytes) {
        return;
    }

    buf_num = QEMU_ALIGN_UP(bytes, TARGET_PAGE_SIZE) / TARGET_PAGE_SIZE;
    flat_buf = (CpaFlatBuffer *)(buf_list + 1);
    for (i = 0; i < buf_num; i++) {
        flat_buf[i].dataLenInBytes = TARGET_PAGE_SIZE;
    }
    if (bytes % TARGET_PAGE_SIZE)
        flat_buf[buf_num - 1].dataLenInBytes = bytes % TARGET_PAGE_SIZE;
    buf_list->numBuffers = buf_num;
}

static void qat_buf_list_set_bufs_from_mpa(CpaBufferList *buf_list,
                                           unsigned long addr_base,
                                           MultiPageAddr *mpa)
{
    int i, j, n = 0;
    unsigned long start, offset, addr, pages;
    CpaFlatBuffer *flat_buf;

    flat_buf = (CpaFlatBuffer *)(buf_list + 1);

    for (i = 0; i < mpa->last_idx; i++) {
        start = multi_page_addr_get_one(mpa, i);
        pages = start & (~TARGET_PAGE_MASK);
        start >>= TARGET_PAGE_BITS;
        for (j = 0; j < pages; j++) {
            offset = (start + j) << TARGET_PAGE_BITS;
            addr = addr_base + offset;
            if (qat_dev->zero_copy) {
                flat_buf[n].pData = (uint8_t *)(addr);
            } else {
                memcpy(flat_buf[n].pData, (uint8_t *)(addr), TARGET_PAGE_SIZE);
            }
            flat_buf[n++].dataLenInBytes = TARGET_PAGE_SIZE;
        }
    }

    buf_list->numBuffers = mpa->pages;
    buf_list->pBuffers = flat_buf;
}

static void qat_buf_list_free(CpaBufferList *buf_list)
{
    CpaFlatBuffer *flat_buf;
    uint32_t i;

    if (!buf_list) {
        return;
    }

    if (buf_list->pPrivateMetaData) {
        qaeMemFreeNUMA((void **)&buf_list->pPrivateMetaData);
    }

    flat_buf = buf_list->pBuffers;
    if (!flat_buf) {
        return;
    }

    if (!qat_dev->zero_copy) {
        for (i = 0; i < buf_list->numBuffers; i++) {
            if (!flat_buf[i].pData) {
                continue;
            }
            qaeMemFreeNUMA((void **)&flat_buf[i].pData);
        }
    }

    g_free(buf_list);
}

static void qat_instance_req_free(QatReq *req)
{
    QatInstance *instance = req->instance;
    bool free_to_cache = false;

    qemu_spin_lock(&instance->lock);
    if (instance->req_cache_num < QAT_INSTANCE_REQ_CACHE_NUM) {
        QLIST_INSERT_HEAD(&instance->req_cache_list, req, node);
        instance->req_cache_num++;
        free_to_cache = true;
    }
    qemu_spin_unlock(&instance->lock);

    if (!free_to_cache) {
        qat_buf_list_free(req->src_buf_list);
        qat_buf_list_free(req->dst_buf_list);
        g_free(req);
    }
}

static QatReq *qat_instance_req_alloc_cache(QatInstance *instance)
{
    QatReq *req;

    qemu_spin_lock(&instance->lock);
    if (!instance->req_cache_num) {
        qemu_spin_unlock(&instance->lock);
        return NULL;
    }

    req = QLIST_FIRST(&instance->req_cache_list);
    QLIST_REMOVE(req, node);
    instance->req_cache_num--;
    qemu_spin_unlock(&instance->lock);

    return req;
}

static QatReq *qat_instance_req_alloc_slow(QatInstance *instance,
                                           unsigned long src_bytes,
                                           unsigned long dst_bytes)
{
    QatReq *req;
    CpaBufferList *src_buf_list, *dst_buf_list;

    req = g_malloc0(sizeof(QatReq));
    src_buf_list = qat_buf_list_alloc(instance->node_affinity, src_bytes);
    if (!src_buf_list) {
        goto err_src;
    }

    dst_buf_list = qat_buf_list_alloc(instance->node_affinity, dst_bytes);
    if (!dst_buf_list) {
        goto err_dst;
    }

    req->src_buf_list = src_buf_list;
    req->dst_buf_list = dst_buf_list;
    req->instance = instance;

    return req;
err_dst:
    qat_buf_list_free(src_buf_list);
err_src:
    g_free(req);
    qemu_log("%s: fail to alloc a qat req \n", __func__);
    return NULL;
}

static QatReq *qat_instance_req_alloc(QatInstance *instance,
                                      unsigned long src_bytes,
                                      unsigned long dst_bytes)
{
    QatReq *req;

    req = qat_instance_req_alloc_cache(instance);
    if (!req) {
        qemu_log("%s debug: req cache not enough \n", __func__);
        req = qat_instance_req_alloc_slow(instance, src_bytes,
                                          dst_bytes);
    }

    if (!req) {
        return NULL;
    }

    qat_buf_list_set_valid_bytes(req->src_buf_list, src_bytes);
    qat_buf_list_set_valid_bytes(req->dst_buf_list, dst_bytes);

    return req;
}

static void compress_callback(void *pCallbackTag, CpaStatus status)
{
    QatReq *req = (QatReq *)pCallbackTag;
    CpaBufferList *buf_list;
    CpaDcRqResults *result;
    uint32_t bytes, i = 0;

    if (req == NULL)
    {
        qemu_log("%s: Compression with NULL request ptr \n", __func__);
        return;
    }

    if (status != CPA_STATUS_SUCCESS)
    {
        qemu_log("%s: Compression failed with status %x, ram addr=%lx \n",
                  __func__, status, req->offset);
        return;
    }

    buf_list = req->dst_buf_list;
    result = &req->result;
    if ((result->status != CPA_DC_OK) &&
        (result->status == CPA_DC_OVERFLOW)) {
        qat_dev->overflow++;
        save_uncompressed_page(req->block, &req->mpa);
    } else {
        save_compressed_page_header(req->block,
                                    &req->mpa,
                                    (uint64_t)result->produced,
                                    result->checksum);
        for (i = 0; i * TARGET_PAGE_SIZE < result->produced; i++) {
            if ((i + 1) * TARGET_PAGE_SIZE > result->produced) {
                bytes = result->produced - (i * TARGET_PAGE_SIZE);
            } else {
                bytes = TARGET_PAGE_SIZE;
            }
            save_compressed_data((void *)buf_list->pBuffers[i].pData, bytes);
        }
        compression_counters.compressed_size += result->produced;
        compression_counters.pages += req->mpa.pages;
    }

    qat_instance_req_free(req);
    qat_dev->responses++;
    qat_dev->consumed_bytes += result->consumed;
    qat_dev->produced_bytes += result->produced;
}

static void decompress_copy_to_guest_memory(QatReq *req)
{
    MultiPageAddr *mpa = &req->mpa;
    CpaBufferList *buf_list = req->dst_buf_list;
    unsigned long start, pages;
    uint8_t *dst_buf;
    int i, j, n = 0;

    for (i = 0; i < mpa->last_idx; i++) {
        start = multi_page_addr_get_one(&req->mpa, i);
        pages = start & (~TARGET_PAGE_MASK);
        start &= TARGET_PAGE_MASK;
        for (j = 0; j < pages; j++) {
            dst_buf = req->block->host + start + (j << TARGET_PAGE_BITS);
            memcpy(dst_buf, buf_list->pBuffers[n++].pData, TARGET_PAGE_SIZE);
        }
    }
}

static void decompress_callback(void *pCallbackTag, CpaStatus status)
{
    QatReq *req = (QatReq *)pCallbackTag;
    MultiPageAddr *mpa = &req->mpa;
    CpaDcRqResults *result;

    if (req == NULL)
    {
        qemu_log("%s: Compression with NULL request ptr \n", __func__);
        return;
    }

    if (status != CPA_STATUS_SUCCESS)
    {
        qemu_log("%s: Decompression failed with status %d, ram addr=%lx, req->id=%ld \n",
                  __func__, status, req->offset, req->id);
    }

    result = &req->result;
    if (result->checksum != req->checksum) {
        qemu_log("%s: error, checksum unmatch \n", __func__);
    }

    if ((result->status != CPA_DC_OK) &&
        (result->status == CPA_DC_OVERFLOW)) {
            qemu_log("%s: Compress result not as expected = %d\n", __func__,
                     result->status);
            qemu_log("%s: consumed=%d produced=%d\n", __func__,
                                          result->consumed, result->produced);
            return;
    }

    if (result->produced != mpa->pages * TARGET_PAGE_SIZE) {
        qemu_log("%s: unmatched, result->consumed=%d, result->produced=%d, mpa->pages=%ld\n",
                 __func__, result->consumed, result->produced, mpa->pages);
    }

    if (!qat_dev->zero_copy) {
        decompress_copy_to_guest_memory(req);
    }

    qat_instance_req_free(req);
    qat_dev->responses++;
    qat_dev->consumed_bytes += result->consumed;
    qat_dev->produced_bytes += result->produced;
}

static int qat_instance_session_setup(QatInstance *instance, QatSetupType type)
{
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaDcInstanceCapabilities cap = {0};
    CpaDcSessionHandle session_handle = NULL;
    Cpa32U session_size = 0, ctx_size = 0;
    CpaBufferList *ctx_buf_list = NULL;
    CpaDcSessionSetupData sd = { 0 };
    CpaDcCallbackFn session_callback;
    CpaStatus status;

    sd.compLevel = migrate_compress_level();
    sd.compType = CPA_DC_DEFLATE;
    sd.huffType = CPA_DC_HT_FULL_DYNAMIC;
    sd.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
    sd.sessState = CPA_DC_STATELESS;
#if (CPA_DC_API_VERSION_NUM_MAJOR == 1 && CPA_DC_API_VERSION_NUM_MINOR < 6)
    sd.deflateWindowSize = 7;
#endif
    sd.checksum = CPA_DC_CRC32;
    if (type == QAT_SETUP_COMPRESS) {
        sd.sessDirection = CPA_DC_DIR_COMPRESS;
        session_callback = compress_callback;
    } else {
        sd.sessDirection = CPA_DC_DIR_DECOMPRESS;
        session_callback = decompress_callback;
    }

    status = cpaDcQueryCapabilities(instance_handle, &cap);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to get cap \n", __func__);
        return -1;
    }
    if (!cap.checksumCRC32 || !cap.compressAndVerify) {
        qemu_log("%s: checksum isn't supported \n", __func__);
        return -1;
    }

    status = cpaDcGetSessionSize(instance_handle,
                                 &sd,
                                 &session_size,
                                 &ctx_size);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to get session size \n", __func__);
        return -1;
    }

    session_handle = qaeMemAllocNUMA(session_size + ctx_size,
                                     instance->node_affinity, 64);
    if (!session_handle) {
        qemu_log("%s: fail to alloc session handle \n", __func__);
        return -1;
    }

    if (ctx_size) {
        ctx_buf_list = qat_buf_list_alloc(instance->node_affinity, ctx_size);
        if (!ctx_buf_list) {
            qemu_log("%s: fail to alloc ctx_buf_list \n", __func__);
            goto err_free_session_handle;
        }
    }

    status = cpaDcInitSession(instance_handle, session_handle, &sd,
                              ctx_buf_list, session_callback);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to init session \n", __func__);
        goto err_free_ctx_buf_list;
    }
    instance->session_ctx_buf_list = ctx_buf_list;
    instance->session_handle = session_handle;
    qemu_log("%s: sd.compLevel=%d \n", __func__, sd.compLevel);
    return 0;
err_free_ctx_buf_list:
    qat_buf_list_free(ctx_buf_list);
err_free_session_handle:
    qaeMemFreeNUMA((void **)&session_handle);
    return -1;
}

static int qat_instance_add_to_epoll(QatInstance *instance)
{
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaStatus status;
    struct epoll_event event;
    int fd, ret;

    status = icp_sal_DcGetFileDescriptor(instance_handle, &fd);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to get instance poll fd\n", __func__);
        return -1;
    }

    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(qat_dev->efd, EPOLL_CTL_ADD, fd, &event);
    if (ret < 0) {
        qemu_log("%s: fail to add to epoll list, ret=%d\n", __func__, ret);
        return -1;
    }
    instance->fd = fd;

    return 0;
}

static int qat_instance_intermediate_buf_setup(QatInstance *instance)
{
    uint16_t i, buf_num;
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaStatus status;

    status = cpaDcGetNumIntermediateBuffers(instance_handle, &buf_num);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: unable to get intermediate buf num \n", __func__);
        return -1;
    }
    instance->intermediate_buf_list =
                           g_malloc0(buf_num * sizeof(CpaBufferList *));
    instance->intermediate_buf_num = buf_num;

    for (i = 0; i < buf_num; i++) {
        instance->intermediate_buf_list[i] =
                  qat_buf_list_alloc(instance->node_affinity, QAT_REQ_BUF_SIZE * 2);
    }

    return 0;
}

static void qat_instance_intermediate_buf_cleanup(QatInstance *instance)
{
    uint16_t i;

    for (i = 0; i < instance->intermediate_buf_num; i++) {
        qat_buf_list_free(instance->intermediate_buf_list[i]);
    }
    g_free(instance->intermediate_buf_list);
}

static int qat_poll_instances(void)
{
    CpaStatus status;
    QatInstance *instance;
    uint16_t i, instance_num = qat_dev->instance_num;

    for (i = 0; i < instance_num; i++) {
        instance = &qat_dev->instances[i];
        status = icp_sal_DcPollInstance(instance->instance_handle, 1);
        if ((status != CPA_STATUS_SUCCESS) &&
            (status != CPA_STATUS_RETRY)) {
            qemu_log("%s: fail to poll instance, i = %d, status=%d \n",
                     __func__, i, status);
            continue;
        }
    }

    return 0;
}

static void qat_poll_instances_all(void)
{
    uint64_t responses;

    /* Continue to poll all the instances until no responses are obtained */
    do {
        responses = qat_dev->responses;
        qat_poll_instances();
    } while (responses != qat_dev->responses);
}

static void *qat_epoll_thread_run(void *arg)
{

    int efd = qat_dev->efd;
    int maxevents = (int)qat_dev->instance_num;
    struct epoll_event *events =
                       g_malloc0(sizeof(struct epoll_event) * maxevents);

    while (epoll_thread_running) {
        qat_poll_instances_all();
        epoll_wait(efd, events, maxevents, 100);
    }

    g_free(events);
    return NULL;
}

static int qat_create_epoll_thread(void)
{
    int efd = 0, ret;
    cpu_set_t cpuset;

    efd = epoll_create1(0);
    if (efd < 0) {
        qemu_log("%s: fail to create epoll fd \n", __func__);
        return -1;
    }
    qat_dev->efd = efd;
    epoll_thread_running = true;
    qemu_thread_create(&qat_dev->epoll_thread, "qat_epoll_thread",
                       qat_epoll_thread_run, qat_dev, QEMU_THREAD_JOINABLE);
    CPU_ZERO(&cpuset);
    CPU_SET(20, &cpuset);
    ret = pthread_setaffinity_np(qat_dev->epoll_thread.thread,
                                 sizeof(cpu_set_t), &cpuset);
    if (ret != 0) {
        qemu_log("%s: fail to set affinity \n", __func__);
        return -1;
    }

    return 0;
}

static QatInstance *qat_select_instance_rr(void)
{
    qat_dev->rr_instance_id =
            (qat_dev->rr_instance_id + 1) % qat_dev->instance_num;

    return &qat_dev->instances[qat_dev->rr_instance_id];
}

static CpaStatus qat_submit_compress_req(QatInstance *instance, QatReq *req)
{
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaDcSessionHandle session_handle = instance->session_handle;
    CpaStatus status;

    req->result.checksum = 0;
    status = cpaDcCompressData(instance_handle,
                               session_handle,
                               req->src_buf_list,
                               req->dst_buf_list,
                               &req->result,
                               CPA_DC_FLUSH_FINAL,
                               req);
    if (status == CPA_STATUS_RETRY) {
        qemu_log("%s: retry, instance_id=%d, qat_dev->requests=%ld, qat_dev->responses=%ld\n",
                 __func__, qat_dev->rr_instance_id, qat_dev->requests, qat_dev->responses);
    }

    return status;
}

static CpaStatus qat_submit_decompress_req(QatInstance *instance, QatReq *req)
{
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaDcSessionHandle session_handle = instance->session_handle;
    CpaStatus status;

    req->result.checksum = 0;
    status = cpaDcDecompressData(instance_handle,
                                 session_handle,
                                 req->src_buf_list,
                                 req->dst_buf_list,
                                 &req->result,
                                 CPA_DC_FLUSH_FINAL,
                                 req);
    if (status == CPA_STATUS_RETRY) {
        qemu_log("%s: retry, instance_id=%d, qat_dev->requests=%ld, qat_dev->responses=%ld\n",
                 __func__, qat_dev->rr_instance_id, qat_dev->requests, qat_dev->responses);
    }

    return status;
}

static QatReq *qat_get_compress_req(QatInstance *instance,
                                    RAMBlock *block,
                                    MultiPageAddr *mpa)
{
    QatReq *req;
    unsigned long src_bytes = qat_dev->zero_copy ? 0: QAT_REQ_BUF_SIZE;

    req = qat_instance_req_alloc(instance, src_bytes, QAT_REQ_BUF_SIZE);
    if (!req) {
        return NULL;
    }
    req->block = block;
    req->offset = multi_page_addr_get_one(mpa, 0);

    qat_buf_list_set_bufs_from_mpa(req->src_buf_list,
                                   (unsigned long)block->host, mpa);
    memcpy(&req->mpa, mpa, sizeof(MultiPageAddr));

    return req;
}

static QatReq *qat_get_decompress_req(QatInstance *instance,
                                      QEMUFile *f,
                                      RAMBlock *block,
                                      int src_bytes,
                                      MultiPageAddr *mpa)
{
    QatReq *req;
    int n = 0, buf_size;
    unsigned long dst_bytes = qat_dev->zero_copy ? 0: QAT_REQ_BUF_SIZE;

    req = qat_instance_req_alloc(instance, src_bytes, dst_bytes);
    if (!req) {
        return NULL;
    }
    req->block = block;
    req->offset = multi_page_addr_get_one(mpa, 0);
    qat_buf_list_set_bufs_from_mpa(req->dst_buf_list,
                                   (unsigned long)block->host, mpa);

    while (src_bytes) {
        if (src_bytes >= TARGET_PAGE_SIZE) {
            buf_size = TARGET_PAGE_SIZE;
        } else {
            buf_size = src_bytes;
        }
        qemu_get_buffer(f, req->src_buf_list->pBuffers[n++].pData, buf_size);
        src_bytes -= buf_size;
    }
    memcpy(&req->mpa, mpa, sizeof(MultiPageAddr));

    return req;
}

int qat_compress_page(RAMBlock *block, MultiPageAddr *mpa)
{
    QatReq *req;
    QatInstance *instance;
    CpaStatus status;

    if (!qat_dev->consumed_bytes)
        qat_dev->start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    qat_dev->requests++;
    instance = qat_select_instance_rr();
    req = qat_get_compress_req(instance, block, mpa);

    if (req == NULL) {
	qat_dev->requests--;
	qemu_log("%s: qat get NULL request ptr for compression! \n", __func__);
	return -1;
    }

    req->id = qat_dev->requests;

    do {
        status = qat_submit_compress_req(instance, req);
        if ((status != CPA_STATUS_SUCCESS) && (status != CPA_STATUS_RETRY)) {
            qemu_log("%s: requests=%ld, fail to compress, status=%d \n",
                     __func__, qat_dev->requests, status);
            qat_instance_req_free(req);
            qat_dev->requests--;
            return -1;
        }
    } while (status == CPA_STATUS_RETRY);

    return 0;
}

int qat_decompress_page(QEMUFile *f, RAMBlock *block, int bytes,
                        MultiPageAddr *mpa, uint32_t checksum)
{
    QatReq *req;
    CpaStatus status;
    QatInstance *instance;

    if (!qat_dev->consumed_bytes)
        qat_dev->start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    if (!block || !bytes) {
        qemu_log("%s: invalid param, block=%p, bytes=%d \n",
                 __func__, block, bytes);
        return -1;
    }

    qat_dev->requests++;
    instance = qat_select_instance_rr();

    req = qat_get_decompress_req(instance, f, block, bytes, mpa);
    if (!req) {
        qemu_log("%s: fail to get a req \n", __func__);
        return -1;
    }
    req->id = qat_dev->requests;
    req->checksum = checksum;

    do {
        status = qat_submit_decompress_req(instance, req);
        if ((status != CPA_STATUS_SUCCESS) && (status != CPA_STATUS_RETRY)) {
            qemu_log("%s: requests=%ld, fail to decompress, status=%d \n",
                     __func__, qat_dev->requests, status);
            qat_instance_req_free(req);
            return -1;
        }
    } while (status == CPA_STATUS_RETRY);

    return 0;
}

static void qat_instance_req_cache_list_cleanup(QatInstance *instance)
{
    QatReq *req;

    qemu_spin_lock(&instance->lock);
    QLIST_FOREACH(req, &instance->req_cache_list, node) {
        QLIST_REMOVE(req, node);
        qat_buf_list_free(req->src_buf_list);
        qat_buf_list_free(req->dst_buf_list);
        g_free(req);
        instance->req_cache_num--;
    }
    qemu_spin_unlock(&instance->lock);

    /* Sanity check */
    if (instance->req_cache_num) {
        qemu_log("%s: req_cache_num incorrect \n", __func__);
    }
}

static int qat_instance_req_cache_list_setup(QatInstance *instance,
                                             unsigned long src_bytes,
                                             unsigned long dst_bytes)
{
    int i;
    QatReq *req;

    instance->req_cache_num = 0;
    qemu_spin_init(&instance->lock);
    QLIST_INIT(&instance->req_cache_list);

    for (i = 0; i < QAT_INSTANCE_REQ_CACHE_NUM; i++) {
        req = qat_instance_req_alloc_slow(instance, src_bytes, dst_bytes);
        if (!req) {
            qemu_log("%s: req pre-alloc failed \n", __func__);
            return -1;
        }

        qemu_spin_lock(&instance->lock);
        QLIST_INSERT_HEAD(&instance->req_cache_list, req, node);
        instance->req_cache_num++;
        qemu_spin_unlock(&instance->lock);
    }

    return 0;
}

static int qat_instance_setup(QatInstance *instance, QatSetupType type)
{
    unsigned long src_bytes, dst_bytes;
    CpaInstanceInfo2 instance_info;
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaStatus status;

    status = cpaDcInstanceGetInfo2(instance_handle, &instance_info);
    if (status != CPA_STATUS_SUCCESS)
    {
        qemu_log("%s fail to get instance info \n", __func__);
        return -1;
    }
    instance->node_affinity = instance_info.nodeAffinity;

    if (type == QAT_SETUP_DECOMPRESS) {
        src_bytes = QAT_REQ_BUF_SIZE;
        dst_bytes = qat_dev->zero_copy ? 0: QAT_REQ_BUF_SIZE;
    } else {
        src_bytes = qat_dev->zero_copy ? 0: QAT_REQ_BUF_SIZE;
        dst_bytes = QAT_REQ_BUF_SIZE;
    }
    status = cpaDcSetAddressTranslation(instance_handle, qat_virt_to_phy);

    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: unable to set address translation \n", __func__);
        return -1;
    }

    if (qat_instance_intermediate_buf_setup(instance) < 0) {
        return -1;
    }

    status = cpaDcStartInstance(instance_handle,
                                instance->intermediate_buf_num,
                                instance->intermediate_buf_list);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to start\n", __func__);
        return -1;
    }

    if (qat_instance_session_setup(instance, type) < 0)
        return -1;

    if (qat_instance_add_to_epoll(instance) < 0)
        return -1;

    if (qat_instance_req_cache_list_setup(instance, src_bytes, dst_bytes) < 0)
        return -1;

    return 0;
}

static void qat_instance_cleanup(QatInstance *instance)
{
    CpaBufferList *ctx_buf_list = instance->session_ctx_buf_list;
    CpaDcSessionHandle session_handle = instance->session_handle;
    CpaInstanceHandle instance_handle = instance->instance_handle;
    CpaStatus status;

    qat_instance_intermediate_buf_cleanup(instance);
    qat_instance_req_cache_list_cleanup(instance);

    /* Close the DC Session */
    status = cpaDcRemoveSession(instance_handle, session_handle);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to remove session, status=%d\n", __func__, status);
        return;
    }

    status = cpaDcStopInstance(instance_handle);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: fail to remove session, status=%d\n", __func__, status);
        return;
    }

    if (ctx_buf_list) {
        qat_buf_list_free(ctx_buf_list);
    }
    qaeMemFreeNUMA((void **)&session_handle);
}

int qat_setup(QatSetupType type)
{
    uint16_t instance_num;
    int ret, processNum, i = -1;
    CpaInstanceHandle *instance_handles;
    CpaStatus status;
    char ProcessNamePrefix[] = "SSL";
    char ProcessName[10] = "\0";

    if (type >= QAT_SETUP_MAX)
        return -1;

    qemu_log("%s: start \n", __func__);
    osalLogLevelSet(OSAL_LOG_LVL_ALL);

    status = qaeMemInit();
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: unable to init qaeMEM\n", __func__);
        return -1;
    }

    for (processNum = 0; processNum < MAX_PROCESS_NUM; processNum++) {
	sprintf(ProcessName, "%s%d", ProcessNamePrefix, processNum);
	qemu_log("%s: processnum = %d, processName = %s\n", __func__, processNum, ProcessName);
	status = icp_sal_userStart(processNum ? ProcessName : ProcessNamePrefix);
	if (status == CPA_STATUS_SUCCESS) {
		qemu_log("%s:sal user start SSL%d\n", __func__, processNum);
		break;
	}
    }

    if ( processNum == MAX_PROCESS_NUM && status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: unable to start SAL, status=%d\n", __func__, status);
        return -1;
    }

    qat_dev = g_malloc0(sizeof(QatDev));
    qat_dev->zero_copy = migrate_qat_zero_copy();
    status = cpaDcGetNumInstances(&instance_num);
    if (status != CPA_STATUS_SUCCESS || !instance_num) {
        qemu_log("%s: no qat instance available \n", __func__);
        goto err_free_qat_dev;
    }
    qat_dev->instance_num = instance_num;

    instance_handles = g_malloc0(sizeof(CpaInstanceHandle) * instance_num);
    qat_dev->instances = g_malloc0(sizeof(QatInstance) * instance_num);
    status = cpaDcGetInstances(instance_num, instance_handles);
    if (status != CPA_STATUS_SUCCESS) {
        qemu_log("%s: unable to get instance handles \n", __func__);
        goto err_free_qat_dev;
    }

    ret = qat_create_epoll_thread();
    if (ret) {
        goto err_instance_cleanup;
    }

    for (i = 0; i < instance_num; i++) {
        qat_dev->instances[i].id = i;
        qat_dev->instances[i].instance_handle = instance_handles[i];
        ret = qat_instance_setup(&qat_dev->instances[i], type);
        if (ret) {
            goto err_instance_cleanup;
        }
    }
    qat_dev->consumed_bytes = 0;
    qat_dev->produced_bytes = 0;

    qemu_log("%s: instance_num=%d, zero_copy=%d \n", __func__, instance_num, qat_dev->zero_copy);
    return 0;
err_instance_cleanup:
    while (i >= 0) {
        qat_instance_cleanup(&qat_dev->instances[i]);
	i--;
    }
    g_free(instance_handles);
    g_free(qat_dev->instances);
err_free_qat_dev:
    g_free(qat_dev);
    return -1;
}

void qat_cleanup(void)
{
    if (!qat_dev)
	return;

    while (qat_dev->responses != qat_dev->requests) {
        qemu_log("%s: cleanup waiting for requests done! \n", __func__);
        cpu_relax();
    }

    epoll_thread_running = false;
    qemu_thread_join(&qat_dev->epoll_thread);
    qemu_log("%s: requests=%ld, responses=%ld, overflow=%ld \n",
             __func__, qat_dev->requests, qat_dev->responses,
             qat_dev->overflow);
    close(qat_dev->efd);

    while (qat_dev->instance_num) {
        qat_instance_cleanup(&qat_dev->instances[--qat_dev->instance_num]);
    }
    g_free(qat_dev->instances);
    g_free(qat_dev);

    icp_sal_userStop();
    qaeMemDestroy();
}
