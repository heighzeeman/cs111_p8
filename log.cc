
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <iostream>

#include "log.hh"
#include "util.hh"
#include "v6fs.hh"

uint32_t
rnd_uint32()
{
    static constexpr char rndpath[] = "/dev/urandom";
    int fd = open(rndpath, O_RDONLY);
    if (fd == -1)
        threrror(rndpath);
    uint32_t res;
    if (read(fd, &res, sizeof(res)) != sizeof(res)) {
        close(fd);
        threrror(rndpath);
    }
    close(fd);
    return res;
}

void
read_loghdr(int fd, loghdr *hdr, uint32_t blockno)
{
    if (pread(fd, hdr, sizeof(*hdr), blockno * SECTOR_SIZE) != sizeof(*hdr))
        threrror("pread");

    if (hdr->l_magic != LOG_MAGIC_NUM ||
        hdr->l_hdrblock != blockno ||
        hdr->l_checkpoint < hdr->logstart() * SECTOR_SIZE)
        throw log_corrupt("invalid log header");
}

Tx
V6Log::begin()
{
    if (in_tx_)
        return {};
    log(LogBegin{});
    begin_sequence_ = sequence_;
    begin_offset = w_.tell();
    in_tx_ = true;
    return Tx(this);
}

void
V6Log::log(LogEntry::entry_type e)
{
    static const uint32_t reserve = LogEntry(0, LogRewind{}).nbytes();

    LogEntry le(++sequence_, std::move(e));
    uint32_t pos = w_.tell();
    if (pos + reserve > hdr_.logend() * SECTOR_SIZE) {
        LogEntry(sequence_, LogRewind{}).save(w_);
        le.sequence_ = ++sequence_;
        w_.seek(hdr_.logstart() * SECTOR_SIZE);
    }

    le.save(w_);
}

uint16_t
V6Log::balloc_near(uint16_t near, bool metadata)
{
    if (fs_.badblock(near))
        near = fs_.superblock().datastart();
    int bn = freemap_.find1(near);
    if (bn < 0)
        return 0;
    freemap_.at(bn) = false;
    if (in_tx_)
        log(LogBlockAlloc{ uint16_t(bn), metadata });
    return bn;
}

void
V6Log::bfree(uint16_t blockno)
{
    assert(in_tx_);
    freed_.push_back(blockno);
    log(LogBlockFree{blockno});
}

void
V6Log::commit()
{
    log(LogCommit{begin_sequence_});
    for (uint16_t bn : freed_)
        freemap_.at(bn) = true;
    freed_.clear();
    in_tx_ = false;
    if (space() < hdr_.logbytes() / 2)
        checkpoint();
    else if (time(nullptr) > checkpoint_time_ + 30)
        checkpoint();
}

void
V6Log::flush()
{
    w_.flush();
    committed_ = in_tx_ ? begin_sequence_ : sequence_;
}

void
V6Log::checkpoint()
{
    assert(!in_tx_);

    hdr_.l_checkpoint = w_.tell();
    hdr_.l_sequence = sequence_ + 1;
    // Stick null transaction after checkpoint
    log(LogBegin{});
    log(LogCommit{sequence_});

    flush();
    fs_.sync();
    applied_ = committed_;

    std::vector<uint16_t> freed(std::move(freed_));
    freed_.clear();
    for (uint16_t bn : freed)
        freemap_.at(bn) = true;
    if (pwrite(fs_.fd_, freemap_.data(), freemap_.datasize(),
               hdr_.mapstart() * SECTOR_SIZE) == -1)
        threrror("pwrite");

    fs_.writeblock(&hdr_, hdr_.l_hdrblock);
    checkpoint_time_ = time(nullptr);
}

// Note it's a little weird that we are duping the file descriptor and
// sharing a seek offset with the V6FS code, but the V6FS only uses
// pread/pwrite, so this is okay.
V6Log::V6Log(V6FS &fs)
    : fs_(fs), w_(fs.fd_),
      freemap_(fs_.superblock().s_fsize, fs_.superblock().datastart())
{
    read_loghdr(fs_.fd_, &hdr_, fs_.superblock().s_fsize);
    applied_ = committed_ = sequence_ = hdr_.l_sequence;
    w_.seek(hdr_.l_checkpoint);
    if (pread(fs.fd_, freemap_.data(), freemap_.datasize(),
              hdr_.mapstart() * SECTOR_SIZE) == -1)
        threrror("pread");
    freemap_.tidy();
}

uint32_t
V6Log::space()
{
    const uint32_t pos = w_.tell();
    const uint32_t cp = hdr_.l_checkpoint;
    return cp >= pos ? cp - pos : hdr_.logbytes() - (pos - cp);
}

void
V6Log::create(V6FS &fs)
{
    filsys &sb = fs.superblock();

    loghdr lh;
    memset(&lh, 0, sizeof(lh));
    lh.l_magic = LOG_MAGIC_NUM;
    lh.l_hdrblock = sb.s_fsize;
    lh.l_mapsize = (sb.s_fsize - sb.datastart() + (8 * SECTOR_SIZE - 1)) /
        (8 * SECTOR_SIZE);
    lh.l_logsize = lh.l_mapsize + sb.s_fsize/128 + 8;
    lh.l_checkpoint = lh.logstart() * SECTOR_SIZE;
    lh.l_sequence = rnd_uint32();
    //lh.l_sequence = 1;

    if (ftruncate(fs.fd_, lh.l_hdrblock * SECTOR_SIZE) == -1 ||
        ftruncate(fs.fd_, lh.logend() * SECTOR_SIZE) == -1)
        threrror("ftruncate");

    Bitmap freemap(lh.l_mapsize * SECTOR_SIZE * 8);
    auto mark = [&freemap,ds=sb.datastart()](int i){
        freemap.at(i - ds) = true;
    };

    uint16_t bn = 0;
    for (int i = sb.s_nfree; --i > 0;)
        mark(sb.s_free[i]);
    if (sb.s_nfree > 0)
        bn = sb.s_free[0];
    while (bn) {
        mark(bn);
        Ref<Buffer> bp = fs.bread(bn);
        for (int i = 100; --i > 0;)
            mark(bp->at<uint16_t>(i));
        bn = bp->at<uint16_t>(0);
    }

    if (pwrite(fs.fd_, freemap.data(), freemap.datasize(),
               lh.mapstart() * SECTOR_SIZE) == -1)
        threrror("pwrite");
    fs.writeblock(&lh, lh.l_hdrblock);
    sb.s_uselog = 1;
    sb.s_nfree = 0;             // using free map now
    fs.writeblock(&fs.superblock(), SUPERBLOCK_SECTOR);
}