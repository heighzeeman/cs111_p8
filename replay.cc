
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "replay.hh"
#include "v6fs.hh"

#include <stdexcept>

V6Replay::V6Replay(V6FS &fs)
    : fs_(fs), r_(fs_.fd_),
      freemap_(fs_.superblock().s_fsize, fs_.superblock().datastart())
{
    read_loghdr(fs_.fd_, &hdr_, fs_.superblock().s_fsize);
    if (pread(fs.fd_, freemap_.data(), freemap_.datasize(),
              hdr_.mapstart() * SECTOR_SIZE) == -1)
        threrror("pread");
    freemap_.tidy();
    sequence_ = hdr_.l_sequence;
    r_.seek(hdr_.l_checkpoint);
}

void
V6Replay::apply(const LogBegin &e)
{
    // Nothing to do here
}

void
V6Replay::apply(const LogPatch &e)
{
    Ref<Buffer> contents = fs_.bread(e.blockno);
	uint16_t offset = e.offset_in_block;
	const std::vector<uint8_t>& toWrite = e.bytes;
	
	for (size_t i = 0; i < toWrite.size(); i++) {
		if (i >= SECTOR_SIZE) throw std::runtime_error("Out of bounds LogPatch at i = " + std::to_string(i) + "\n");
		contents->mem_[offset + i] = toWrite[i];
	}
	
	contents->bdwrite();
}

void
V6Replay::apply(const LogBlockAlloc &e)
{
	if (freemap_.at(e.blockno) == false)
		throw std::runtime_error("Block: " + std::to_string(e.blockno) + " already allocated\n");
	freemap_.at(e.blockno) = false;
	
	if (e.zero_on_replay == 1) {
		Ref<Buffer> contents = fs_.bget(e.blockno);
		std::memset(contents->mem_, 0, SECTOR_SIZE);
		contents->bdwrite();
	}
}

void
V6Replay::apply(const LogBlockFree &e)
{
    if (freemap_.at(e.blockno) == true)
		throw std::runtime_error("Block: " + std::to_string(e.blockno) + " already free\n");
	freemap_.at(e.blockno) = true;
}

void
V6Replay::apply(const LogCommit &e)
{
    // Nothing to do here
}

void
V6Replay::apply(const LogRewind &e)
{
    // Note:  LogRewind is already handled specially by read_next(),
    // so this method never gets called.  We need the method to exist
    // because of how std::visit function works on std::variant.
}

void
V6Replay::read_next(LogEntry *out)
{
    auto load = [out,this]() {
        out->load(r_);
        if (out->sequence_ != sequence_)
            throw log_corrupt("bad sequence number");
        ++sequence_;
    };

    load();
    if (out->get<LogRewind>()) {
        r_.seek(hdr_.logstart() * SECTOR_SIZE);
        load();
    }
}

bool
V6Replay::check_tx()
{
    cleanup _c([this, start = r_.tell()]() { r_.seek(start); });
    lsn_t startseq = sequence_;

    try {
        LogEntry le;
        read_next(&le);
        if (!le.get<LogBegin>())
            throw log_corrupt("no LogBegin");
        lsn_t beginseq = le.sequence_;

        for (;;) {
            read_next(&le);
            if (LogCommit *c = le.get<LogCommit>()) {
                if (c->sequence != beginseq)
                    throw log_corrupt("begin/commit sequence mismatch");
                sequence_ = startseq;
                return true;
            }
        }
    }
    catch (const log_corrupt &e) {
        // Don't reset sequence to ensure checkpoint above existing LSNs
        std::cout << "Reached log end: " << e.what() << std::endl;
        return false;
    }
}

void
V6Replay::replay()
{
    LogEntry le;
    while (check_tx()) {
        do {
            read_next(&le);
            le.visit([this](const auto &e) { apply(e); });
        } while (!le.get<LogCommit>());
    }

    std::cout << "played log entries " << hdr_.l_sequence
              << " to " << sequence_ << std::endl;

    hdr_.l_sequence = sequence_;
    hdr_.l_checkpoint = r_.tell();
    if (pwrite(fs_.fd_, freemap_.data(), freemap_.datasize(),
               hdr_.mapstart() * SECTOR_SIZE) == -1)
        threrror("pwrite");
    fs_.writeblock(&hdr_, fs_.superblock().s_fsize);
    // We don't log inode allocations, so just force re-scan
    fs_.superblock().s_ninode = 0;
    fs_.superblock().s_fmod = 1;
    fs_.unclean_ = false;
}
