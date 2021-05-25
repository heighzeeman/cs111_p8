
#include "v6fs.hh"

void
Buffer::bwrite()
{
    if (fs().log_)
        fs().log_->flush();
    fs().writeblock(mem_, blockno());
    initialized_ = true;
    dirty_ = logged_ = false;
}
