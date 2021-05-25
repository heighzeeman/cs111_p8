
#include "fsops.hh"

namespace {

inline Tx
begin(const Ref<Inode> &ip)
{
    return ip->fs().begin();
}

inline Tx
begin(const Dirent &de)
{
    return begin(de.dir_);
}

} // anonymous namespace

int
null_inode_permissions(const Inode *)
{
    return 7;
}

int
fs_named(Dirent *out, Ref<Inode> ip, std::string path, int flags,
         inode_permissions access)
try {
    assert(!(flags & ND_CREATE) || &ip->fs().log_ || ip->fs().log_->in_tx_);

    std::vector<std::string> cs = path_components(path);
    if (cs.empty())
        cs.push_back(".");

    std::string name = std::move(cs.back());
    if (name.size() > sizeof(direntv6::d_name))
        return -ENAMETOOLONG;
    cs.pop_back();
    if ((flags & (ND_DOT_OK|ND_CREATE)) != ND_DOT_OK &&
        (name == "." || name == ".."))
        return -EINVAL;

    for (auto i = cs.begin();; ++i) {
        if ((ip->i_mode & IFMT) != IFDIR)
            return -ENOTDIR;
        if (!(access(ip.get()) & 1))
            return -EACCES;
        if (i == cs.end())
            break;
        if (Dirent de = ip->lookup(*i))
            ip = ip->fs().iget(de.inum());
        else
            return -ENOENT;
    }

    int perm = access(ip.get());
    if (!(perm & 1))
        return -EACCES;

    Dirent de;
    if ((perm & 2) && (flags & ND_CREATE))
        de = ip->create(name);
    else
        de = ip->lookup(name);
    if (!de)
        return -ENOENT;
    if ((flags & ND_EXCLUSIVE) && de.inum())
        return -EEXIST;
    *out = de;
    return 0;
}
 catch(const resource_exhausted &e) {
     return e.error;
 }

int
fs_mknod(Dirent where, inode_initializer init)
try {
    if (where.inum())
        return -EEXIST;

    Ref<Inode> ip = where.fs().ialloc();
    Tx _tx = begin(where);
    ip->i_mode = IALLOC;
    ip->i_nlink = 1;
    ip->atouch();
    ip->mtime(ip->atime());
    if (init) {
        init(ip.get());
        ip->i_mode |= IALLOC;
    }
    else
        ip->i_mode |= 0666;
    ip->fs().patch(ip->raw());
    where.set_inum(ip->inum());
    return 0;
}
 catch(const resource_exhausted &e) {
     return e.error;
 }

int
fs_mkdir(Dirent where, inode_initializer init)
try {
    if (where.inum())
        return -EEXIST;
    if (where.dir_->i_nlink >= 255)
        return -EFBIG;

    Ref<Inode> ip = where.fs().ialloc();
    Tx _tx = begin(where);
    ip->i_mode = IFDIR | IALLOC;
    ip->i_nlink = 2;
    ip->atouch();
    ip->mtime(ip->atime());
    if (init) {
        init(ip.get());
        ip->i_mode = (ip->i_mode & ~IFMT) | IFDIR | IALLOC;
    }
    else
        ip->i_mode |= 0777;
    where.set_inum(ip->inum());
    ip->create(".").set_inum(ip->inum());
    ip->create("..").set_inum(where.dir_->inum());
    ip->fs().patch(ip->raw());
    where.dir_->fs().patch(++where.dir_->i_nlink);
    return 0;
}
 catch(const resource_exhausted &e) {
     return e.error;
 }

int
fs_rmdir(Dirent where)
try {
    if (!where.inum())
        return -ENOENT;
    V6FS &fs = where.fs();
    Ref<Inode> ip = fs.iget(where.inum());
    if ((ip->i_mode & IFMT) != IFDIR)
        return -ENOTDIR;

    {
        Cursor c(ip);
        for (direntv6 *d = c.next<direntv6>(); d; d = c.next<direntv6>())
            if (d->d_inumber && d->name() != "." && d->name() != "..")
                return -ENOTEMPTY;
    }

    // Truncation might need two buffers for an indirect and a direct block
    if (!fs.cache_.b.can_alloc(2))
        return -ENOMEM;
    Tx _tx = begin(where);
    where.set_inum(0);
    fs.patch(--where.dir_->i_nlink);
    where.dir_->mtouch();
    ip->clear();
    fs.ifree(ip->inum());
    return 0;
}
 catch(const resource_exhausted &e) {
     return e.error;
 }

int
fs_link(Dirent oldde, Dirent newde)
try {
    if (!oldde.inum())
        return -ENOENT;
    if (newde.inum())
        return -EEXIST;
    Ref<Inode> ip = oldde.fs().iget(oldde.inum());
    if (ip->i_nlink >= 255)
        return -EFBIG;

    Tx _tx = begin(ip);
    ip->mtouch();
    ip->fs().patch(++ip->i_nlink);
    newde.set_inum(oldde.inum());
    return 0;
}
 catch(const resource_exhausted &e) {
     return e.error;
 }

int
fs_unlink(Dirent where)
try {
    if (!where.inum())
        return -ENOENT;
    Ref<Inode> ip = where.fs().iget(where.inum());
    Tx _tx = begin(where);
    where.set_inum(0);
    if (ip->i_nlink > 1)
        ip->fs().patch(--ip->i_nlink);
    else
        ip->clear();
    return 0;
}
 catch(const resource_exhausted &e) {
     return e.error;
 }
