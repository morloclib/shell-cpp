#ifndef __MORLOC__SHELL_HPP__
#define __MORLOC__SHELL_HPP__

#include <string>
#include <vector>
#include <tuple>
#include <map>
#include <functional>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <poll.h>
#include <chrono>
#include <cerrno>
#include <regex>
#include <signal.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <fnmatch.h>
#include "mlccpptypes/prelude.hpp"

namespace fs = std::filesystem;

extern char** environ;


// ============================================================================
// Record structs
// ============================================================================

struct FileStat {
    int64_t size;
    int64_t mtime;
    int64_t atime;
    int64_t ctime;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    std::string owner;
    std::string group;
    uint64_t nlinks;
    bool isFile;
    bool isDir;
    bool isSymlink;
};

struct ProcessResult {
    int32_t exitCode;
    std::string stdout;
    std::string stderr;
};

struct ProcessInfo {
    int32_t pid;
    int32_t ppid;
    std::string user;
    std::string state;
    double cpuPercent;
    double memPercent;
    int64_t virt;
    int64_t rss;
    int64_t shared;
    int nice;
    int priority;
    double cpuTime;
    std::string command;
    std::string cmdline;
};

struct MemInfo {
    int64_t total;
    int64_t available;
    int64_t used;
    int64_t free;
    int64_t buffers;
    int64_t cached;
    int64_t swapTotal;
    int64_t swapUsed;
    int64_t swapFree;
};

struct DiskInfo {
    std::string mountPoint;
    std::string fsType;
    int64_t total;
    int64_t used;
    int64_t free;
    double usagePercent;
};

struct SystemInfo {
    std::string osName;
    std::string nodeName;
    std::string release;
    std::string version;
    std::string machine;
};

struct LoadInfo {
    double load1;
    double load5;
    double load15;
};

struct DirEntry {
    std::string name;
    std::string path;
    bool isFile;
    bool isDir;
    bool isSymlink;
};

struct LsOpts {
    bool showAll;
    bool followSymlinks;
    bool sortByTime;
    bool reverseOrder;
};

struct FindOpts {
    std::string namePattern;
    int maxDepth;
    bool filesOnly;
    bool dirsOnly;
    bool followSymlinks;
};

struct CpOpts {
    bool recursive;
    bool preserve;
    bool noClobber;
};

struct RmOpts {
    bool recursive;
    bool force;
};

struct RunOpts {
    std::string cwd;
    std::vector<std::string> env;
    int timeout;
    bool mergeStderr;
};


// ============================================================================
// Internal helpers
// ============================================================================

namespace morloc_shell_internal {

// The file `cmd` names: itself when it holds a '/', otherwise the first
// executable of that name on PATH, as execvp would find it. Empty if none.
static std::string resolve_program(const std::string& cmd) {
    if (cmd.find('/') != std::string::npos) return cmd;
    const char* path = getenv("PATH");
    std::string dirs = path ? path : "/usr/bin:/bin";
    size_t start = 0;
    while (start <= dirs.size()) {
        size_t colon = dirs.find(':', start);
        std::string dir = dirs.substr(start, colon == std::string::npos ? std::string::npos : colon - start);
        std::string candidate = (dir.empty() ? std::string(".") : dir) + "/" + cmd;
        struct stat st;
        if (::stat(candidate.c_str(), &st) == 0 && S_ISREG(st.st_mode) && access(candidate.c_str(), X_OK) == 0) {
            return candidate;
        }
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return "";
}

// Run argv[0] with `args`, collecting its output. Everything the child needs
// is built before the fork: a pool is multithreaded, so the child may make
// only async-signal-safe calls before exec. Both pipes are read together, so
// a child that fills one while the other is read cannot stall. A run still
// going after `timeout_s` seconds (0: no limit) is killed and reported as
// exit code -1 with stderr "timeout". A child killed by signal N reports -N.
static ProcessResult run_command(const std::vector<std::string>& argv,
                                 const std::string& cwd,
                                 const std::vector<std::string>& env_pairs,
                                 bool merge_stderr,
                                 int timeout_s = 0) {
    std::string program = argv.empty() ? std::string() : resolve_program(argv[0]);
    if (program.empty()) return ProcessResult{127, "", ""};

    std::vector<char*> c_argv;
    for (const auto& a : argv) c_argv.push_back(const_cast<char*>(a.c_str()));
    c_argv.push_back(nullptr);

    std::vector<std::string> env_strs;
    for (char** e = environ; *e; ++e) {
        std::string kv(*e);
        std::string key = kv.substr(0, kv.find('='));
        bool overridden = false;
        for (const auto& pair : env_pairs) {
            if (pair.substr(0, pair.find('=')) == key) { overridden = true; break; }
        }
        if (!overridden) env_strs.push_back(kv);
    }
    for (const auto& pair : env_pairs) {
        if (pair.find('=') != std::string::npos) env_strs.push_back(pair);
    }
    std::vector<char*> c_envp;
    for (auto& e : env_strs) c_envp.push_back(const_cast<char*>(e.c_str()));
    c_envp.push_back(nullptr);
    bool chdir_needed = !cwd.empty() && cwd != ".";

    int out_pipe[2] = {-1, -1}, err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) != 0 || (!merge_stderr && pipe(err_pipe) != 0)) {
        int e = errno;
        for (int fd : {out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) if (fd >= 0) close(fd);
        return ProcessResult{-1, "", std::string("pipe: ") + strerror(e)};
    }

    pid_t child = fork();
    if (child < 0) {
        int e = errno;
        for (int fd : {out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) if (fd >= 0) close(fd);
        return ProcessResult{-1, "", std::string("fork: ") + strerror(e)};
    }
    if (child == 0) {
        close(out_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(out_pipe[1]);
        if (merge_stderr) {
            dup2(STDOUT_FILENO, STDERR_FILENO);
        } else {
            close(err_pipe[0]);
            dup2(err_pipe[1], STDERR_FILENO);
            close(err_pipe[1]);
        }
        if (chdir_needed && chdir(cwd.c_str()) != 0) _exit(127);
        execve(program.c_str(), c_argv.data(), c_envp.data());
        _exit(127);
    }

    close(out_pipe[1]);
    if (!merge_stderr) close(err_pipe[1]);
    std::string out_str, err_str;
    struct pollfd fds[2] = {{out_pipe[0], POLLIN, 0}, {merge_stderr ? -1 : err_pipe[0], POLLIN, 0}};
    std::string* sinks[2] = {&out_str, &err_str};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    bool timed_out = false;
    char buf[8192];
    while (fds[0].fd >= 0 || fds[1].fd >= 0) {
        int wait_ms = -1;
        if (timeout_s > 0) {
            auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) { timed_out = true; break; }
            wait_ms = static_cast<int>(left);
        }
        int rc = poll(fds, 2, wait_ms);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int k = 0; k < 2; k++) {
            if (fds[k].fd < 0 || fds[k].revents == 0) continue;
            ssize_t n = read(fds[k].fd, buf, sizeof(buf));
            if (n > 0) {
                sinks[k]->append(buf, static_cast<size_t>(n));
            } else if (n == 0 || errno != EINTR) {
                close(fds[k].fd);
                fds[k].fd = -1;
            }
        }
    }
    for (auto& f : fds) if (f.fd >= 0) close(f.fd);
    if (timed_out) kill(child, SIGKILL);

    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (timed_out) return ProcessResult{-1, "", "timeout"};
    int32_t code = WIFEXITED(status) ? static_cast<int32_t>(WEXITSTATUS(status))
                 : WIFSIGNALED(status) ? -static_cast<int32_t>(WTERMSIG(status))
                 : -1;
    return ProcessResult{code, out_str, err_str};
}

static std::string get_owner(uid_t uid) {
    struct passwd* pw = getpwuid(uid);
    if (pw) return std::string(pw->pw_name);
    return std::to_string(uid);
}

static std::string get_group(gid_t gid) {
    struct group* gr = getgrgid(gid);
    if (gr) return std::string(gr->gr_name);
    return std::to_string(gid);
}

static FileStat stat_path(const std::string& p) {
    struct stat st;
    lstat(p.c_str(), &st);
    FileStat fs;
    fs.size = static_cast<int64_t>(st.st_size);
    fs.mtime = static_cast<int64_t>(st.st_mtime);
    fs.atime = static_cast<int64_t>(st.st_atime);
    fs.ctime = static_cast<int64_t>(st.st_ctime);
    fs.mode = static_cast<uint32_t>(st.st_mode & 07777);
    fs.uid = static_cast<uint32_t>(st.st_uid);
    fs.gid = static_cast<uint32_t>(st.st_gid);
    fs.owner = get_owner(st.st_uid);
    fs.group = get_group(st.st_gid);
    fs.nlinks = static_cast<uint64_t>(st.st_nlink);
    fs.isFile = S_ISREG(st.st_mode);
    fs.isDir = S_ISDIR(st.st_mode);
    fs.isSymlink = S_ISLNK(st.st_mode);
    return fs;
}

// recursive find helper
static void find_recursive(const std::string& dir, const FindOpts& opts,
                            int depth, std::vector<std::string>& results) {
    if (opts.maxDepth >= 0 && depth > opts.maxDepth) return;
    DIR* dp = opendir(dir.c_str());
    if (!dp) return;
    std::vector<std::string> subdirs;
    struct dirent* ent;
    while ((ent = readdir(dp)) != nullptr) {
        std::string name(ent->d_name);
        if (name == "." || name == "..") continue;
        std::string full = dir + "/" + name;
        struct stat st;
        if (opts.followSymlinks) {
            ::stat(full.c_str(), &st);
        } else {
            lstat(full.c_str(), &st);
        }
        bool is_dir = S_ISDIR(st.st_mode);
        bool is_file = S_ISREG(st.st_mode);
        bool matches = fnmatch(opts.namePattern.c_str(), name.c_str(), 0) == 0;
        if (matches) {
            if (is_dir && !opts.filesOnly) results.push_back(full);
            if (is_file && !opts.dirsOnly) results.push_back(full);
            if (!is_dir && !is_file && !opts.filesOnly && !opts.dirsOnly) results.push_back(full);
        }
        if (is_dir) subdirs.push_back(full);
    }
    closedir(dp);
    for (const auto& sd : subdirs) {
        find_recursive(sd, opts, depth + 1, results);
    }
}

} // namespace morloc_shell_internal


// ============================================================================
// A. Pure path operations
// ============================================================================

inline std::string morloc_path_join(const std::string& a, const std::string& b) {
    return (fs::path(a) / fs::path(b)).string();
}

inline std::tuple<std::string, std::string> morloc_path_split(const std::string& p) {
    fs::path fp(p);
    return std::make_tuple(fp.parent_path().string(), fp.filename().string());
}

inline std::string morloc_path_dir(const std::string& p) {
    return fs::path(p).parent_path().string();
}

inline std::string morloc_path_base(const std::string& p) {
    return fs::path(p).filename().string();
}

inline std::string morloc_path_ext(const std::string& p) {
    return fs::path(p).extension().string();
}

inline std::string morloc_path_stem(const std::string& p) {
    return fs::path(p).stem().string();
}

inline std::string morloc_replace_ext(const std::string& p, const std::string& ext) {
    return fs::path(p).replace_extension(ext).string();
}

inline std::string morloc_add_ext(const std::string& p, const std::string& ext) {
    return p + ext;
}

inline std::string morloc_drop_ext(const std::string& p) {
    fs::path fp(p);
    return (fp.parent_path() / fp.stem()).string();
}

inline std::string morloc_norm_path(const std::string& p) {
    return fs::path(p).lexically_normal().string();
}

inline bool morloc_is_absolute(const std::string& p) {
    return fs::path(p).is_absolute();
}

inline bool morloc_is_relative(const std::string& p) {
    return fs::path(p).is_relative();
}

inline std::vector<std::string> morloc_path_components(const std::string& p) {
    std::vector<std::string> parts;
    for (const auto& part : fs::path(p)) {
        std::string s = part.string();
        if (!s.empty()) parts.push_back(s);
    }
    return parts;
}


// ============================================================================
// B. Filesystem navigation
// ============================================================================

inline std::string morloc_pwd() {
    return fs::current_path().string();
}

inline mlc::Unit morloc_cd(const std::string& d) {
    fs::current_path(d);
    return mlc::Unit();
}

inline std::string morloc_realpath(const std::string& p) {
    return fs::canonical(p).string();
}

inline std::string morloc_home_dir() {
    const char* home = std::getenv("HOME");
    if (home) return std::string(home);
    struct passwd* pw = getpwuid(getuid());
    if (pw) return std::string(pw->pw_dir);
    return ".";
}

inline std::string morloc_tmp_dir() {
    return fs::temp_directory_path().string();
}


// ============================================================================
// C. Directory listing
// ============================================================================

inline std::vector<std::string> morloc_ls(const std::string& d) {
    std::vector<std::string> entries;
    for (const auto& e : fs::directory_iterator(d)) {
        entries.push_back(e.path().filename().string());
    }
    std::sort(entries.begin(), entries.end());
    return entries;
}

inline std::vector<std::string> morloc_ls_with(const LsOpts& opts, const std::string& d) {
    std::vector<std::string> entries;
    auto it_opts = opts.followSymlinks
        ? fs::directory_options::follow_directory_symlink
        : fs::directory_options::none;
    for (const auto& e : fs::directory_iterator(d, it_opts)) {
        std::string name = e.path().filename().string();
        if (!opts.showAll && !name.empty() && name[0] == '.') continue;
        entries.push_back(name);
    }
    if (opts.sortByTime) {
        std::sort(entries.begin(), entries.end(), [&](const std::string& a, const std::string& b) {
            auto ta = fs::last_write_time(fs::path(d) / a);
            auto tb = fs::last_write_time(fs::path(d) / b);
            return ta > tb;
        });
    } else {
        std::sort(entries.begin(), entries.end());
    }
    if (opts.reverseOrder) {
        std::reverse(entries.begin(), entries.end());
    }
    return entries;
}

inline std::vector<DirEntry> morloc_ls_stat(const std::string& d) {
    std::vector<DirEntry> result;
    std::vector<std::string> names;
    for (const auto& e : fs::directory_iterator(d)) {
        names.push_back(e.path().filename().string());
    }
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
        std::string full = (fs::path(d) / name).string();
        struct stat st;
        lstat(full.c_str(), &st);
        DirEntry de;
        de.name = name;
        de.path = full;
        de.isFile = S_ISREG(st.st_mode);
        de.isDir = S_ISDIR(st.st_mode);
        de.isSymlink = S_ISLNK(st.st_mode);
        result.push_back(de);
    }
    return result;
}


// ============================================================================
// D. File management
// ============================================================================

inline mlc::Unit morloc_cp(const CpOpts& opts, const std::string& src, const std::string& dst) {
    if (opts.noClobber && fs::exists(dst)) return mlc::Unit();
    auto cp_opts = fs::copy_options::none;
    if (opts.recursive) cp_opts |= fs::copy_options::recursive;
    if (!opts.noClobber) cp_opts |= fs::copy_options::overwrite_existing;
    fs::copy(src, dst, cp_opts);
    return mlc::Unit();
}

inline mlc::Unit morloc_mv(const std::string& src, const std::string& dst) {
    fs::rename(src, dst);
    return mlc::Unit();
}

inline mlc::Unit morloc_rm(const RmOpts& opts, const std::string& p) {
    std::error_code ec;
    if (opts.recursive) {
        fs::remove_all(p, ec);
    } else {
        fs::remove(p, ec);
    }
    if (ec && !opts.force) {
        throw std::runtime_error("rm failed: " + ec.message());
    }
    return mlc::Unit();
}

inline mlc::Unit morloc_mkdir(const std::string& d) {
    fs::create_directories(d);
    return mlc::Unit();
}

inline mlc::Unit morloc_touch(const std::string& p) {
    if (fs::exists(p)) {
        fs::last_write_time(p, fs::file_time_type::clock::now());
    } else {
        std::ofstream(p).close();
    }
    return mlc::Unit();
}

inline mlc::Unit morloc_chmod(uint32_t mode, const std::string& p) {
    ::chmod(p.c_str(), static_cast<mode_t>(mode));
    return mlc::Unit();
}

inline mlc::Unit morloc_chown(uint32_t uid, uint32_t gid, const std::string& p) {
    ::chown(p.c_str(), static_cast<uid_t>(uid), static_cast<gid_t>(gid));
    return mlc::Unit();
}

inline mlc::Unit morloc_symlink(const std::string& target, const std::string& link) {
    fs::create_symlink(target, link);
    return mlc::Unit();
}

inline mlc::Unit morloc_hardlink(const std::string& target, const std::string& link) {
    fs::create_hard_link(target, link);
    return mlc::Unit();
}

inline std::string morloc_readlink(const std::string& p) {
    return fs::read_symlink(p).string();
}

inline mlc::Unit morloc_rename(const std::string& src, const std::string& dst) {
    fs::rename(src, dst);
    return mlc::Unit();
}


// ============================================================================
// E. File I/O
// ============================================================================

inline std::string morloc_read_file(const std::string& p) {
    std::ifstream f(p);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

inline mlc::Unit morloc_write_file(const std::string& p, const std::string& content) {
    std::ofstream f(p);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    f << content;
    return mlc::Unit();
}

inline mlc::Unit morloc_append_file(const std::string& p, const std::string& content) {
    std::ofstream f(p, std::ios::app);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    f << content;
    return mlc::Unit();
}

inline std::vector<std::string> morloc_read_lines(const std::string& p) {
    std::ifstream f(p);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(line);
    }
    return lines;
}

inline mlc::Unit morloc_write_lines(const std::string& p, const std::vector<std::string>& lines) {
    std::ofstream f(p);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    for (const auto& line : lines) {
        f << line << "\n";
    }
    return mlc::Unit();
}

inline std::vector<int> morloc_read_bytes(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    std::vector<int> data;
    char c;
    while (f.get(c)) {
        data.push_back(static_cast<unsigned char>(c));
    }
    return data;
}

inline mlc::Unit morloc_write_bytes(const std::string& p, const std::vector<int>& data) {
    std::ofstream f(p, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    for (int b : data) {
        f.put(static_cast<char>(b));
    }
    return mlc::Unit();
}

inline std::vector<std::string> morloc_read_head(const std::string& p, int n) {
    std::ifstream f(p);
    if (!f.is_open()) throw std::runtime_error("Cannot open file: " + p);
    std::vector<std::string> lines;
    std::string line;
    for (int i = 0; i < n && std::getline(f, line); i++) {
        lines.push_back(line);
    }
    return lines;
}


// ============================================================================
// F. File information
// ============================================================================

inline FileStat morloc_stat(const std::string& p) {
    return morloc_shell_internal::stat_path(p);
}

inline int64_t morloc_file_size(const std::string& p) {
    return static_cast<int64_t>(fs::file_size(p));
}

inline bool morloc_path_exists(const std::string& p) {
    return fs::exists(fs::symlink_status(p));
}

inline bool morloc_is_file(const std::string& p) {
    return fs::is_regular_file(p);
}

inline bool morloc_is_dir(const std::string& p) {
    return fs::is_directory(p);
}


// ============================================================================
// G. Directory traversal
// ============================================================================

inline std::vector<std::string> morloc_glob(const std::string& pattern) {
    // Simple glob: split into directory prefix and filename pattern
    std::vector<std::string> results;
    fs::path pat(pattern);
    std::string dir_str = pat.parent_path().string();
    std::string name_pat = pat.filename().string();
    if (dir_str.empty()) dir_str = ".";

    if (fs::is_directory(dir_str)) {
        for (const auto& entry : fs::recursive_directory_iterator(dir_str)) {
            if (fnmatch(name_pat.c_str(), entry.path().filename().c_str(), 0) == 0) {
                results.push_back(entry.path().string());
            }
        }
    }
    std::sort(results.begin(), results.end());
    return results;
}

inline std::vector<std::string> morloc_find(const FindOpts& opts, const std::string& d) {
    std::vector<std::string> results;
    morloc_shell_internal::find_recursive(d, opts, 0, results);
    std::sort(results.begin(), results.end());
    return results;
}

inline std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<std::string>>>
morloc_walk(const std::string& d) {
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<std::string>>> result;

    // BFS-style walk to match os.walk() ordering
    std::vector<std::string> dirs_to_visit;
    dirs_to_visit.push_back(d);

    while (!dirs_to_visit.empty()) {
        std::string current = dirs_to_visit.front();
        dirs_to_visit.erase(dirs_to_visit.begin());
        std::vector<std::string> subdirs, files;
        DIR* dp = opendir(current.c_str());
        if (!dp) continue;
        struct dirent* ent;
        while ((ent = readdir(dp)) != nullptr) {
            std::string name(ent->d_name);
            if (name == "." || name == "..") continue;
            std::string full = current + "/" + name;
            struct stat st;
            lstat(full.c_str(), &st);
            if (S_ISDIR(st.st_mode)) {
                subdirs.push_back(name);
                dirs_to_visit.push_back(full);
            } else {
                files.push_back(name);
            }
        }
        closedir(dp);
        std::sort(subdirs.begin(), subdirs.end());
        std::sort(files.begin(), files.end());
        result.push_back(std::make_tuple(current, subdirs, files));
    }
    return result;
}

inline std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<std::string>>>
morloc_walk_filter(std::function<bool(const DirEntry&)> pred, const std::string& d) {
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<std::string>>> result;
    std::vector<std::string> dirs_to_visit;
    dirs_to_visit.push_back(d);

    while (!dirs_to_visit.empty()) {
        std::string current = dirs_to_visit.front();
        dirs_to_visit.erase(dirs_to_visit.begin());
        std::vector<std::string> subdirs, files;
        DIR* dp = opendir(current.c_str());
        if (!dp) continue;
        struct dirent* ent;
        while ((ent = readdir(dp)) != nullptr) {
            std::string name(ent->d_name);
            if (name == "." || name == "..") continue;
            std::string full = current + "/" + name;
            struct stat st;
            lstat(full.c_str(), &st);
            DirEntry de;
            de.name = name;
            de.path = full;
            de.isFile = S_ISREG(st.st_mode);
            de.isDir = S_ISDIR(st.st_mode);
            de.isSymlink = S_ISLNK(st.st_mode);
            if (pred(de)) {
                if (de.isDir) {
                    subdirs.push_back(name);
                    dirs_to_visit.push_back(full);
                } else {
                    files.push_back(name);
                }
            }
        }
        closedir(dp);
        std::sort(subdirs.begin(), subdirs.end());
        std::sort(files.begin(), files.end());
        result.push_back(std::make_tuple(current, subdirs, files));
    }
    return result;
}


// ============================================================================
// H. Process execution
// ============================================================================

inline ProcessResult morloc_run(const std::string& cmd, const std::vector<std::string>& args) {
    std::vector<std::string> argv;
    argv.push_back(cmd);
    argv.insert(argv.end(), args.begin(), args.end());
    return morloc_shell_internal::run_command(argv, ".", {}, false);
}

inline ProcessResult morloc_run_with(const RunOpts& opts, const std::string& cmd,
                                      const std::vector<std::string>& args) {
    std::vector<std::string> argv;
    argv.push_back(cmd);
    argv.insert(argv.end(), args.begin(), args.end());
    return morloc_shell_internal::run_command(argv, opts.cwd, opts.env, opts.mergeStderr, opts.timeout);
}

inline ProcessResult morloc_shell(const std::string& cmd) {
    std::vector<std::string> argv = {"/bin/sh", "-c", cmd};
    return morloc_shell_internal::run_command(argv, ".", {}, false);
}

inline std::string morloc_capture(const std::string& cmd, const std::vector<std::string>& args) {
    ProcessResult r = morloc_run(cmd, args);
    return r.stdout;
}

// ============================================================================
// I. Process information
// ============================================================================

inline int32_t morloc_get_pid() {
    return static_cast<int32_t>(getpid());
}

inline int32_t morloc_get_parent_pid() {
    return static_cast<int32_t>(getppid());
}

namespace morloc_shell_internal {

// Process listings come from ps(1), whose POSIX fields read the same on Linux
// and macOS, so one code path serves both. Two calls: the command name is the
// last field of one, the full command line of the other, since either may
// contain spaces.
static const std::vector<std::string> PS_FIELDS =
    {"pid", "ppid", "uid", "pcpu", "pmem", "vsz", "rss", "nice", "pri", "time", "stat"};

static std::vector<std::string> split_ws(const std::string& line, size_t max_fields) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && isspace(static_cast<unsigned char>(line[i]))) i++;
        if (i >= line.size()) break;
        if (out.size() + 1 == max_fields) {
            size_t e = line.find_last_not_of(" \t\r\n");
            out.push_back(line.substr(i, e + 1 - i));
            break;
        }
        size_t j = i;
        while (j < line.size() && !isspace(static_cast<unsigned char>(line[j]))) j++;
        out.push_back(line.substr(i, j - i));
        i = j;
    }
    return out;
}

static std::vector<std::string> lines_of(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) out.push_back(line);
    return out;
}

// Seconds in a ps TIME field: [[DD-]HH:]MM:SS[.ss].
static double ps_seconds(std::string text) {
    double days = 0;
    auto dash = text.find('-');
    if (dash != std::string::npos) {
        days = std::stod(text.substr(0, dash));
        text = text.substr(dash + 1);
    }
    double secs = 0;
    std::istringstream iss(text);
    std::string part;
    while (std::getline(iss, part, ':')) secs = secs * 60 + std::stod(part);
    return days * 86400 + secs;
}

static int ps_int(const std::string& text) {
    try { return std::stoi(text); } catch (...) { return 0; }  // "-" for a real-time process's nice
}

// File-backed and shared resident memory, where the platform reports it.
static int64_t shared_bytes(int32_t pid) {
    int64_t total = 0;
    std::ifstream f("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("RssFile:", 0) == 0 || line.rfind("RssShmem:", 0) == 0) {
            total += std::stoll(line.substr(line.find(':') + 1)) * 1024;
        }
    }
    return total;
}

// ProcessInfo records for `pids`, or for every process when empty.
static std::vector<ProcessInfo> processes(const std::vector<int32_t>& pids) {
    std::vector<std::string> select;
    if (pids.empty()) {
        select = {"-A"};
    } else {
        std::string list;
        for (auto p : pids) list += (list.empty() ? "" : ",") + std::to_string(p);
        select = {"-p", list};
    }
    std::string cols;
    for (const auto& f : PS_FIELDS) cols += f + "=,";
    cols += "comm=";

    std::vector<std::string> argv = {"ps"};
    argv.insert(argv.end(), select.begin(), select.end());
    std::vector<std::string> args_argv = argv;
    args_argv.push_back("-o");
    args_argv.push_back("pid=,args=");
    argv.push_back("-o");
    argv.push_back(cols);

    std::map<int32_t, std::string> args_by_pid;
    for (const auto& line : lines_of(run_command(args_argv, ".", {}, false).stdout)) {
        auto parts = split_ws(line, 2);
        if (!parts.empty()) args_by_pid[std::stoi(parts[0])] = parts.size() > 1 ? parts[1] : "";
    }
    std::vector<ProcessInfo> result;
    for (const auto& line : lines_of(run_command(argv, ".", {}, false).stdout)) {
        auto parts = split_ws(line, PS_FIELDS.size() + 1);
        if (parts.size() <= PS_FIELDS.size()) continue;
        ProcessInfo pi;
        pi.pid = std::stoi(parts[0]);
        pi.ppid = std::stoi(parts[1]);
        pi.user = get_owner(static_cast<uid_t>(std::stoul(parts[2])));
        pi.cpuPercent = std::stod(parts[3]);
        pi.memPercent = std::stod(parts[4]);
        pi.virt = std::stoll(parts[5]) * 1024;
        pi.rss = std::stoll(parts[6]) * 1024;
        pi.nice = ps_int(parts[7]);
        pi.priority = ps_int(parts[8]);
        pi.cpuTime = ps_seconds(parts[9]);
        pi.state = parts[10];
        pi.shared = shared_bytes(pi.pid);
        pi.command = fs::path(parts[11]).filename().string();
        pi.cmdline = args_by_pid.count(pi.pid) ? args_by_pid[pi.pid] : "";
        result.push_back(pi);
    }
    return result;
}

} // namespace morloc_shell_internal

inline std::vector<ProcessInfo> morloc_list_processes() {
    return morloc_shell_internal::processes({});
}

inline ProcessInfo morloc_get_process(int32_t pid) {
    auto found = morloc_shell_internal::processes({pid});
    if (found.empty()) throw std::runtime_error("Process " + std::to_string(pid) + " not found");
    return found[0];
}

inline std::vector<ProcessInfo> morloc_process_children(int32_t pid) {
    std::vector<ProcessInfo> children;
    for (const auto& p : morloc_shell_internal::processes({})) {
        if (p.ppid == pid) children.push_back(p);
    }
    return children;
}

inline mlc::Unit morloc_kill(int32_t sig, int32_t pid) {
    ::kill(static_cast<pid_t>(pid), sig);
    return mlc::Unit();
}

inline int32_t morloc_wait_pid(int32_t pid) {
    int status = 0;
    waitpid(static_cast<pid_t>(pid), &status, 0);
    if (WIFEXITED(status)) return static_cast<int32_t>(WEXITSTATUS(status));
    return -1;
}


// ============================================================================
// J. System information
// ============================================================================

inline SystemInfo morloc_uname() {
    struct utsname u;
    uname(&u);
    SystemInfo si;
    si.osName = u.sysname;
    si.nodeName = u.nodename;
    si.release = u.release;
    si.version = u.version;
    si.machine = u.machine;
    return si;
}

inline std::string morloc_hostname() {
    char buf[256];
    gethostname(buf, sizeof(buf));
    return std::string(buf);
}

namespace morloc_shell_internal {

static std::string capture(const std::vector<std::string>& argv) {
    return run_command(argv, ".", {}, false).stdout;
}

// Seconds since the epoch from `sysctl -n kern.boottime`:
// "{ sec = 1700000000, usec = 250000 } Tue Nov 14 ...".
static double parse_boottime(const std::string& text) {
    std::smatch m;
    if (!std::regex_search(text, m, std::regex(R"(sec = (\d+), usec = (\d+))"))) {
        throw std::runtime_error("cannot read the boot time: " + text);
    }
    return std::stod(m[1].str()) + std::stod(m[2].str()) / 1e6;
}

// MemInfo from macOS's hw.memsize, `vm_stat` and vm.swapusage.
static MemInfo parse_darwin_mem(int64_t total, const std::string& vm_stat, const std::string& swapusage) {
    std::smatch m;
    int64_t page = 4096;
    if (std::regex_search(vm_stat, m, std::regex(R"(page size of (\d+) bytes)"))) page = std::stoll(m[1].str());
    std::map<std::string, int64_t> pages;
    for (const auto& line : lines_of(vm_stat)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string val = line.substr(colon + 1);
        val.erase(std::remove_if(val.begin(), val.end(), [](char c) { return c == ' ' || c == '.'; }), val.end());
        if (!val.empty() && std::all_of(val.begin(), val.end(), ::isdigit)) {
            pages[line.substr(0, colon)] = std::stoll(val) * page;
        }
    }
    MemInfo mi = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    mi.total = total;
    mi.free = pages["Pages free"] + pages["Pages speculative"];
    mi.cached = pages["File-backed pages"];
    mi.available = mi.free + pages["Pages inactive"] + pages["Pages purgeable"];
    mi.used = total - mi.available;
    std::regex swap_re(R"((total|used|free) = ([\d.]+)([KMG]))");
    for (auto it = std::sregex_iterator(swapusage.begin(), swapusage.end(), swap_re); it != std::sregex_iterator(); ++it) {
        double unit = (*it)[3] == "K" ? 1024.0 : (*it)[3] == "M" ? 1048576.0 : 1073741824.0;
        int64_t bytes = static_cast<int64_t>(std::stod((*it)[2].str()) * unit);
        if ((*it)[1] == "total") mi.swapTotal = bytes;
        else if ((*it)[1] == "used") mi.swapUsed = bytes;
        else mi.swapFree = bytes;
    }
    return mi;
}

// Mount point -> filesystem type from `mount` output, in either the Linux
// form "dev on /path type ext4 (rw,...)" or the macOS form
// "dev on /path (apfs, local, ...)".
static std::map<std::string, std::string> parse_mount(const std::string& text) {
    std::map<std::string, std::string> types;
    std::regex linux_re(R"(.+? on (.+) type (\S+) \()"), darwin_re(R"(.+? on (.+) \(([^,)]+))");
    for (const auto& line : lines_of(text)) {
        std::smatch m;
        if (std::regex_search(line, m, linux_re) || std::regex_search(line, m, darwin_re)) {
            types[m[1].str()] = m[2].str();
        }
    }
    return types;
}

} // namespace morloc_shell_internal

inline double morloc_uptime() {
#ifdef __APPLE__
    std::string out = morloc_shell_internal::capture({"sysctl", "-n", "kern.boottime"});
    double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    return now - morloc_shell_internal::parse_boottime(out);
#else
    std::ifstream f("/proc/uptime");
    double up = 0;
    if (!(f >> up)) throw std::runtime_error("cannot read /proc/uptime");
    return up;
#endif
}

inline int morloc_cpu_count() {
    return static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
}

inline MemInfo morloc_mem_info() {
#ifdef __APPLE__
    using morloc_shell_internal::capture;
    int64_t total = std::stoll(capture({"sysctl", "-n", "hw.memsize"}));
    return morloc_shell_internal::parse_darwin_mem(total, capture({"vm_stat"}), capture({"sysctl", "-n", "vm.swapusage"}));
#else
    std::map<std::string, int64_t> info;
    std::ifstream f("/proc/meminfo");
    if (!f.is_open()) throw std::runtime_error("cannot read /proc/meminfo");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string key;
        int64_t val = 0;
        iss >> key >> val;
        if (!key.empty()) info[key.substr(0, key.size() - 1)] = val * 1024; // kB to bytes
    }
    MemInfo mi = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    mi.total = info["MemTotal"];
    mi.free = info["MemFree"];
    mi.available = info.count("MemAvailable") ? info["MemAvailable"] : mi.free;
    mi.buffers = info["Buffers"];
    mi.cached = info["Cached"];
    mi.swapTotal = info["SwapTotal"];
    mi.swapFree = info["SwapFree"];
    mi.used = mi.total - mi.free - mi.buffers - mi.cached;
    mi.swapUsed = mi.swapTotal - mi.swapFree;
    return mi;
#endif
}

// Mounted filesystems, from POSIX `df -P -k` and the `mount` listing, which
// both Linux and macOS provide.
inline std::vector<DiskInfo> morloc_disk_info() {
    using morloc_shell_internal::capture;
    auto types = morloc_shell_internal::parse_mount(capture({"mount"}));
    std::vector<DiskInfo> result;
    auto lines = morloc_shell_internal::lines_of(capture({"df", "-P", "-k"}));
    for (size_t i = 1; i < lines.size(); i++) {
        auto parts = morloc_shell_internal::split_ws(lines[i], 6);
        if (parts.size() < 6) continue;
        DiskInfo di;
        di.mountPoint = parts[5];
        di.fsType = types.count(di.mountPoint) ? types[di.mountPoint] : "";
        try {
            di.total = std::stoll(parts[1]) * 1024;
            di.used = std::stoll(parts[2]) * 1024;
            di.free = std::stoll(parts[3]) * 1024;
        } catch (...) {
            continue;
        }
        std::string pct = parts[4];
        if (!pct.empty() && pct.back() == '%') pct.pop_back();
        try { di.usagePercent = std::stod(pct); } catch (...) { di.usagePercent = 0.0; }
        result.push_back(di);
    }
    return result;
}

inline LoadInfo morloc_load_avg() {
    double loadavg[3];
    getloadavg(loadavg, 3);
    LoadInfo li;
    li.load1 = loadavg[0];
    li.load5 = loadavg[1];
    li.load15 = loadavg[2];
    return li;
}


// ============================================================================
// K. Environment variables
// ============================================================================

inline std::string morloc_get_env(const std::string& var) {
    const char* val = std::getenv(var.c_str());
    if (!val) throw std::runtime_error("Environment variable not set: " + var);
    return std::string(val);
}

inline mlc::Unit morloc_set_env(const std::string& var, const std::string& val) {
    setenv(var.c_str(), val.c_str(), 1);
    return mlc::Unit();
}

inline mlc::Unit morloc_unset_env(const std::string& var) {
    unsetenv(var.c_str());
    return mlc::Unit();
}

inline std::vector<std::tuple<std::string, std::string>> morloc_environ() {
    std::vector<std::tuple<std::string, std::string>> result;
    for (char** env = environ; *env; ++env) {
        std::string entry(*env);
        auto eq = entry.find('=');
        if (eq != std::string::npos) {
            result.push_back(std::make_tuple(entry.substr(0, eq), entry.substr(eq + 1)));
        }
    }
    return result;
}

inline bool morloc_has_env(const std::string& var) {
    return std::getenv(var.c_str()) != nullptr;
}


#endif
