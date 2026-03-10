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
#include <sys/sysinfo.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <fnmatch.h>
#include "mlccpptypes/prelude.hpp"

namespace fs = std::filesystem;


// ============================================================================
// Record structs
// ============================================================================

struct FileStat {
    int64_t size;
    double mtime;
    double atime;
    double ctime;
    int mode;
    int uid;
    int gid;
    std::string owner;
    std::string group;
    int nlinks;
    bool isFile;
    bool isDir;
    bool isSymlink;
};

struct ProcessResult {
    int exitCode;
    std::string stdout;
    std::string stderr;
};

struct ProcessInfo {
    int pid;
    int ppid;
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

static std::string read_stream(FILE* fp) {
    std::string result;
    char buf[4096];
    while (true) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0) break;
        result.append(buf, n);
    }
    return result;
}

static ProcessResult run_command(const std::vector<std::string>& argv,
                                 const std::string& cwd,
                                 const std::vector<std::string>& env_pairs,
                                 bool merge_stderr) {
    int stdout_pipe[2], stderr_pipe[2];
    pipe(stdout_pipe);
    if (!merge_stderr) pipe(stderr_pipe);

    pid_t child = fork();
    if (child == 0) {
        // child
        close(stdout_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[1]);
        if (merge_stderr) {
            dup2(STDOUT_FILENO, STDERR_FILENO);
        } else {
            close(stderr_pipe[0]);
            dup2(stderr_pipe[1], STDERR_FILENO);
            close(stderr_pipe[1]);
        }
        if (!cwd.empty() && cwd != ".") {
            if (chdir(cwd.c_str()) != 0) _exit(127);
        }
        for (const auto& pair : env_pairs) {
            auto eq = pair.find('=');
            if (eq != std::string::npos) {
                setenv(pair.substr(0, eq).c_str(), pair.substr(eq + 1).c_str(), 1);
            }
        }
        std::vector<char*> c_argv;
        for (const auto& a : argv) c_argv.push_back(const_cast<char*>(a.c_str()));
        c_argv.push_back(nullptr);
        execvp(c_argv[0], c_argv.data());
        _exit(127);
    }

    // parent
    close(stdout_pipe[1]);
    std::string out_str, err_str;

    FILE* out_fp = fdopen(stdout_pipe[0], "r");
    out_str = read_stream(out_fp);
    fclose(out_fp);

    if (!merge_stderr) {
        close(stderr_pipe[1]);
        FILE* err_fp = fdopen(stderr_pipe[0], "r");
        err_str = read_stream(err_fp);
        fclose(err_fp);
    }

    int status = 0;
    waitpid(child, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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
    fs.mtime = static_cast<double>(st.st_mtime);
    fs.atime = static_cast<double>(st.st_atime);
    fs.ctime = static_cast<double>(st.st_ctime);
    fs.mode = st.st_mode & 07777;
    fs.uid = static_cast<int>(st.st_uid);
    fs.gid = static_cast<int>(st.st_gid);
    fs.owner = get_owner(st.st_uid);
    fs.group = get_group(st.st_gid);
    fs.nlinks = static_cast<int>(st.st_nlink);
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

inline mlc::Unit morloc_chmod(int mode, const std::string& p) {
    ::chmod(p.c_str(), static_cast<mode_t>(mode));
    return mlc::Unit();
}

inline mlc::Unit morloc_chown(int uid, int gid, const std::string& p) {
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
    return morloc_shell_internal::run_command(argv, opts.cwd, opts.env, opts.mergeStderr);
}

inline ProcessResult morloc_shell(const std::string& cmd) {
    std::vector<std::string> argv = {"/bin/sh", "-c", cmd};
    return morloc_shell_internal::run_command(argv, ".", {}, false);
}

inline std::string morloc_capture(const std::string& cmd, const std::vector<std::string>& args) {
    ProcessResult r = morloc_run(cmd, args);
    return r.stdout;
}

inline mlc::Unit morloc_exec(const std::string& cmd, const std::vector<std::string>& args) {
    std::vector<char*> c_argv;
    c_argv.push_back(const_cast<char*>(cmd.c_str()));
    for (const auto& a : args) c_argv.push_back(const_cast<char*>(a.c_str()));
    c_argv.push_back(nullptr);
    execvp(cmd.c_str(), c_argv.data());
    throw std::runtime_error("exec failed: " + cmd);
}


// ============================================================================
// I. Process information
// ============================================================================

inline int morloc_get_pid() {
    return static_cast<int>(getpid());
}

inline int morloc_get_parent_pid() {
    return static_cast<int>(getppid());
}

namespace morloc_shell_internal {

static ProcessInfo build_process_info(int pid) {
    ProcessInfo pi;
    pi.pid = pid;
    pi.ppid = 0;
    pi.cpuPercent = 0.0;
    pi.memPercent = 0.0;
    pi.virt = 0;
    pi.rss = 0;
    pi.shared = 0;
    pi.nice = 0;
    pi.priority = 0;
    pi.cpuTime = 0.0;

    // read /proc/<pid>/stat
    std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream sf(stat_path);
    if (sf.is_open()) {
        std::string content;
        std::getline(sf, content);
        // find comm (between parentheses)
        auto lp = content.find('(');
        auto rp = content.rfind(')');
        if (lp != std::string::npos && rp != std::string::npos) {
            pi.command = content.substr(lp + 1, rp - lp - 1);
            std::string rest = content.substr(rp + 2);
            std::istringstream iss(rest);
            std::string state_s;
            int ppid, pgrp, session, tty, tpgid;
            unsigned long flags, minflt, cminflt, majflt, cmajflt;
            long unsigned utime, stime;
            long cutime, cstime, prio, nice_val;
            long unsigned vsize;
            long rss_pages;

            iss >> state_s >> ppid >> pgrp >> session >> tty >> tpgid
                >> flags >> minflt >> cminflt >> majflt >> cmajflt
                >> utime >> stime >> cutime >> cstime >> prio >> nice_val;

            // skip num_threads, itrealvalue
            long dummy;
            iss >> dummy >> dummy;
            // starttime
            long unsigned starttime;
            iss >> starttime >> vsize >> rss_pages;

            pi.state = state_s;
            pi.ppid = ppid;
            pi.priority = static_cast<int>(prio);
            pi.nice = static_cast<int>(nice_val);
            pi.virt = static_cast<int64_t>(vsize);
            long page_size = sysconf(_SC_PAGE_SIZE);
            pi.rss = static_cast<int64_t>(rss_pages * page_size);
            long clk = sysconf(_SC_CLK_TCK);
            pi.cpuTime = static_cast<double>(utime + stime) / clk;
        }
    }

    // read /proc/<pid>/status for uid
    std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream stf(status_path);
    uid_t uid = 0;
    if (stf.is_open()) {
        std::string line;
        while (std::getline(stf, line)) {
            if (line.substr(0, 4) == "Uid:") {
                std::istringstream iss(line.substr(5));
                int u;
                iss >> u;
                uid = static_cast<uid_t>(u);
                break;
            }
        }
    }
    pi.user = get_owner(uid);

    // read cmdline
    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cf(cmdline_path);
    if (cf.is_open()) {
        std::string cl;
        std::getline(cf, cl);
        std::replace(cl.begin(), cl.end(), '\0', ' ');
        // trim trailing space
        while (!cl.empty() && cl.back() == ' ') cl.pop_back();
        pi.cmdline = cl;
    }

    return pi;
}

} // namespace morloc_shell_internal

inline std::vector<ProcessInfo> morloc_list_processes() {
    std::vector<ProcessInfo> result;
    DIR* dp = opendir("/proc");
    if (!dp) return result;
    struct dirent* ent;
    while ((ent = readdir(dp)) != nullptr) {
        std::string name(ent->d_name);
        bool all_digits = !name.empty();
        for (char c : name) {
            if (c < '0' || c > '9') { all_digits = false; break; }
        }
        if (all_digits) {
            int pid = std::stoi(name);
            result.push_back(morloc_shell_internal::build_process_info(pid));
        }
    }
    closedir(dp);
    return result;
}

inline ProcessInfo morloc_get_process(int pid) {
    return morloc_shell_internal::build_process_info(pid);
}

inline std::vector<ProcessInfo> morloc_process_children(int pid) {
    std::vector<ProcessInfo> all = morloc_list_processes();
    std::vector<ProcessInfo> children;
    for (const auto& p : all) {
        if (p.ppid == pid) children.push_back(p);
    }
    return children;
}

inline mlc::Unit morloc_kill(int sig, int pid) {
    ::kill(static_cast<pid_t>(pid), sig);
    return mlc::Unit();
}

inline int morloc_wait_pid(int pid) {
    int status = 0;
    waitpid(static_cast<pid_t>(pid), &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
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

inline double morloc_uptime() {
    struct sysinfo si;
    sysinfo(&si);
    return static_cast<double>(si.uptime);
}

inline int morloc_cpu_count() {
    return static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
}

inline MemInfo morloc_mem_info() {
    MemInfo mi = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::ifstream f("/proc/meminfo");
    if (!f.is_open()) return mi;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string key;
        long val;
        iss >> key >> val;
        val *= 1024; // kB to bytes
        key.pop_back(); // remove ':'
        if (key == "MemTotal") mi.total = static_cast<int64_t>(val);
        else if (key == "MemAvailable") mi.available = static_cast<int64_t>(val);
        else if (key == "MemFree") mi.free = static_cast<int64_t>(val);
        else if (key == "Buffers") mi.buffers = static_cast<int64_t>(val);
        else if (key == "Cached") mi.cached = static_cast<int64_t>(val);
        else if (key == "SwapTotal") mi.swapTotal = static_cast<int64_t>(val);
        else if (key == "SwapFree") mi.swapFree = static_cast<int64_t>(val);
    }
    mi.used = mi.total - mi.free - mi.buffers - mi.cached;
    mi.swapUsed = mi.swapTotal - mi.swapFree;
    return mi;
}

inline std::vector<DiskInfo> morloc_disk_info() {
    std::vector<DiskInfo> result;
    ProcessResult r = morloc_shell("df -T -B1 --output=target,fstype,size,used,avail,pcent 2>/dev/null");
    std::istringstream iss(r.stdout);
    std::string line;
    std::getline(iss, line); // skip header
    while (std::getline(iss, line)) {
        std::istringstream ls(line);
        DiskInfo di;
        std::string pct_str;
        long total_l, used_l, free_l;
        ls >> di.mountPoint >> di.fsType >> total_l >> used_l >> free_l >> pct_str;
        di.total = static_cast<int64_t>(total_l);
        di.used = static_cast<int64_t>(used_l);
        di.free = static_cast<int64_t>(free_l);
        if (!pct_str.empty() && pct_str.back() == '%') pct_str.pop_back();
        try { di.usagePercent = std::stod(pct_str); } catch (...) { di.usagePercent = 0.0; }
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
    extern char** environ;
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
