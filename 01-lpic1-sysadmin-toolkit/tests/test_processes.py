from sysadmin_toolkit import processes


def make_fake_pid(root, pid, comm, state, ppid, cmdline=None, rss_kb=None):
    pid_dir = root / str(pid)
    pid_dir.mkdir()
    stat_line = f"{pid} ({comm}) {state} {ppid} 0 0 0 0 0"
    (pid_dir / "stat").write_text(stat_line)
    if cmdline is not None:
        (pid_dir / "cmdline").write_bytes(cmdline.encode() + b"\x00")
    if rss_kb is not None:
        (pid_dir / "status").write_text(f"Name:\t{comm}\nVmRSS:\t{rss_kb} kB\n")
    return pid_dir


def test_list_processes_reads_stat(tmp_path, monkeypatch):
    monkeypatch.setattr(processes, "PROC_ROOT", tmp_path)
    make_fake_pid(tmp_path, 1, "init", "S", 0)
    make_fake_pid(tmp_path, 2, "worker", "R", 1)
    (tmp_path / "self").symlink_to(tmp_path / "1")

    procs = {p["pid"]: p for p in processes.list_processes()}
    assert set(procs) == {1, 2}
    assert procs[2]["comm"] == "worker"
    assert procs[2]["ppid"] == 1


def test_comm_with_parens_and_spaces(tmp_path, monkeypatch):
    monkeypatch.setattr(processes, "PROC_ROOT", tmp_path)
    make_fake_pid(tmp_path, 5, "some (weird) name", "S", 1)

    info = processes.get_process_info(5)
    assert info["comm"] == "some (weird) name"


def test_get_process_info_includes_cmdline_and_rss(tmp_path, monkeypatch):
    monkeypatch.setattr(processes, "PROC_ROOT", tmp_path)
    make_fake_pid(tmp_path, 10, "sshd", "S", 1, cmdline="/usr/sbin/sshd -D", rss_kb=4096)

    info = processes.get_process_info(10)
    assert info["cmdline"] == "/usr/sbin/sshd -D"
    assert info["rss_kb"] == 4096
    assert info["state_name"] == "sleeping"


def test_find_zombies(tmp_path, monkeypatch):
    monkeypatch.setattr(processes, "PROC_ROOT", tmp_path)
    make_fake_pid(tmp_path, 1, "init", "S", 0)
    make_fake_pid(tmp_path, 2, "defunct-child", "Z", 1)

    zombies = processes.find_zombies()
    assert len(zombies) == 1
    assert zombies[0]["pid"] == 2


def test_top_memory_consumers_sorted_desc(tmp_path, monkeypatch):
    monkeypatch.setattr(processes, "PROC_ROOT", tmp_path)
    make_fake_pid(tmp_path, 1, "small", "S", 0, cmdline="small", rss_kb=1000)
    make_fake_pid(tmp_path, 2, "big", "S", 0, cmdline="big", rss_kb=50000)
    make_fake_pid(tmp_path, 3, "medium", "S", 0, cmdline="medium", rss_kb=10000)

    top = processes.top_memory_consumers(2)
    assert [p["comm"] for p in top] == ["big", "medium"]
