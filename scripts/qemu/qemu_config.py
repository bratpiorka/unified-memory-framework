import re
import subprocess  # nosec
import sys
import collections
import os
import psutil
import shutil

# If you want to manually run this script please install deps by: pip install -r requirements.txt
# To get virsh please install libvirt-clients
#
# Enable verbose mode by using environment variable ENABLE_VERBOSE=1

TopologyCfg = collections.namedtuple(
    "TopologyCfg", ["name", "hmat", "cpu_model", "cpu_options", "mem_options"]
)

verbose_mode = False


def enable_verbose():
    """
    Parse command line arguments
    """
    global verbose_mode
    verbose_mode = os.getenv("ENABLE_VERBOSE", False)


def parse_topology_xml(tpg_file_name: str) -> TopologyCfg:
    """
    Parse topology xml file
    """
    try:
        virsh_path = shutil.which("virsh")
        if virsh_path is None:
            raise Exception("virsh not found in PATH")

        result = subprocess.run(  # nosec
            [virsh_path, "domxml-to-native", "qemu-argv", tpg_file_name],
            stdout=subprocess.PIPE,
            shell=False,
        )
        result.check_returncode()
        libvirt_args = result.stdout.decode("utf-8").strip()

        tpg_cfg = {
            "name": re.search(r"guest=(\w+)", libvirt_args).group(1),
            "hmat": "hmat=on" in libvirt_args,
            "cpu_model": re.search(r"cpu (\S+)", libvirt_args).group(1),
            "cpu_options": re.search("(?=-smp)(.*)threads=[0-9]+", libvirt_args).group(
                0
            ),
            "mem_options": re.search(
                r"-object '{\"qom-type\":\"memory-backend-ram\".*(?=-uuid)",
                libvirt_args,
            ).group(0),
        }

        if verbose_mode != False:
            print(f"Name: {tpg_cfg['cpu_model']}")
            print(f"HMAT: {tpg_cfg['hmat']}")
            print(f"CPU_MODEL: {tpg_cfg['cpu_model']}")
            print(f"CPU_OPTIONS: {tpg_cfg['cpu_options']}")
            print(f"MEM_OPTIONS: {tpg_cfg['mem_options']}")

        tpg = TopologyCfg(**tpg_cfg)
    except subprocess.CalledProcessError:
        sys.exit(f"\n XML file: {tpg_file_name} error in virsh parsing")
    except Exception:
        sys.exit(f"\n Provided file is missing or missing virsh.")
    return tpg


def get_qemu_args(tpg_file_name: str) -> str:
    """
    Get QEMU arguments from topology xml file
    """
    tpg = parse_topology_xml(tpg_file_name)
    qemu_args = f"-name {tpg.name} {calculate_memory(tpg)} -cpu {tpg.cpu_model} {tpg.cpu_options} {tpg.mem_options}"
    return qemu_args


def calculate_memory(tpg: TopologyCfg) -> str:
    """
    Memory used by QEMU
    """
    if tpg.mem_options:
        mem_needed = 0
        all_sizes = re.findall(r'size":(\d+)', tpg.mem_options)
        for single_size in all_sizes:
            mem_needed += int(single_size)

        mem = psutil.virtual_memory()
        if mem_needed >= mem.total:
            raise MemoryHostException(mem.total, mem_needed, tpg.name)
        return f"-m {mem_needed/1024/1024}M"
    else:
        return "-m 2G"


if __name__ == "__main__":
    enable_verbose()

    if len(sys.argv) > 1:
        tpg_file_name = sys.argv[1]
    else:
        sys.exit(f"\n Usage: {sys.argv[0]} <tpg_file_name>")
    print(get_qemu_args(tpg_file_name))
