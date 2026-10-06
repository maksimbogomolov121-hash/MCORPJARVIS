from pathlib import Path
import sys


# ============================================================
# PATH
# ============================================================

CURRENT_FILE = Path(__file__).resolve()
SYNC_ROOT = CURRENT_FILE.parent
PROJECT_ROOT = SYNC_ROOT.parent


if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# IMPORTS
# ============================================================

from SYNC.sync_manager import SyncManager


# ============================================================
# TEST
# ============================================================

def main():

    print("=" * 70)
    print("JARVIS V11 - SAFE SYNC PLAN TEST")
    print("=" * 70)

    print()
    print("[1] Создаём SyncManager...")

    manager = SyncManager(
        root_path=PROJECT_ROOT
    )

    print("[+] SyncManager создан.")

    print()
    print("[2] Ищем устройства...")

    devices = manager.device_manager.get_devices(
        active_only=True
    )

    if not devices:
        print("[-] Активные устройства не найдены.")
        return

    print()

    for device in devices:

        print(
            f"  ID: {device.device_id}"
        )

        print(
            f"  TYPE: {device.device_type}"
        )

        print(
            f"  NAME: {device.name}"
        )

        print(
            f"  ROOT: {device.root_path}"
        )

        print()

    # --------------------------------------------------------
    # PC
    # --------------------------------------------------------

    pc_devices = [
        d for d in devices
        if d.device_type == "PC"
    ]

    if not pc_devices:

        print(
            "[-] PC устройство не найдено."
        )

        return

    pc = pc_devices[0]

    # --------------------------------------------------------
    # USB
    # --------------------------------------------------------

    usb_devices = [
        d for d in devices
        if d.device_type == "USB"
    ]

    if not usb_devices:

        print(
            "[-] USB устройство не найдено."
        )

        print()
        print(
            "Подключи JARVIS USB и запусти USB Detector."
        )

        return

    usb = usb_devices[0]

    print(
        "[+] PC найден:"
    )

    print(
        f"    {pc.device_id}"
    )

    print()

    print(
        "[+] USB найден:"
    )

    print(
        f"    {usb.device_id}"
    )

    print(
        f"    {usb.root_path}"
    )

    # ========================================================
    # ANALYZE ONLY
    # ========================================================

    print()
    print("=" * 70)
    print("АНАЛИЗ PC -> USB")
    print("=" * 70)

    print()
    print(
        "ВАЖНО: сейчас выполняется ТОЛЬКО ANALYZE."
    )

    print(
        "Файлы НЕ будут копироваться."
    )

    print(
        "Файлы НЕ будут удаляться."
    )

    print()

    plan = manager.analyze(
        source_device=pc.device_id,
        target_device=usb.device_id
    )

    # ========================================================
    # RESULT
    # ========================================================

    print()
    print("=" * 70)
    print("SYNC PLAN")
    print("=" * 70)

    print()

    print(
        f"Source: {plan.source_device}"
    )

    print(
        f"Target: {plan.target_device}"
    )

    print()

    print(
        f"Changes: {len(plan.changes)}"
    )

    print()

    if not plan.changes:

        print(
            "[+] Изменений для синхронизации не найдено."
        )

    else:

        for change in plan.changes:

            print(
                f"{change.change_type:10} "
                f"{change.path}"
            )

    print()
    print("=" * 70)
    print("TEST FINISHED")
    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()