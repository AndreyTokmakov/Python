import psutil
from SystemInformation.Utlities import Utilities

if __name__ == '__main__':

    # Memory Information
    print("=" * 40, "Memory Information", "=" * 40)

    # get the memory details
    svmem = psutil.virtual_memory()
    print(f"Total: {Utilities.get_size(svmem.total)}")
    print(f"Available: {Utilities.get_size(svmem.available)}")
    print(f"Used: {Utilities.get_size(svmem.used)}")
    print(f"Percentage: {svmem.percent}%")
    print("=" * 20, "SWAP", "=" * 20)

    # get the swap memory details (if exists)
    swap = psutil.swap_memory()
    print(f"Total: {Utilities.get_size(swap.total)}")
    print(f"Free: {Utilities.get_size(swap.free)}")
    print(f"Used: {Utilities.get_size(swap.used)}")
    print(f"Percentage: {swap.percent}%")

    pass