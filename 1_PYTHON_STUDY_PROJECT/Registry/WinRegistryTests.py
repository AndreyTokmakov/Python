from Registry.WinRegistry import WinRegistry
from Registry.WinRegistry import WinRegistryAssert;
import winreg;

########################################################################

def Test():
    regKey = WinRegistry.GetRegistryKey("HKEY_CURRENT_USER", "Software\\Atom");
    if regKey is None:
        return;
    
    param = WinRegistry.GetRegistryKeyParam(regKey, "pv");
    
    print(param.name);
    print(param.value);
    print(param.type);
    
    regKey = WinRegistry.GetRegistryKey("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mail.Ru Atom");
    if regKey is None:
        return;
    
    param = WinRegistry.GetRegistryKeyParam(regKey, "Version");
    
    print(param.name);
    print(param.value);
    print(param.type);
    
    
def AsstertsTest():
    WinRegistryAssert.AssertKeyParamValue("HKEY_CURRENT_USER", "Software\\Atom", "pv", "3.1.0.82", winreg.REG_SZ);

########################################################################
if __name__ == '__main__':
    #Test();
    AsstertsTest();