from Funcs import Test;
import inspect, re


def get_variable_name(variable):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)


def get_variable_name_1(obj):
    return [name for name in globals() if globals()[name] is obj][0]


def AssertTrue(var):
    # var_name = get_variable_name(var);
    var_name = get_variable_name_1(var)
    print(var_name, " = ", var)


########################################

if __name__ == '__main__':
    result = True
    AssertTrue(result);
    # Test()
