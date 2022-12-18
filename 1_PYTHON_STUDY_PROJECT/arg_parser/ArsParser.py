import argparse


def No_Value_Param():
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--stand_alone", action="store_true", 
                       default=False, help = "Stand alone mode. Run tests localy without kafka.")
    args = parser.parse_args()
    print(args)
    

if __name__ == '__main__':
        parser = argparse.ArgumentParser()

        parser.add_argument("-t",  "--test",
                            help = "The test suite name",
                            type = str, required = True);

        parser.add_argument("-w", "--workdir",
                            help = "The path of the work directory", default = "C:\\chromium\\src",
                            type = str, required = False);

        parser.add_argument("-b", "--builddir",
                            help = "The path of the build and binaries directory", default = "out\\Debug",
                            type = str, required = False);

        parser.add_argument("-d",  "--depot_tools",
                            help = "The DEPOT_TOOLS directory path.", default = "C:\\depot_tools",
                            type = str, required = False);

        parser.add_argument("-f",  "--filters",
                            help = "The path of the gtest filters configuration directory", default = "C:\\Temp\\UnitTestsFilters",
                            type = str, required = False);

        parser.add_argument("-m",  "--bot_mode",
                            help = "Run tests in bot mode", default = "False",
                            type = str, required = False);

        parser.add_argument("-r",  "--retry_limit",
                            help = "The max number of attempts to run a nasty failed tests", default = "3",
                            type = str, required = False);

        options = parser.parse_args(); 
          
        workDirectory = options.workdir;
        buildDirectory = options.builddir;        
        testName = options.test;
        depotToolsPath = options.depot_tools;
        testFiltersDirectory = options.filters;
        failedTestsRetryLimit = options.retry_limit;
        runInBotMode = options.bot_mode.lower() in ("true", "yes", "1");
        
        
        print("workDirectory = ", workDirectory);
        print("buildDirectory = ", buildDirectory);
        print("testName = ", testName);
        print("depotToolsPath = ", depotToolsPath);
        print("testFiltersDirectory = ", testFiltersDirectory);  
        print("failedTestsRetryLimit = ", failedTestsRetryLimit);
        print("runInBotMode = ", runInBotMode);

        
        intRetLim = 3;
        try:
            intRetLim = int(failedTestsRetryLimit);
        except:
            print("Failed to cast value '", failedTestsRetryLimit, "' to Integer");
     
        print("failedTestsRetryLimit = ", intRetLim);
        
        if intRetLim is not 3:
            print ("intRetLim is not 3")
        
        