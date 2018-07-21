#include <iostream>
#include <string>
#include <vector>
#include "ErfReader.h"

std::vector<std::string> foo(std::string Strats)
{
    std::vector<std::string> StrategyNames;
    // Can't figure out how to do .asStringList() with docopt..  maybe TODO?
    int Start = 0;
    size_t End = Strats.find(',');
    while (End != std::string::npos)
    {
        auto SS = Strats.substr(Start, End - Start);
        StrategyNames.push_back(SS);
        Start = End+1;
        End = Strats.find(',', Start);
    }
    auto SS = Strats.substr(Start);
    if (!SS.empty())
        StrategyNames.push_back(SS);

    return StrategyNames;
}

void print(std::vector<std::string> v)
{
    std::cout << v.size() << ": ";
    for (auto s : v)
    {
        std::cout << s << ' ';
    }
    std::cout << std::endl;
}


int main()
{
    ErfReader reader("\\ch-dv-cap-1.priv.dvtrading.co\Duma\2018_07_20\orders_1532057400_1532057700.erf", true);
    reader.processFile([](const Packet& p) { std::cout << "packet" << std::endl; });
    return 0;
}