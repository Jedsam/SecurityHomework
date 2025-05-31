#include <fstream>
#define ELLYPTIC_CURVE_NAME "ecc.txt"
class ecc {
private:
    static std::ofstream ecc_file;
    static int p;
    static int a;
    static int b;
    static int G;
    static int n;
    static int h;

    static void Initialize() {
        ecc_file.open(ELLYPTIC_CURVE_NAME, std::ios::in);

    }
};
