#pragma once
#include <iostream>
#include<math.h>
#include<stdlib.h>
#include<NTL/ZZ.h>
using namespace std;
NTL_CLIENT//using namespace NTL;
class RSA
{
    ZZ p, q;
    ZZ e,n;
    ZZ d;
public:
    ZZ getPublickey() {
        return e;
    }
    ZZ getPrivatekey() {
        return d;
    }
    void chagePublickey(ZZ s) {
        e = s;
    }
    RSA(){
        GenGermainPrime(p, 350);
        GenGermainPrime(q, 350);
        cout << "生成数p和q:" << endl;
        cout << p << endl << q << endl;
        n = p * q;
        ZZ fn = (p - 1) * (q - 1);
        cout << "n的值：" << endl;
        cout << n << endl;
        while (1) {
            e = GenGermainPrime_ZZ(100);
            if (GCD(e, fn) == 1)break;
        }
        cout << "生成公钥e:" << e << endl;
        d = InvMod(e, fn);

    }
        ZZ RSA_ENCODE(ZZ m){ 
        ZZ c = PowerMod(m, e, n);
        return c;
    }
        ZZ RSA_DECODE(ZZ c) {
           ZZ m = PowerMod(c, d, n);
            return m;
        }
};

