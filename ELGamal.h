#pragma once
#include "SHA256.h"
class ELGamal
{
	ZZ p, q;
	ZZ g;
	ZZ x;
	ZZ y;
	ZZ r, s;
public:
	ZZ c1, c2;
	ELGamal() {

		GenGermainPrime(q, 100);
		p = 2 * q + 1;

		for (g = GenGermainPrime_ZZ(10);; g++)
		{

			if (g % 2 != 1 && g % q != 1)break;
		}
		cout << p << " " << q << endl;
		while (1) {
			GenGermainPrime(x, 100);
			if (x >= 1 && x <= p - 2)break;
		}
		y = PowerMod(g, x, p);
		cout << "����Ԫ:" << g << endl;
		cout << "��ԿΪy:" << y << ",˽ԿΪx:" << x << endl;
	}
	void ElGamal_Encode(ZZ m)
	{
		ZZ k;
		GenGermainPrime(k, 100);
		cout << "��������:" << m << endl;
		c1 = PowerMod(g, k, p);
		c2 = (PowerMod(y, k, p) * (m % p)) % p;
		cout << "��������Ϊ(" << c1 << "," << c2 << ")" << endl;
	}
	ZZ ElGamal_Decode(ZZ c1,ZZ c2){
		ZZ s = PowerMod(c1, x, p);//c1��x�η�
		ZZ h=InvMod(s,p);//s����Ԫ
		ZZ m = ((c2%p)*h)%p ;//(c1/c2^x)%pת��Ϊ�˷�
		return m;
	}
	ZZ ElGamal_QM() {
		ZZ m0, m1, m2, m3, m4, m5, m6, m7;
		m0 = H0.to_ulong();
		m1 = H1.to_ulong();
		m2 = H2.to_ulong();
		m3 = H3.to_ulong();
		m4 = H4.to_ulong();
		m5 = H5.to_ulong();
		m6 = H6.to_ulong();
		m7 = H7.to_ulong();
		ZZ m;
		m = m0 * power_ZZ(10, 70) + m1 * power_ZZ(10, 60) + m2 * power_ZZ(10, 50) + m3 * power_ZZ(10, 40) + m4 * power_ZZ(10, 30) +
			m5 * power_ZZ(10, 20) + m6 * power_ZZ(10, 10) + m7;
		cout << "Ҫǩ���ľ�����ϣ���ܵ�����:" << endl << m << endl;
		cout << "����Ԫ:" << g << endl;
		cout << "��ԿΪy:" << y << ",˽ԿΪx:" << x << endl;
		ZZ _k;//���ѡȡ����
		while (1) {
			GenGermainPrime(_k, 100);
			if (_k >= 1 && _k <= p - 2 && GCD(_k, p - 1) == 1)break;

		}
		r = PowerMod(g, _k, p);
		s = ((m - x * r) * InvMod(_k, p - 1)) % (p - 1);
		cout << s << endl;
		cout << "����ǩ��Ϊ: (" << r << "," << s << ")" << endl;
		return m;
	}
	void ElGamal_YZ(ZZ m){
		cout << "��֤ǩ��" << endl;
		if ((PowerMod(y, r, p) * PowerMod(r, s, p)) % p == PowerMod(g, m, p)) {
			cout << "��֤�ɹ�" << endl;

		}
		else
		{
			cout << PowerMod(y, r, p) * PowerMod(r, s, p) << endl;
			cout << PowerMod(g, m, p);
			cout << "��֤ʧ��" << endl;
		}

	}
	
};

