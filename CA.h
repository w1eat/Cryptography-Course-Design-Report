#pragma once
#include<NTL/ZZ.h>
#include<iostream>
#include<fstream>
#include<string>
using namespace std;
NTL_CLIENT
class CA
{
public:
	void CAIN(ZZ publickey, ZZ privatekey) {
		cout << "����ע��CA" << endl;
		ofstream fout("CA.txt");
		if (!fout) {
			cout << "ע��ʧ��" << endl;
		}
		fout  << publickey << "\n"  << privatekey << endl;
		cout << "ע��ͨ��" << endl;
		fout.close();
	}
	void CAOUT(RSA rsa) {
		ZZ a;
		ZZ b;
		cout << "���ڻ�ȡ��Կ" << endl;
		ifstream fin("CA.txt");
		if (!fin) {
			cout << "��ȡʧ��" << endl;
		}
		fin >> a;
		fin >> b;
		cout << "��ȡ�ɹ�" << endl;
		rsa.chagePublickey(b);
		cout <<"��ԿΪ" << b << endl;
		fin.close();
	}
};

