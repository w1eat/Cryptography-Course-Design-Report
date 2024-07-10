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
		cout << "正在注册CA" << endl;
		ofstream fout("CA.txt");
		if (!fout) {
			cout << "注册失败" << endl;
		}
		fout  << publickey << "\n"  << privatekey << endl;
		cout << "注册通过" << endl;
		fout.close();
	}
	void CAOUT(RSA rsa) {
		ZZ a;
		ZZ b;
		cout << "正在获取公钥" << endl;
		ifstream fin("CA.txt");
		if (!fin) {
			cout << "获取失败" << endl;
		}
		fin >> a;
		fin >> b;
		cout << "获取成功" << endl;
		rsa.chagePublickey(b);
		cout <<"公钥为" << b << endl;
		fin.close();
	}
};

