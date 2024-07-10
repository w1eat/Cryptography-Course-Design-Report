#pragma once
#include<iostream>
#include<bitset>
using namespace std;
typedef bitset<8>type;
typedef bitset<32>word;
word H0 = 0x6a09e667;
word H1 = 0xbb67ae85;
word H2 = 0x3c6ef372;
word H3 = 0xa54ff53a;
word H4 = 0x510e527f;
word H5 = 0x9b05688c;
word H6 = 0x1f83d9ab;
word H7 = 0x5be0cd19;
word Secret[64] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
class SHA256
{
public:
	word XunHuanR(word h, int n) {
		word h1 = h;
		for (int i = 0; i < n; i++) {//循环右移
			bool t = h1[31];
			for (int j = 31; j > 0; j--)
				h1[j] = h1[j - 1];
			h1[0] = t;
		}
		return h1;
	}
	void tianchong(int n, word message[], word w[]) {
		int k = 32 * n;
		int a = k % 512;
		int N = k / 512;
		if (a < 448) {
			int x = ((N + 1) * 512) / 32;
			int y = ((N + 1) * 512);
			for (int i = 0; i < n; i++)w[i] ^= message[i];
			w[n] ^= word(0x80000000);
			bitset<64>temp(y);
			for (int i = 0; i < 32; i++)w[x - 1][i] = temp[i];
			for (int i = 0; i < 32; i++)w[x - 2][i] = temp[i + 32];
		}
		else {
			int x = ((N + 2) * 512) / 32;
			int y = ((N + 2) * 512);
			for (int i = 0; i < n; i++)w[i] ^= message[i];
			w[n] ^= word(0x80000000);
			bitset<64>temp(y);
			for (int i = 0; i < 32; i++)w[x - 1][i] = temp[i];
			for (int i = 0; i < 32; i++)w[x - 2][i] = temp[i + 32];
		}
	}

	//16个字扩散为64个
	//以下函数为主要函数
	word Ch(word h4, word h5, word h6) {
		word h;
		h = (h4 & h5) ^ ((h4.flip() & h6));
		return h;
	}
	word Ma(word h0, word h1, word h2) {
		word h;
		h = (h0 & h1) ^ (h0 & h2) ^ (h1 & h2);
		return h;
	}

	word sum0(word h0) {
		word h1, h2, h3;
		h1 = XunHuanR(h0, 2);
		h2 = XunHuanR(h0, 13);
		h3 = XunHuanR(h0, 22);
		return h1 ^ h2 ^ h3;
	}
	word sum1(word h4) {
		word h1, h2, h3;
		h1 = XunHuanR(h4, 6);
		h2 = XunHuanR(h4, 11);
		h3 = XunHuanR(h4, 25);
		return h1 ^ h2 ^ h3;
	}
	void kuosan(word m[16], word _m[64]) {
		for (int i = 0; i < 16; i++) {
			_m[i] ^= m[i];
		}
		for (int i = 16; i < 64; i++) {
			word s0 = (XunHuanR(_m[i - 15], 7) ^ XunHuanR(_m[i - 15], 15) ^ (_m[i - 15] >> 3));
			word s1 = (XunHuanR(_m[i - 2], 7) ^ XunHuanR(_m[i - 2], 19) ^ (_m[i - 15] >> 10));
			_m[i] = (_m[i - 16] ^ _m[i - 7] ^ s0 ^ s1);
		}
	}
	//64轮轮函数加密
	void F(word Secret[64], word messages[16]) {
		word m[64];
		kuosan(messages, m);
		for (int i = 0; i < 16; i++) {
			for (int j = i * 32; j < 32; j++) {
				m[i] = messages[j];
			}
		}
		for (int i = 0; i < 64; i++) {
			word h0, h4;
			h4 = (m[i] ^ Secret[i] ^ (Ch(H4, H5, H6) ^ H7) ^ sum1(H4) ^ H3);
			h0 = (m[i] ^ Secret[i] ^ (Ch(H4, H5, H6) ^ H7) ^ sum1(H4) ^ Ma(H0, H1, H2) ^ sum0(H0));
			H1 = H0, H2 = H1, H3 = H2, H5 = H4, H6 = H5, H7 = H6;
			H0 = h0, H4 = h4;
		}
	}
	void SHA_Encode(word message[],int len) {
		int n;
		if((len*32)%512<448)n = (len * 32 / 512) + 2;
		else n= (len * 32 / 512) + 1;

		int k = n * 512 / 32;
		word _m[16];
		tianchong(len, message, _m);
		word tem[16];
		//cout << "要加密的数据" << endl;
		//for (int i = 0; i < len; i++)cout << message[i].to_ulong() << endl;
			F(Secret, _m);
		cout << "结果" << endl;
		cout << H0.to_ulong() << endl << H1.to_ulong() << endl << H2.to_ulong() << endl << H3.to_ulong() <<
			endl << H4.to_ulong() << endl << H5.to_ulong() << endl << H6.to_ulong() << endl << H7.to_ulong() << endl;
	}

};

