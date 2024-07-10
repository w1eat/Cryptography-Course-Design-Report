#include "AES.h"
#include "RSA.h"
#include "CA.h"
#include "ELGamal.h"
#include "SHA256.h"
#include<NTL/ZZ.h>
#include<iostream>
#include<string>
using namespace std;
NTL_CLIENT
    void displayMenu(){
        cout << "=== 保密通信系统 ===" << endl;
        cout << "1. 发送消息" << endl;
        cout << "2. 退出" << endl;
        cout << "===================" << endl;
        cout << "请选择操作：";
    }

    void sendMessage() {
        string studentID, name, className;
        cout << "请输入12位学号：";
        cin >> studentID;
        cout << "请输入姓名：";
        cin >> name;
        cout << "请输入班级：";
        cin >> className;


        //AES加密
            byte plain[16] = { byte(studentID[0]),byte(studentID[1]),byte(studentID[2]),byte(studentID[3]),
                byte(studentID[4]),byte(studentID[5]),byte(studentID[6]),byte(studentID[7]),
                byte(studentID[8]),byte(studentID[9]),byte(studentID[10]),byte(studentID[11]),
                byte(name[0]),byte(name[1]),byte(name[2]),byte(className[0])
            };
      
        AES aes;
        word w[4 * (Nr + 1)];   //w数组用于存储轮密钥字（128bit密钥版共使用11个轮密钥，每个轮密钥128bit=4*32bit，因此一共44个轮密钥字
        aes.KeyExpansion(key, w);  //密钥扩展函数，实现从种子密钥key到11个轮密钥w的扩展
                // 输出待加密的明文
        cout << endl << "待加密的明文：" << endl;
        for (int i = 0; i < 16; ++i)
        {
           cout << hex <<plain[i].to_ulong() << " ";
            if ((i + 1) % 4 == 0)
                cout << endl;
        }
        cout << endl;

            // aes加密，输出密文
            aes.encrypt(plain, w);             //明文数组plain和轮密钥数组w输入加密函数，加密得到密文（仍存放在plain数组中）
            cout << "aes加密后的密文：" << endl;
            for (int i = 0; i < 16; ++i)
            {
                cout << hex << plain[i].to_ulong() << " ";
                if ((i + 1) % 4 == 0)
                    cout << endl;
            }
            cout << endl;
            cout << "===================" << endl;
            int choice;
            cout << "请选择你想用的公钥加密算法：1：RSA,2:ELGamal,3:SM2：";
            cin >> choice;
            ZZ m;
            //初始化RSA
            ZZ c[16];
            RSA rsa;
            //初始化ELGamal对象和储存
            ELGamal elgamal;
            ZZ _c1[16], _c2[16];


            if (choice == 1) {
                cout << "===================" << endl;
                cout << "RSA加密中，请等待" << endl;
                //RSA加密w

                //证书获取公钥
                CA ca;
                ca.CAIN(rsa.getPublickey(), rsa.getPrivatekey());
                ca.CAOUT(rsa);
                for (int i = 0; i < 16; i++) {
                    m = plain[i].to_ulong();
                    c[i] = rsa.RSA_ENCODE(m);
                }
            }
            else if (choice == 2) {
                cout << "===================" << endl;
                cout << "ELGamal加密中，请等待" << endl;
                for (int i = 0; i < 16; i++) {
                    m = plain[i].to_ulong();
                    elgamal.ElGamal_Encode(m);
                    _c1[i] = elgamal.c1;
                    _c2[i] = elgamal.c2;
                }
            }
            //ELGamal签名
            //传入message作为签名
            cout << "===================" << endl;
            cout << "ELGamal签名中，请等待" << endl;
            cout << "===================" << endl;
            cout << "SHA256加密传入" << endl;
            word message[2] = { 0x428a2f98, 0x71374491};
            SHA256 sha;
            sha.SHA_Encode(message,2);
            cout << "开始签名" << endl;
            ZZ el=elgamal.ElGamal_QM();
            cout << "发送签名" << endl;
            //验证签名
            elgamal.ElGamal_YZ(el);
            cout << "消息已发送！" << endl;
        // 在这里添加你的消息解密和发送逻辑
            if (choice == 1) {
                //rsa解密
                for (int i = 0; i < 16; i++) {
                    m = rsa.RSA_DECODE(c[i]);
                    int _m = conv<int>(m);
                    plain[i] = byte(_m);
                }
            }
            else if (choice == 2) {
                for (int i = 0; i < 16; i++) {
                    m = elgamal.ElGamal_Decode(_c1[i],_c2[i]);
                    int _m = conv<int>(m);
                    plain[i] = byte(_m);
                }
            }
         //aes解密
            aes.decrypt(plain, w);

                cout << "解密后的明文：" << endl;
    for (int i = 0; i < 12; ++i)
    {
        studentID[i] = char(plain[i].to_ulong());
    }
    for (int i = 12; i < 15; ++i)
    {
        name[i-12] = char(plain[i].to_ulong());
    }
    className[0]= char(plain[15].to_ulong());
    cout << endl;
    cout <<"接受到的学号："<< studentID << endl;
    cout << "接受到的学生姓名：" << name << endl;
    cout << "班级：" << className << endl;
    }

    int main() {
        int choice;

        do {
            displayMenu();
            cin >> choice;

            switch (choice) {
            case 1:
                sendMessage();
                break;
            case 2:
                cout << "系统已退出。" << endl;
                break;
            default:
                cout << "无效的选择，请重新输入。" << endl;
                break;
            }
        } while (choice != 2);

        return 0;
    }


