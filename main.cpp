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
        cout << "=== ����ͨ��ϵͳ ===" << endl;
        cout << "1. ������Ϣ" << endl;
        cout << "2. �˳�" << endl;
        cout << "===================" << endl;
        cout << "��ѡ�������";
    }

    void sendMessage() {
        string studentID, name, className;
        cout << "������12λѧ�ţ�";
        cin >> studentID;
        cout << "������������";
        cin >> name;
        cout << "������༶��";
        cin >> className;


        //AES����
            byte plain[16] = { byte(studentID[0]),byte(studentID[1]),byte(studentID[2]),byte(studentID[3]),
                byte(studentID[4]),byte(studentID[5]),byte(studentID[6]),byte(studentID[7]),
                byte(studentID[8]),byte(studentID[9]),byte(studentID[10]),byte(studentID[11]),
                byte(name[0]),byte(name[1]),byte(name[2]),byte(className[0])
            };
      
        AES aes;
        word w[4 * (Nr + 1)];   //w�������ڴ洢����Կ�֣�128bit��Կ�湲ʹ��11������Կ��ÿ������Կ128bit=4*32bit�����һ��44������Կ��
        aes.KeyExpansion(key, w);  //��Կ��չ������ʵ�ִ�������Կkey��11������Կw����չ
                // ��������ܵ�����
        cout << endl << "�����ܵ����ģ�" << endl;
        for (int i = 0; i < 16; ++i)
        {
           cout << hex <<plain[i].to_ulong() << " ";
            if ((i + 1) % 4 == 0)
                cout << endl;
        }
        cout << endl;

            // aes���ܣ��������
            aes.encrypt(plain, w);             //��������plain������Կ����w������ܺ��������ܵõ����ģ��Դ����plain�����У�
            cout << "aes���ܺ�����ģ�" << endl;
            for (int i = 0; i < 16; ++i)
            {
                cout << hex << plain[i].to_ulong() << " ";
                if ((i + 1) % 4 == 0)
                    cout << endl;
            }
            cout << endl;
            cout << "===================" << endl;
            int choice;
            cout << "��ѡ�������õĹ�Կ�����㷨��1��RSA,2:ELGamal,3:SM2��";
            cin >> choice;
            ZZ m;
            //��ʼ��RSA
            ZZ c[16];
            RSA rsa;
            //��ʼ��ELGamal����ʹ���
            ELGamal elgamal;
            ZZ _c1[16], _c2[16];


            if (choice == 1) {
                cout << "===================" << endl;
                cout << "RSA�����У���ȴ�" << endl;
                //RSA����w

                //֤���ȡ��Կ
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
                cout << "ELGamal�����У���ȴ�" << endl;
                for (int i = 0; i < 16; i++) {
                    m = plain[i].to_ulong();
                    elgamal.ElGamal_Encode(m);
                    _c1[i] = elgamal.c1;
                    _c2[i] = elgamal.c2;
                }
            }
            //ELGamalǩ��
            //����message��Ϊǩ��
            cout << "===================" << endl;
            cout << "ELGamalǩ���У���ȴ�" << endl;
            cout << "===================" << endl;
            cout << "SHA256���ܴ���" << endl;
            word message[2] = { 0x428a2f98, 0x71374491};
            SHA256 sha;
            sha.SHA_Encode(message,2);
            cout << "��ʼǩ��" << endl;
            ZZ el=elgamal.ElGamal_QM();
            cout << "����ǩ��" << endl;
            //��֤ǩ��
            elgamal.ElGamal_YZ(el);
            cout << "��Ϣ�ѷ��ͣ�" << endl;
        // ��������������Ϣ���ܺͷ����߼�
            if (choice == 1) {
                //rsa����
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
         //aes����
            aes.decrypt(plain, w);

                cout << "���ܺ�����ģ�" << endl;
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
    cout <<"���ܵ���ѧ�ţ�"<< studentID << endl;
    cout << "���ܵ���ѧ��������" << name << endl;
    cout << "�༶��" << className << endl;
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
                cout << "ϵͳ���˳���" << endl;
                break;
            default:
                cout << "��Ч��ѡ�����������롣" << endl;
                break;
            }
        } while (choice != 2);

        return 0;
    }


