#pragma once
/*************************************************************************
> File Name: AEScpp
************************************************************************/
#include <iostream>
#include <bitset>   // C++的 bitset 模板类基本用法
#include <string>
using namespace std;
typedef bitset<8> byte;  //重命名bitset<8>模板类为byte
typedef bitset<32> word;  //重命名bitset<32>模板类word
const int Nr = 10; // AES-128需要 10 轮加密
const int Nk = 4;  // Nk 表示输入密钥的 word 个数

//下面定义并初始化AES中的S盒（加密时使用），S盒用byte型的二维数组（16×16）来处理
byte S_Box[16][16] = {
  {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
  {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
  {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
  {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
  {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
  {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
  {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
  {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
  {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
  {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
  {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
  {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
  {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
  {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
  {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
  {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

//下面定义并初始化AES中解密密时使用的S盒
byte Inv_S_Box[16][16] = {
  {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
  {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
  {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
  {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
  {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
  {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
  {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
  {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
  {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
  {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
  {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
  {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
  {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
  {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
  {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
  {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

// 轮常数，密钥扩展中用到。轮常数是32bit的常量，AES-128只需要10轮，故定义为长度为10的word数组
word Rcon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
         0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };
    byte key[16] = { 0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c };
class AES
{
   
    /******************************下面是加密的变换函数**********************/
    /**
    * 对状态矩阵中每个元素进行S盒代换 - 元素下标的高位4位为行号，下标的低位4位为列号
    回忆：    bitset<8> b(0x19);    //十六进制表示的19，二进制为00011001
    那么，b[0]=1, b[1]=0, b[2]=0, b[3]=1, b[4]=1, b[5]=0, b[6]=0, b[7]=0，所以，用下标法表示b的每个bit的话对应方法是：
    十六进制表示的19
    二进制为0001 1001
    b[7]b[6]b[5]b[4] b[3]b[2]b[1]b[0]
    */
public:
    void SubBytes(byte mtx[4 * 4])
    {
        for (int i = 0; i < 16; ++i)
        {
            int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];  //
            int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
            mtx[i] = S_Box[row][col];
        }
    }//传入mtx明文每八位为一组将byte前四位和后四位分别转化为10进制查表替换

    /**
    * 行变换 - 按字节循环移位
    */
    void ShiftRows(byte mtx[4 * 4])
    {
        // 第一行不动mtx[0]-[3]不做任何处理
        /*
        for(int i=0;i<n;i++){
        byte temp=mtx[0];
        for(int j=1;j<4;j++)
        mtx[j-1]=mtx[j];
        mtx[4]=temp;
        }
        */

        // 第二行循环左移一位
        byte temp = mtx[4];
        for (int i = 0; i < 3; ++i)
            mtx[i + 4] = mtx[i + 5];
        mtx[7] = temp;

        // 第三行循环左移两位
        for (int i = 0; i < 2; ++i)
        {
            temp = mtx[i + 8];
            mtx[i + 8] = mtx[i + 10];
            mtx[i + 10] = temp;
        }

        // 第四行循环左移三位
        temp = mtx[15];
        for (int i = 3; i > 0; --i)
            mtx[i + 12] = mtx[i + 11];
        mtx[12] = temp;
    }

    /**
    * 下面定义GFMul函数，实现有限域上的乘法 GF(2^8)，在列混合这一步骤中使用
    * 函数输入为两个GF(2^8)中元素a和b，输出为a*b mod m(x)（模m(x)的多项式乘法）
    * 其中a的多项式形式是a[7]x^7+a[6]x^6+a[5]x^5+a[4]x^4+a[3]x^3+a[2]x^2+a[1]x+a[0]
    */
    byte GFMul(byte a, byte b) {
        byte p = 0;                 //定义p，用来保存a*b mod m(x)的计算结果
        byte hi_bit_set;
        for (int counter = 0; counter < 8; counter++) {   //根据b的每一项的值是0还是1决定执行下面操作的三项还是两项
      /**
      a*b mod m(x)根据b的各项的值由以下三个操作构成：
      1.把a加到结果p上（b[0]为1时做，为0时不做）
      2.将a左移1位
      3.如果左移后a的最高次数为8，将a模m(x)
      */
            if ((b & byte(1)) != 0) {           //判断b[0]如果为1
                p ^= a;           //把当前的a加到p上（GF(2)中加法操作就是异或操作）
            }
            hi_bit_set = (byte)(a & byte(0x80));       //hi_bit_set只保留a[7]的值，其他位为0
            a <<= 1;         //把当前的a左移1位，相当于做了一次乘以x操作
            if (hi_bit_set != 0) {           //如果左移前a[7]的值为1，左移1位后，真实的多项式将有x^8项，需要进行一次mod m(x)操作
                a ^= byte(0x1b);    //实现模m(x)= x^8 + x^4 + x^3 + x + 1，x^8不需要处理
            }
            b >>= 1;               //把当前的b右移1位，准备进行下一次循环
        }
        return p;
    }

    /**
    * 列混合
    */
    void MixColumns(byte mtx[4 * 4])
    {
        byte arr[4];       //定义长度为4的一维byte数组用来装待处理的一列
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)   //将待处理的一列装入arr
                arr[j] = mtx[i + j * 4];


            mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];      //与矩阵第一行（02 03 01 01）做内积运算得到新的一列的第一个元素
            mtx[i + 4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
            mtx[i + 8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
            mtx[i + 12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
        }
    }

    /**
    * 轮密钥加变换 - 将每一列与扩展密钥进行异或
    */
    void AddRoundKey(byte mtx[4 * 4], word k[4])
    {
        for (int i = 0; i < 4; ++i)
        {
            //k[i]是word（32bit），首先要拆解出4个byte      
            word k1 = k[i] >> 24;                          // k1的最右侧8bit就是k[i]最左侧的8bit
            word k2 = (k[i] << 8) >> 24;
            word k3 = (k[i] << 16) >> 24;
            word k4 = (k[i] << 24) >> 24;

            mtx[i] = mtx[i] ^ byte(k1.to_ulong());               // byte(k1.to_ulong())可以将k1由word类型变成byte类型
            mtx[i + 4] = mtx[i + 4] ^ byte(k2.to_ulong());
            mtx[i + 8] = mtx[i + 8] ^ byte(k3.to_ulong());
            mtx[i + 12] = mtx[i + 12] ^ byte(k4.to_ulong());
        }
    }

    /**************************下面是解密的逆变换函数***********************/
    /**
    * 逆S盒变换
    */
    void InvSubBytes(byte mtx[4 * 4])
    {
        for (int i = 0; i < 16; ++i)
        {
            int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
            int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
            mtx[i] = Inv_S_Box[row][col];
        }
    }

    /**
    * 逆行变换 - 以字节为单位循环右移
    */
    void InvShiftRows(byte mtx[4 * 4])
    {
        // 第二行循环右移一位
        byte temp = mtx[7];
        for (int i = 3; i > 0; --i)
            mtx[i + 4] = mtx[i + 3];
        mtx[4] = temp;
        // 第三行循环右移两位
        for (int i = 0; i < 2; ++i)
        {
            temp = mtx[i + 8];
            mtx[i + 8] = mtx[i + 10];
            mtx[i + 10] = temp;
        }
        // 第四行循环右移三位
        temp = mtx[12];
        for (int i = 0; i < 3; ++i)
            mtx[i + 12] = mtx[i + 13];
        mtx[15] = temp;
    }
    //列混合
    void InvMixColumns(byte mtx[4 * 4])
    {
        byte arr[4];
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
                arr[j] = mtx[i + j * 4];

            mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
            mtx[i + 4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
            mtx[i + 8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
            mtx[i + 12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
        }
    }

    /******************************下面是密钥扩展部分***********************/
    /**
    * Word函数：将4个 byte 转换为一个 word
    */
    word Word(byte& k1, byte& k2, byte& k3, byte& k4)
    {
        word result(0x00000000);
        word temp;
        temp = k1.to_ulong(); // K1
        temp <<= 24;
        result |= temp;
        temp = k2.to_ulong(); // K2
        temp <<= 16;
        result |= temp;
        temp = k3.to_ulong(); // K3
        temp <<= 8;
        result |= temp;
        temp = k4.to_ulong(); // K4
        result |= temp;
        return result;
    }

    /**
    * 按字节 循环左移一个字节
    * 即把[a0, a1, a2, a3]变成[a1, a2, a3, a0]
    */
    word RotWord(word& rw)
    {
        word high = rw << 8;    //rw << 8得到[a1, a2, a3, 00]
        word low = rw >> 24;    //rw >> 24得到[00, 00, 00, a0]
        return high | low;
    }

    /**
    * 对输入word中的每一个字节进行S-盒变换
    */
    word SubWord(word& sw)
    {
        word temp;
        for (int i = 0; i < 32; i += 8)    //每8个比特为一组（一次循环），进行S盒代换
        {
            int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
            int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
            byte val = S_Box[row][col];           //得到S盒代换结果放到byte型val中
            for (int j = 0; j < 8; ++j)                 // 把byte型val放到word型temp的合适的位置
                temp[i + j] = val[j];
        }
        return temp;
    }

    /**
    * 密钥扩展函数 - 对128位密钥进行扩展得到 w[4*(Nr+1)]
    * 密
    */
    void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)])
    {
        word temp;
        int i = 0;
        // w[]的前4个就是输入的key//原样输入
        while (i < Nk)
        {
            w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
            ++i;
        }

        i = Nk;

        while (i < 4 * (Nr + 1))
        {
            temp = w[i - 1]; // 记录前一个word
            if (i % Nk == 0)//如果是子密钥的第一列要先循环移位在S盒变换在异或
            {
                word after_rw;
                after_rw = RotWord(temp);
                w[i] = w[i - Nk] ^ SubWord(after_rw) ^ Rcon[i / Nk - 1];
            }

            else
                w[i] = w[i - Nk] ^ temp;
            ++i;
        }
    }

    /******************************下面是加密和解密函数**************************/
    /**
    * 加密函数
    * 参数是一个长度为16的byte型数组和一个长度为44的word型扩展密钥数组（传址）
    */
    void encrypt(byte in[4 * 4], word w[4 * (Nr + 1)])
    {
        word key[4];      //存放每次要使用的一组轮密钥
        for (int i = 0; i < 4; ++i)    //取出第一次要使用的一组轮密钥
            key[i] = w[i];
        AddRoundKey(in, key);//明文先做一次轮密钥加变换

        for (int round = 1; round < Nr; ++round)//前9次次循环
        {
            SubBytes(in);      //S盒变换
            ShiftRows(in);     //行变换
            MixColumns(in);    //列混合
            for (int i = 0; i < 4; ++i)
                key[i] = w[4 * round + i];//取下一次的密钥
            AddRoundKey(in, key); //循环末尾轮密钥加变换
        }
        //最后一次循环无列混合 
        SubBytes(in);
        ShiftRows(in);
        for (int i = 0; i < 4; ++i)
            key[i] = w[4 * Nr + i];
        AddRoundKey(in, key);
    }

    /**
    * 解密
    */
    void decrypt(byte in[4 * 4], word w[4 * (Nr + 1)])
    {
        word key[4];
        for (int i = 0; i < 4; ++i)
            key[i] = w[4 * Nr + i];
        AddRoundKey(in, key);

        for (int round = Nr - 1; round > 0; --round)
        {
            InvShiftRows(in);
            InvSubBytes(in);
            for (int i = 0; i < 4; ++i)
                key[i] = w[4 * round + i];
            AddRoundKey(in, key);
            InvMixColumns(in);
        }

        InvShiftRows(in);
        InvSubBytes(in);
        for (int i = 0; i < 4; ++i)
            key[i] = w[i];
        AddRoundKey(in, key);
    }

    /**********************************************************************/
    /*                                  */
    /*               测试                 */
    /*                                  */
    /**********************************************************************/
    //int main()
    //{


    //    byte plain[16] = { 0x32, 0x88, 0x31, 0xe0,
    //            0x43, 0x5a, 0x31, 0x37,
    //            0xf6, 0x30, 0x98, 0x07,
    //            0xa8, 0x8d, 0xa2, 0x34 };
    //    // 输出密钥
    //    cout << "密钥是：";
    //    for (int i = 0; i < 16; ++i)
    //        cout << hex << key[i].to_ulong() << " ";
    //    cout << endl;

    //    word w[4 * (Nr + 1)];   //w数组用于存储轮密钥字（128bit密钥版共使用11个轮密钥，每个轮密钥128bit=4*32bit，因此一共44个轮密钥字
    //    KeyExpansion(key, w);  //密钥扩展函数，实现从种子密钥key到11个轮密钥w的扩展

    //    // 输出待加密的明文
    //    cout << endl << "待加密的明文：" << endl;
    //    for (int i = 0; i < 16; ++i)
    //    {
    //        cout << hex << plain[i].to_ulong() << " ";
    //        if ((i + 1) % 4 == 0)
    //            cout << endl;
    //    }
    //    cout << endl;

    //    // 加密，输出密文
    //    encrypt(plain, w);             //明文数组plain和轮密钥数组w输入加密函数，加密得到密文（仍存放在plain数组中）
    //    cout << "加密后的密文：" << endl;
    //    for (int i = 0; i < 16; ++i)
    //    {
    //        cout << hex << plain[i].to_ulong() << " ";
    //        if ((i + 1) % 4 == 0)
    //            cout << endl;
    //    }
    //    cout << endl;

    //    // 解密，输出明文
    //    decrypt(plain, w);
    //    cout << "解密后的明文：" << endl;
    //    for (int i = 0; i < 16; ++i)
    //    {
    //        cout << hex << plain[i].to_ulong() << " ";
    //        if ((i + 1) % 4 == 0)
    //            cout << endl;
    //    }
    //    cout << endl;
    //    return 0;
    //}
};

