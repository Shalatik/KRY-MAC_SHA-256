// Simona Ceskova xcesko00
// 30.04.2024
// KRY 2

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <bitset>
#include <bit>
#include <cstdint>
#include <vector>
#include <sstream>
#include <regex>

using namespace std;


// ******************************************** SHA FUNCTIONS ********************************************
//function used in calculation SHA parts
unsigned int rightRotate(unsigned int n, unsigned int d)
{
    return (n >> d) | (n << (32 - d));
}

//Ch(x, y,z) = (x and y) xor (neg(x) and z)
unsigned int ch(unsigned int x, unsigned int y, unsigned int z)
{
    return (x & y) ^ (~x & z);
}
// Maj(x, y,z) = (x and y) xor (x and z) xor (y and z)
unsigned int maj(unsigned int x, unsigned int y, unsigned int z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

//sum{256}(x) = ROTR^2(x) xor ROTR^13(x) xor ROTR^22(x)
unsigned int sum_zero(unsigned int x)
{
    return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
}

//sum{256}(x) = ROTR^6(x) xor ROTR^11(x) xor ROTR^25(x)
unsigned int sum_one(unsigned int x)
{
    return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
}

//sigma_0(x) = ROTR^7(x) xor ROTR^18(x) xor SHR^3(x)
unsigned int sigma_zero(unsigned int x)
{
    return ((rightRotate(x, 7) ^ rightRotate(x, 18)) ^ (x >> 3));
}

//sigma_1(x) = ROTR^17(x) xor ROTR^19(x) xor SHR^10(x)
unsigned int sigma_one(unsigned int x)
{
    return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >> 10);
}
// ******************************************** SHA FUNCTIONS ********************************************
// ************************************************* SHA  ************************************************


// M = 512
//calculation of SHA HASH message_schedule
//step 1 of SHA
vector<unsigned int> message_schedule(string M)
{
    unsigned int block;
    vector<unsigned int> blocks;
    unsigned int w, x, y, z;

    //first 0-15 blocks stay the same
    for (int i = 0; i < 16; i++)
    {
        block = (unsigned int)bitset<32>(M.substr(i * 32, 32)).to_ulong();
        blocks.push_back(block);
    }

    //for the rest of the blocks 16-63
    //sigma{256}_1(W_(t-2)) + W_(t-7) + sigma{256}_0(W_(t-15)) + W_(t-16)
    for (int i = 16; i < 64; i++)
    {
        w = sigma_one(blocks[i - 2]);
        x = blocks[i - 7];
        y = sigma_zero(blocks[i - 15]);
        z = blocks[i - 16];

        //modulo 2^32
        block = (w + x + y + z) % (1ULL << 32);
        blocks.push_back(block);
    }
    return blocks;
}

//inicialization of first working variables throught H_0-H_7 constants
//step 2 of SHA
vector<unsigned int> give_H_i()
{
    unsigned int a = 0x6a09e667;
    unsigned int b = 0xbb67ae85;
    unsigned int c = 0x3c6ef372;
    unsigned int d = 0xa54ff53a;
    unsigned int e = 0x510e527f;
    unsigned int f = 0x9b05688c;
    unsigned int g = 0x1f83d9ab;
    unsigned int h = 0x5be0cd19;
    vector<unsigned int> H_i = {a, b, c, d, e, f, g, h};
    return H_i;
}

//calculation of working variables hash
//step 3 of SHA
vector<unsigned int> calculate_constants(vector<unsigned int> W, vector<unsigned int> H_i)
{
    unsigned int a = H_i[0];
    unsigned int b = H_i[1];
    unsigned int c = H_i[2];
    unsigned int d = H_i[3];
    unsigned int e = H_i[4];
    unsigned int f = H_i[5];
    unsigned int g = H_i[6];
    unsigned int h = H_i[7];
    unsigned int T1, T2;
    vector<unsigned int> K = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    for (int t = 0; t < 64; t++)
    {
        //T_1 = h + sum{256}_1(e) + Ch(e,f,g) + K{256}_t + W_t
        T1 = (h + sum_one(e) + ch(e, f, g) + K[t] + W[t]);
        //T_2 = sum{256}_0(a) + Maj(a,b,c)
        T2 = (sum_zero(a) + maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = (d + T1);
        d = c;
        c = b;
        b = a;
        a = (T1 + T2);
    }

    vector<unsigned int> abc = {a, b, c, d, e, f, g, h};
    return abc;
}

//parsing last block of message to 512 bits
//adds one 1 bit, length and fills with 0
string parse_message_block(string binary_message_string, int length_mess)
{
    //how many zeros there should be
    int padding = 512 - ((binary_message_string.size() + 1 + 64) % 512);

    //add one bit 1
    binary_message_string = binary_message_string + "1";

    //adding zeros
    for (int i = 0; i < padding; i++)
        binary_message_string = binary_message_string + "0";

    //adding length of the whole message
    string binary_length = bitset<64>(length_mess).to_string();
    binary_message_string = binary_message_string + binary_length;

    return binary_message_string;
}

//help function for printing SHA in format)
void SHA_print(vector<unsigned int> H_i)
{
    // print out SHA result
    for (int i = 0; i < 8; i++)
    {
        //printing in hexa
        printf("%08x", H_i[i]);
    }
    cout << "\n";
}

string message_to_binary(string M)
{
    string binary_message_string = "";

    //turning message into binary
    for (int i = 0; i < (int)M.size(); i++)
    {
        string to_binary_string = bitset<8>(M[i]).to_string();
        binary_message_string = binary_message_string + to_binary_string;
    }
    return binary_message_string;
}

//main function for SHA calculation
vector<unsigned int> SHA(string binary_message_string, vector<unsigned int> H_i)
{
    
    //working variables
    vector<unsigned int> blocks, abc;

    //count of messages
    int number_of_messages = binary_message_string.size() / 512;
    //length of the last message
    int length_of_last = binary_message_string.size() % 512;
    //length of the whole message
    int length_of_message = binary_message_string.size();

    //this is for the case, when the last message is straight 512 bits
    //because still for the last message the length and bit 1 needs to be added
    if(length_of_last == 512)
        number_of_messages--;

    //for each message except the last one
    for (int i = 0; i < number_of_messages; i++)
    {
        blocks = message_schedule(bitset<512>(binary_message_string).to_string());
        abc = calculate_constants(blocks, H_i);
        binary_message_string = binary_message_string.erase(0, 512);
        //itermediate hash values of H_0 - H_7
        for (int i = 0; i < 8; i++)
            H_i[i] = (abc[i] + H_i[i]) % (1ULL << 32);
    }

    //for the last message 
    //if the message is longer than 448 bits, then there will have to be added another one message to fit length and bit 1
    if(length_of_last < 448)
    {
        //same procedur as for every message
        //parsing with 1 bit, zeros and length
        string binary_message_string_block = parse_message_block(binary_message_string, length_of_message);
        blocks = message_schedule(binary_message_string_block);
        abc = calculate_constants(blocks, H_i);
        for (int i = 0; i < 8; i++)
            H_i[i] = (abc[i] + H_i[i]) % (1ULL << 32);
    }
    else
    {
        //one other message
        binary_message_string = binary_message_string + "1";
        for (int i = 0; i < 1024-1-64-length_of_last; i++)
            binary_message_string = binary_message_string + "0";
        string binary_length = bitset<64>(length_of_message).to_string();
        binary_message_string = binary_message_string + binary_length;

        //first message with bit 1 (and zeros)
        blocks = message_schedule(binary_message_string.substr(0,512));
        abc = calculate_constants(blocks, H_i);
        binary_message_string = binary_message_string.erase(0, 512);

        for (int i = 0; i < 8; i++)
            H_i[i] = (abc[i] + H_i[i]) % (1ULL << 32);

        //second message filled with zeros and length
        blocks = message_schedule(binary_message_string);
        abc = calculate_constants(blocks, H_i);
        for (int i = 0; i < 8; i++)
            H_i[i] = (abc[i] + H_i[i]) % (1ULL << 32);
    }

    return H_i;
}

// ************************************************* SHA  ************************************************
// ************************************************* MAC  ************************************************

//control function if MAC of input is correct
int MAC(string message, string KEY, string CHS)
{
    //calculated MAC of message and key
    string binary_message_string = message_to_binary(KEY + message);
    vector<unsigned int> SHA_H = SHA(binary_message_string, give_H_i());
    string SHA_CHS = "";
    string temp_s;
    //into hexa
    for (size_t i = 0; i < SHA_H.size(); ++i)
    {
        char temp_c[9];
        sprintf(temp_c, "%08x", SHA_H[i]);
        temp_s = temp_c;
        SHA_CHS = SHA_CHS + temp_s;
    }

    //comparing calculated MAC with input MAC
    int compare = SHA_CHS.compare(CHS);
    if (compare == 0)
        return 0;
    else
        return 1;
}

// ************************************************* MAC  ************************************************
// ******************************************** EXTENSION ATTACK ********************************************
//from the parametr -m, the MAC is divided into 8 blocks
vector<unsigned int> give_H_i_MAC(string CHS)
{
    string temp_8;
    unsigned int temp;
    vector<unsigned int> H_i;

    //dividing input MAC into 8 blocks
    for(int i = 0; i<8 ;i++)
    {
        temp_8 = CHS.substr(0,8);
        temp = stoul(temp_8, nullptr, 16);
        H_i.push_back(temp);
        CHS = CHS.erase(0, 8);
    }
    return H_i;
}

//normal SHA but for message with padding and added string from parameter -a
//H_i is from the input MAC
vector<unsigned int> extension_SHA(string binary_message_string, vector<unsigned int> H_i)
{
    vector<unsigned int> blocks, abc;

    int number_of_messages = binary_message_string.size() / 512;

    //calculation SHA for each message
    for (int i = 0; i < number_of_messages; i++)
    {
        blocks = message_schedule(bitset<512>(binary_message_string).to_string());
        abc = calculate_constants(blocks, H_i);
        binary_message_string = binary_message_string.erase(0, 512);
        for (int i = 0; i < 8; i++)
            H_i[i] = (abc[i] + H_i[i]) % (1ULL << 32);
    }
    return H_i;
}

//printing padding of message with length from parameter -n*8 
void print_extension_message(string message, int message_length, int key_length)
{
    string temp_message = message;
    string only_message = message.erase(message_length, 512);
    string padding = temp_message.erase(0, message_length);

    //message in message in ASCII
    for (int i = 0; i < message_length / 8; i++)
    {
        cout << char((bitset<8>(only_message).to_ulong()));
        only_message = only_message.erase(0, 8);
    }

    //printing bit 1 and zeros padding 
    unsigned int temp;
    int padding_length = padding.size();
    for (int i = 0; i < (padding_length - (key_length + 64)) / 8; i++)
    {
        temp = bitset<8>(padding).to_ulong();
        printf("\\x%02x", temp);
        padding = padding.erase(0, 8);
    }

    padding = padding.erase(0, 40);

    //printing length of the message
    for (int i = 0; i < 8; i++)
    {
        temp = bitset<8>(padding).to_ulong();
        printf("\\x%02x", temp);
        padding = padding.erase(0, 8);
    }
}


//printing extention padding 
void extension_padding(string message, int key_length, string MSG, string MSG_binary)
{
    string binary_message_string = "";
    vector<unsigned int> H_i = give_H_i();
    vector<unsigned int> blocks, abc;

    //message into binary
    for (int i = 0; i < (int)message.size(); i++)
    {
        string to_binary_string = bitset<8>(message[i]).to_string();
        binary_message_string = binary_message_string + to_binary_string;
    }

    int length_of_message = binary_message_string.size() + key_length * 8;
    string binary_message_string_block = parse_message_block(binary_message_string, length_of_message);
    
    //printing message with padding
    print_extension_message(binary_message_string_block, binary_message_string.size(), key_length * 8);
    //printing string from parameter -a
    cout << MSG << "\n";
}

//parsing MSG (parameter -a) into format for SHA with length of the message and key + MSG length
string extension(string message, int key_length, string MSG_binary)
{
    string binary_message_string = "";
    vector<unsigned int> blocks, abc;

    //message into binary
    for (int i = 0; i < (int)message.size(); i++)
    {
        string to_binary_string = bitset<8>(message[i]).to_string();
        binary_message_string = binary_message_string + to_binary_string;
    }

    //final length is length of message + length of key * 8 bits
    int length_of_message = binary_message_string.size() + key_length * 8;

    //the message with padding and added lenght from key_length, in format for SHA
    string binary_message_string_block = parse_message_block(binary_message_string, length_of_message);

    int length_extension = binary_message_string_block.size();

    //parsing MSG (parameter -a) into format for SHA with length of the message and key + MSG length
    string extension_string = parse_message_block(MSG_binary, length_extension + MSG_binary.size());
    return extension_string;
}

//function for length extension attack
void length_extension(string message,string MSG, string NUM, string CHS)
{
    //length of the key (from input it is string, so converted to int)
    int key_length = stoi(NUM);

    //message into binary
    string MSG_binary = "";
    for (int i = 0; i < (int)MSG.size(); i++)
    {
        string temp_s = bitset<8>(MSG[i]).to_string();
        MSG_binary = MSG_binary + temp_s;
    }

    //parsed string ready for SHA with parameter -a and message padding
    string extension_string = extension(message, key_length, MSG_binary);

    //returns inicialized H_0-H_7 according to input MAC from parametr -m divided into 8 blocks
    vector<unsigned int> H_i = give_H_i_MAC(CHS);

    //help function for calculating SHA of already parsed message
    vector<unsigned int> SHA_H = extension_SHA(extension_string, H_i);

    //printing SHA result
    SHA_print(SHA_H);

    //printing extension padding
    extension_padding(message, key_length, MSG, MSG_binary);
}

// ******************************************** EXTENSION ATTACK ********************************************

//regex check for the key
int regex_MSG_check(string MSG)
{
    //^[a-zA-Z0-9!#$%&’"()*+,\-.\/:;<>=?@[\]\\^_{}|~]*$
    regex m_r ("^[a-zA-Z0-9!#$%&’\"()*+,\\-.\\/:;<>=?@[\\]\\^_{}|~]*$");
    if (regex_match (MSG,m_r)){
        return 0;
    }
    else{
        fprintf(stderr, "Message in the wrong format!\n");
        return 1;    
    }
}

//regex check for the key
int regex_KEY_check(string KEY)
{
    //^[A-Fa-f0-9]*$
    regex k_r ("^[A-Za-z0-9]*$");
    if (regex_match (KEY,k_r)){
        return 0;
    }
    else{
        fprintf(stderr, "Key in the wrong format!\n");
        return 1;
    }
}

//parsing parameters and arguments
int argument_parser(int argc, char **argv, string message)
{
    //this is for other oder of parameters
    // -s -k and -k -s
    bool flag = false;
    char *temp[argc];
    temp[0] = argv[0];
    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i],"-v") == 0 || strcmp(argv[i], "-c") == 0 || strcmp(argv[i],"-e")==0 || strcmp(argv[i], "-s")==0){
            temp[1] = argv[i];
            flag = true;
            break;
        }
    }
    if(flag){
        int i = 1;
        int c = 2;
        while(i < argc){
            if(strcmp(argv[i], temp[1]))
            {
                temp[c] = argv[i];
                c++;
            }
            i++;
        }
    }
    else
    {   
        fprintf(stderr, "Wrong parameters!\n");
        return 1;    
    }
    vector<unsigned int> SHA_H;
    string KEY, CHS, NUM, MSG, binary_message_string;
    int return_code = 1;

    if(strcmp(temp[1], "-c") == 0)
    {
        if (argc != 2)
        {
            fprintf(stderr, "Parametr -c has the wrong parameters!\n");
            return 1;
        }
        binary_message_string = message_to_binary(message);
        SHA_H = SHA(binary_message_string, give_H_i());
        // print out SHA result
        SHA_print(SHA_H);
        return_code = 0;
    }
    else if(strcmp(temp[1], "-s") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "Parametr -s has the wrong parameters!\n");
            return 1;
        }
        if (strcmp(temp[2], "-k") != 0)
        {
            fprintf(stderr, "Parametr -s has the wrong parameters!\n");
            return 1;
        }
        KEY = temp[3];
        return_code = regex_KEY_check(KEY);
        if(return_code)
            return 1;
        binary_message_string = message_to_binary(KEY + message);
        SHA_H = SHA(binary_message_string, give_H_i());
        SHA_print(SHA_H);
    }
    else if(strcmp(temp[1], "-v") == 0)
    {
        if (argc != 6)
        {
            fprintf(stderr, "Parametr -v has the wrong parameters!\n");
            return 1;
        }
        if(strcmp(temp[2],"-k") == 0 && strcmp(temp[4],"-m") == 0)
        {
            KEY = temp[3];
            CHS = temp[5];
        }
        else if(strcmp(temp[4],"-k") == 0 && strcmp(temp[2],"-m") == 0)
        {
            KEY = temp[5];
            CHS = temp[3];
        }
        else
        {
            fprintf(stderr, "Parametr -v has the wrong parameters!\n");
            return 1;
        }
        return_code = MAC(message, KEY, CHS);
    }
    else if(strcmp(temp[1], "-e") == 0)
    {
        if (argc != 8)
        {
            fprintf(stderr, "Parametr -e has the wrong parameters!\n");
            return 1;
        }
        if(strcmp(temp[2],"-n") == 0 && strcmp(temp[4],"-m") == 0 && strcmp(temp[6],"-a") == 0)
        {
            NUM = temp[3];
            CHS = temp[5];
            MSG = temp[7];
        }
        else if(strcmp(temp[2],"-n") == 0 && strcmp(temp[4],"-a") == 0 && strcmp(temp[6],"-m") == 0)
        {
            NUM = temp[3];
            MSG = temp[5];
            CHS = temp[7];
        }
        else if(strcmp(temp[2],"-a") == 0 && strcmp(temp[4],"-n") == 0 && strcmp(temp[6],"-m") == 0)
        {
            MSG = temp[3];
            NUM = temp[5];
            CHS = temp[7];
        }
        else if(strcmp(temp[2],"-a") == 0 && strcmp(temp[4],"-m") == 0 && strcmp(temp[6],"-n") == 0)
        {
            MSG = temp[3];
            NUM = temp[5];
            CHS = temp[7];
        }
        else if(strcmp(temp[2],"-m") == 0 && strcmp(temp[4],"-a") == 0 && strcmp(temp[6],"-n") == 0)
        {
            CHS = temp[3];
            MSG = temp[5];
            NUM = temp[7];
        }
        else if(strcmp(temp[2],"-m") == 0 && strcmp(temp[4],"-n") == 0 && strcmp(temp[6],"-a") == 0)
        {
            CHS = temp[3];
            NUM = temp[5];
            MSG = temp[7];
        }
        else
        {
            fprintf(stderr, "Parametr -e has the wrong parameters!\n");
            return 1;
        }
        return_code = regex_MSG_check(MSG);
        if(return_code)
            return 1;
        length_extension(message ,MSG, NUM, CHS);
    }
    return return_code;
}

int main(int argc, char **argv)
{
    int return_code = 0;
    string message;
    if(argc == 1)
    {
        system("cat README.md");
        return 1;
    }
    else{
        getline(cin, message);
        return_code = argument_parser(argc, argv, message);
        return return_code;
    }
}