#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

void padBlock(vector<unsigned char>& block, size_t blockSize) {  // block padding function
    size_t paddingSize = blockSize - block.size();
    for (size_t i = 0; i < paddingSize; ++i) {
        block.push_back(0x81); 
    }
}

vector<unsigned char> swapBytes(vector<unsigned char>& ciphertext, const string& key) {  // block cipher byte swapping function 
    size_t start = 0;
    size_t end = ciphertext.size() - 1;
    
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        int mod2 = key[i % key.size()] % 2;
        if (mod2 == 1) {
            swap(ciphertext[start], ciphertext[end]);
        }
        ++start;
        --end;
        if (start >= end) {
            start = 0;
            end = ciphertext.size() - 1;
        }
    }
    
    return ciphertext;
}

vector<unsigned char> blockCipherEncrypt(vector<unsigned char>& plaintext, const string& key) {  // block cipher encryption function
    vector<unsigned char> ciphertext;
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext.push_back(plaintext[i] ^ key[i % key.size()]);
    }
    swapBytes(ciphertext, key);
    return ciphertext;
}

vector<unsigned char> blockCipherDecrypt(vector<unsigned char>& ciphertext, const string& key) {  // block cipher decryption function
    vector<unsigned char> decryptedText;
    swapBytes(ciphertext, key);
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        decryptedText.push_back(ciphertext[i] ^ key[i % key.size()]);
    }
    return decryptedText;
}

vector<unsigned char> streamCipher(vector<unsigned char>& input, const string& key) {  // stream cipher encryption/decryption function 
    vector<unsigned char> output;
    for (size_t i = 0; i < input.size(); ++i) {
        output.push_back(input[i] ^ key[i % key.size()]);
    }
    return output;
}

int main(int argc, char* argv[]) {
    if (argc != 6) {  // check args 
        cerr << "Usage: " << argv[0] << " <B/S> <input_file> <output_file> <keyfile> <mode>" << endl;
        return 1;
    }

    // allocate args 
    char cipherType = argv[1][0];
    string inputFile = argv[2];
    string outputFile = argv[3];
    string keyfile = argv[4];
    char mode = argv[5][0];

    // check for correct cipher type 
    if (cipherType != 'B' && cipherType != 'S') {
        cerr << "Cipher type must be 'B' or 'S'" << endl;
        return 1;
    }

    // read key from file
    ifstream keyFile(keyfile);
    if (!keyFile.is_open()) {
        cerr << "Unable to open keyfile: " << keyfile << endl;
        return 1;
    }
    string key;
    keyFile >> key;

    // open input file
    ifstream inFile(inputFile, ios::binary);
    if (!inFile.is_open()) {
        cerr << "Unable to open input file: " << inputFile << endl;
        return 1;
    }

    // open output file
    ofstream outFile(outputFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "Unable to open output file: " << outputFile << endl;
        return 1;
    }

    // read input file
    vector<unsigned char> plaintext;
    char ch;
    while (inFile.get(ch)) {
        plaintext.push_back(ch);
    }

    // check type and mode and run
    vector<unsigned char> result;
    if (mode == 'E') {
        if (cipherType == 'B') {
            padBlock(plaintext, 16);  // pad block if needed
            result = blockCipherEncrypt(plaintext, key);
        } else { 

            result = streamCipher(plaintext, key);
        }
    } else if (mode == 'D') {
        if (cipherType == 'B') {
            result = blockCipherDecrypt(plaintext, key);
            while (!result.empty() && result.back() == 0x81) {
                result.pop_back();
            }
        } else { 
            result = streamCipher(plaintext, key);
        }
    } else {
        cerr << "Mode must be 'E' for encryption or 'D' for decryption" << endl;
        return 1;
    }

    for (auto byte : result) {
        outFile.put(byte);
    }

    // close files
    inFile.close();
    outFile.close();
    keyFile.close();

    cout << "Operation completed successfully." << endl;

    return 0;
}
