#include <iostream>
#include <vector>
#include "HEaaN/HEaaN.hpp"

using namespace std;
using namespace HEaaN;

int main() {
    // Initialize context
    Context context = makeContext(ParameterPreset::FGa); // FGa - Precision optimal FG parameter

    // Initialize keys
    SecretKey sk(context); // generate secret key
    KeyGenerator keygen(context, sk); // generate public key
    keygen.genEncryptionKey(); // generate encryption key
    keygen.genMultiplicationKey(); // generate multiplication key
    KeyPack keypack = keygen.getKeyPack();

    // Initialize encryptor, decryptor, encoder, evaluator
    Encryptor encryptor(context);
    Decryptor decryptor(context);
    EnDecoder encoder(context);
    HomEvaluator evaluator(context, keypack);
    
    // Messages
    Message msg1(1);
    Message msg2(1);

    msg1[0] = Complex(1.0, 0.0); msg1[1] = Complex(2.0, 0.0); // {1, 2}
    msg2[0] = Complex(2.0, 0.0); msg2[1] = Complex(3.0, 0.0); // {2, 3}

    // Encode the messages
    Plaintext ptxt1 = encoder.encode(msg1);
    Plaintext ptxt2 = encoder.encode(msg2);

    // Encrypt the messages
    Ciphertext ctxt1(context);
    Ciphertext ctxt2(context);
    encryptor.encrypt(msg1, keypack, ctxt1);
    encryptor.encrypt(msg2, keypack, ctxt2);

    // Multiplication
    Ciphertext ctxt_result1(context);
    evaluator.add(ctxt1, ctxt2, ctxt_result1); // result = 3 5

    // Multiplication
    Ciphertext ctxt_result2(context);
    evaluator.mult(ctxt_result1, ctxt_result1, ctxt_result2); // result = 9 25

    // Multiplication
    Ciphertext ctxt_result3(context);
    evaluator.mult(ctxt_result1, ctxt_result2, ctxt_result3); // result = 27 125

    // Decrypt the result
    Message decrypted_result;
    decryptor.decrypt(ctxt_result3, sk, decrypted_result);

    // Print the result
    cout << decrypted_result[0].real() << endl;
    cout << decrypted_result[1].real() << endl;

    return 0;
}