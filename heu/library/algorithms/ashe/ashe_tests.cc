// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string>

#include "gtest/gtest.h"

#include "heu/library/algorithms/ashe/ashe.h"

namespace heu::lib::algorithms::ashe::test {

class asheTest : public testing::Test {
 protected:
  static void SetUpTestSuite() { KeyGenerator::Generate(2048, &sk_, &pp_); }

  static SecretKey sk_;
  static PublicKey pp_;
};

SecretKey asheTest::sk_;
PublicKey asheTest::pp_;

TEST_F(asheTest, SerializeTest) {
  auto pp_buffer = pp_.Serialize();
  PublicKey pp2;
  pp2.Deserialize(pp_buffer);
  ASSERT_EQ(pp_.k_r1, pp2.k_r1);
  ASSERT_EQ(pp_.k_r2, pp2.k_r2);
  ASSERT_EQ(pp_.k_q, pp2.k_q);
  ASSERT_EQ(pp_.k_p, pp2.k_p);
  ASSERT_EQ(pp_.randomZeros, pp2.randomZeros);

  auto sk_buffer = sk_.Serialize();
  SecretKey sk2;
  sk2.Deserialize(sk_buffer);
  ASSERT_EQ(sk_.p_, sk2.p_);
  ASSERT_EQ(sk_.q_, sk2.q_);

  Encryptor encryptor(pp2, sk2);

  Evaluator evaluator(pp2);

  BigInt m0(-12345);
  Ciphertext ct = encryptor.Encrypt(m0);

  BigInt dc;
  Decryptor decryptor(pp_, sk_);
  decryptor.Decrypt(ct, &dc);
  EXPECT_EQ(dc, m0);
}

TEST_F(asheTest, OperationEvaluate) {
  Encryptor encryptor_(pp_, sk_);
  Evaluator evaluator_(pp_);
  Decryptor decryptor_(pp_, sk_);

  Plaintext m0 = Plaintext(12345);
  Plaintext m1 = Plaintext(-20000);
  Plaintext m3 = Plaintext(0);
  Ciphertext c0 = encryptor_.Encrypt(m0);
  Ciphertext c1 = encryptor_.Encrypt(m1);
  Ciphertext c2 = encryptor_.Encrypt(-m0);
  Ciphertext c3 = encryptor_.Encrypt(m3);
  EXPECT_EQ(m0, Plaintext(12345));

  Plaintext plain;
  Ciphertext res;

  // evaluate add
  res = evaluator_.Add(c0, c0);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 * 2));
  res = evaluator_.Add(c1, c1);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-20000 * 2));
  res = evaluator_.Add(c0, c1);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 - 20000));
  res = evaluator_.Add(c1, m3);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-20000));
  res = evaluator_.Add(c0, m1);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 - 20000));
  res = evaluator_.Add(c1, m0);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 - 20000));
  res = evaluator_.Add(c2, c0);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(0));

  res = evaluator_.Mul(c0, m0);
  decryptor_.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 * 12345));
  res = evaluator_.Mul(c1, m0);
  decryptor_.Decrypt(res, &plain);

  Ciphertext Zero = encryptor_.EncryptZero();
  decryptor_.Decrypt(Zero, &plain);
  EXPECT_EQ(plain, BigInt(0));
  decryptor_.Decrypt(c1, &plain);
  EXPECT_EQ(plain, BigInt(-20000));

  Plaintext pt0 = Plaintext(12345);
  Plaintext pt1 = Plaintext(20000);
  Ciphertext ct0 = encryptor_.Encrypt(pt0);
  Ciphertext ct1 = encryptor_.Encrypt(pt1);
  evaluator_.AddInplace(&ct0, pt1);
  decryptor_.Decrypt(ct0, &plain);
  EXPECT_EQ(plain, BigInt(20000 + 12345));
  evaluator_.AddInplace(&ct0, ct1);
  decryptor_.Decrypt(ct0, &plain);
  EXPECT_EQ(plain, BigInt(20000 + 12345 + 20000));
  evaluator_.Randomize(&ct0);
  decryptor_.Decrypt(ct0, &plain);
  EXPECT_EQ(plain, BigInt(20000 + 12345 + 20000));
  Plaintext pt_min = Plaintext(pp_.MessageSpace().first);
  Plaintext pt_max = Plaintext(pp_.MessageSpace().second - BigInt(1));
  Ciphertext ct_max = encryptor_.Encrypt(pt_max);
  Ciphertext ct_min = encryptor_.Encrypt(pt_min);
  Plaintext tmp = decryptor_.Decrypt(ct_min);
  EXPECT_EQ(tmp, pt_min);
  tmp = decryptor_.Decrypt(ct_max);
  EXPECT_EQ(tmp, pt_max);
}

TEST_F(asheTest, NegateEvalutate) {
  Encryptor encryptor_(pp_, sk_);
  Evaluator evaluator_(pp_);
  Decryptor decryptor_(pp_, sk_);
  Plaintext p1 = Plaintext(123456);
  Plaintext p2 = Plaintext(23456);
  Ciphertext c1 = encryptor_.Encrypt(p1);
  Ciphertext c2 = encryptor_.Encrypt(p2);
  Ciphertext c3 = evaluator_.Sub(c1, c2);
  decryptor_.Decrypt(c3, &p1);
  EXPECT_EQ(BigInt(123456 - 23456), p1);
  evaluator_.NegateInplace(&c2);
  decryptor_.Decrypt(c2, &p2);
  EXPECT_EQ(BigInt(-23456), p2);
}

TEST_F(asheTest, RuntimeEfficientTest) {
  Encryptor encryptor_(pp_, sk_);
  Evaluator evaluator_(pp_);
  Decryptor decryptor_(pp_, sk_);
  Ciphertext c1, c2;
  std::chrono::time_point<std::chrono::high_resolution_clock> t1, t2;
  c1 = encryptor_.Encrypt(pp_.MessageSpace().second);
  c2 = encryptor_.Encrypt(pp_.MessageSpace().second);
  t1 = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < 100000; i++) {
    evaluator_.AddInplace(&c1, c2);
    // Plaintext m = decryptor_.Decrypt(c2);
    // std::cout << m << std::endl;
    // EXPECT_EQ(m, BigInt(-1)*BigInt(i + 2));
  }
  t2 = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1);
  std::cout << "add 1w times used " << duration.count() << std::endl;
  auto p = decryptor_.Decrypt(c1);
  std::cout << p << std::endl;
  EXPECT_EQ(p, pp_.MessageSpace().second * 100001);
  t1 = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < 10000; i++) {
    Plaintext m = decryptor_.Decrypt(c2);
  }
  t2 = std::chrono::high_resolution_clock::now();
  duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1);
  std::cout << "decrypt 1w times used " << duration.count() << std::endl;
}
}  // namespace heu::lib::algorithms::ashe::test
