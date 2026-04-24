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

#include "heu/library/algorithms/ashe/evaluator.h"

namespace heu::lib::algorithms::ashe {
void Evaluator::Randomize(Ciphertext *ct) const {
  BigInt r;
  BigInt::RandomLtN(BigInt(pp_.randomZeros.size()), &r);
  AddInplace(ct, Ciphertext(pp_.randomZeros[r.Get<int64_t>()]));
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  return Ciphertext(a.n_ + b.n_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &b) const {
  return Ciphertext(a.n_ + b % MOD_);
}

Ciphertext Evaluator::Add(const Plaintext &a, const Ciphertext &b) const {
  return Add(b, a);
}

Plaintext Evaluator::Add(const Plaintext &a, const Plaintext &b) const {
  return a + b;
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  a->n_ += b.n_;
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &b) const {
  if (b.IsNegative()) {
    a->n_ += b + MOD_;
  } else {
    a->n_ += b;
  }
}

void Evaluator::AddInplace(Plaintext *a, const Plaintext &b) const {
  *a = Add(*a, b);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return Ciphertext(a.n_ - b.n_);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Plaintext &b) const {
  return Add(a, -b);
}

Ciphertext Evaluator::Sub(const Plaintext &a, const Ciphertext &b) const {
  return Add(Negate(b), a);
}

Plaintext Evaluator::Sub(const Plaintext &a, const Plaintext &b) const {
  return a - b;
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  *a = Sub(*a, b);
}

void Evaluator::SubInplace(Ciphertext *a, const Plaintext &p) const {
  *a = Sub(*a, p);
}

void Evaluator::SubInplace(Plaintext *a, const Plaintext &b) const {
  *a = Sub(*a, b);
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &b) const {
  if (!b.IsNegative()) {
    return Ciphertext(b * a.n_);
  } else {
    Ciphertext neg_a = Negate(a);
    return Ciphertext((-b) * neg_a.n_);
  }
}

Ciphertext Evaluator::Mul(const Plaintext &a, const Ciphertext &b) const {
  return Mul(b, a);
}

Plaintext Evaluator::Mul(const Plaintext &a, const Plaintext &b) const {
  return a * b;
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &b) const {
  *a = Mul(*a, b);
}

void Evaluator::MulInplace(Plaintext *a, const Plaintext &b) const {
  *a = Mul(*a, b);
}

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  BigInt r;
  BigInt::RandomLtN(BigInt(pp_.randomZeros.size()), &r);
  BigInt random0 = pp_.randomZeros[r.Get<int64_t>()];
  return Ciphertext(MOD_ - a.n_ + random0);
}

void Evaluator::NegateInplace(Ciphertext *a) const { *a = Negate(*a); }
}  // namespace heu::lib::algorithms::ashe
