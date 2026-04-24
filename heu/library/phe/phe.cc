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

#include "heu/library/phe/phe.h"

#include <utility>

namespace heu::lib::phe {

template <typename Enc, typename PK, typename = void>
struct CanConstructWithPkOnly : std::false_type {};

template <typename Enc, typename PK>
struct CanConstructWithPkOnly<Enc, PK,
                              std::void_t<decltype(Enc(std::declval<PK>()))>>
    : std::true_type {};

template <typename Enc, typename PK, typename SK,
          bool CanUsePkOnly = CanConstructWithPkOnly<Enc, PK>::value>
struct EncryptorCreator;

template <typename Enc, typename PK, typename SK>
struct EncryptorCreator<Enc, PK, SK, true> {
  static Enc create(const PK &pk, const SK &) { return Enc(pk); }
};

template <typename Enc, typename PK, typename SK>
struct EncryptorCreator<Enc, PK, SK, false> {
  static Enc create(const PK &pk, const SK &sk) { return Enc(pk, sk); }
};

template <typename Enc, typename PK, typename SK,
          bool CanUsePkOnly = CanConstructWithPkOnly<Enc, PK>::value>
struct EncryptorSetupHelper;

template <typename Enc, typename PK, typename SK>
struct EncryptorSetupHelper<Enc, PK, SK, true> {
  static void setupWithPk(std::shared_ptr<Encryptor> &encryptor,
                          SchemaType schema_type, const PK &pk) {
    encryptor = std::make_shared<Encryptor>(schema_type, Enc(pk));
  }

  static void setupWithSk(std::shared_ptr<Encryptor> &, SchemaType, const PK &,
                          const SK &) {}
};

template <typename Enc, typename PK, typename SK>
struct EncryptorSetupHelper<Enc, PK, SK, false> {  // symmetric

  static void setupWithPk(std::shared_ptr<Encryptor> &, SchemaType,
                          const PK &) {}

  static void setupWithSk(std::shared_ptr<Encryptor> &encryptor,
                          SchemaType schema_type, const PK &pk, const SK &sk) {
    encryptor = std::make_shared<Encryptor>(schema_type, Enc(pk, sk));
  }
};

void HeKitPublicBase::Setup(std::shared_ptr<PublicKey> pk) {
  public_key_ = std::move(pk);

  int hit = 0;
  for (const auto &schema : GetAllSchema()) {
    if (public_key_->IsCompatible(schema)) {
      schema_type_ = schema;
      ++hit;
    }
  }
  YACL_ENFORCE(hit == 1,
               "Cannot detect the schema type of public key {}, hit={}",
               public_key_->ToString(), hit);
}

void HeKitSecretBase::Setup(std::shared_ptr<PublicKey> pk,
                            std::shared_ptr<SecretKey> sk) {
  HeKitPublicBase::Setup(std::move(pk));
  secret_key_ = std::move(sk);
  YACL_ENFORCE(secret_key_->IsCompatible(schema_type_),
               "The public key and secret key do not belong to the same "
               "algorithm, pk={}",
               schema_type_);
}

#define GEN_KEY_AND_INIT(ns)                                                   \
  [&](ns::PublicKey &pk) {                                                     \
    ns::SecretKey sk;                                                          \
    ns::KeyGenerator::Generate(key_size, &sk, &pk);                            \
                                                                               \
    encryptor_ = std::make_shared<Encryptor>(                                  \
        schema_type,                                                           \
        EncryptorCreator<ns::Encryptor, ns::PublicKey, ns::SecretKey>::create( \
            pk, sk));                                                          \
    decryptor_ =                                                               \
        std::make_shared<Decryptor>(schema_type, ns::Decryptor(pk, sk));       \
    evaluator_ = std::make_shared<Evaluator>(schema_type, ns::Evaluator(pk));  \
    return std::make_shared<SecretKey>(std::move(sk));                         \
  }

template <typename Enc, typename PK,
          bool CanUsePkOnly = CanConstructWithPkOnly<Enc, PK>::value>
struct DestEncryptorSetupHelper;

template <typename Enc, typename PK>
struct DestEncryptorSetupHelper<Enc, PK, true> {
  static void setup(std::shared_ptr<Encryptor> &encryptor,
                    SchemaType schema_type, const PK &pk) {
    encryptor = std::make_shared<Encryptor>(schema_type, Enc(pk));
  }
};

template <typename Enc, typename PK>
struct DestEncryptorSetupHelper<Enc, PK, false> {
  static void setup(std::shared_ptr<Encryptor> &encryptor,
                    SchemaType schema_type, const PK &) {
    (void)schema_type;
    encryptor = nullptr;
  }
};

HeKit::HeKit(SchemaType schema_type, size_t key_size) {
  auto pk = std::make_shared<PublicKey>(schema_type);
  auto sk =
      pk->Visit(HE_DISPATCH_RET(std::shared_ptr<SecretKey>, GEN_KEY_AND_INIT));
  Setup(std::move(pk), std::move(sk));
}

#define GEN_KEY_AND_INIT_DEFAULT(ns)                                           \
  [&](ns::PublicKey &pk) {                                                     \
    ns::SecretKey sk;                                                          \
    ns::KeyGenerator::Generate(&sk, &pk);                                      \
                                                                               \
    encryptor_ = std::make_shared<Encryptor>(                                  \
        schema_type,                                                           \
        EncryptorCreator<ns::Encryptor, ns::PublicKey, ns::SecretKey>::create( \
            pk, sk));                                                          \
    decryptor_ =                                                               \
        std::make_shared<Decryptor>(schema_type, ns::Decryptor(pk, sk));       \
    evaluator_ = std::make_shared<Evaluator>(schema_type, ns::Evaluator(pk));  \
    return std::make_shared<SecretKey>(std::move(sk));                         \
  }

HeKit::HeKit(SchemaType schema_type) {
  auto pk = std::make_shared<PublicKey>(schema_type);
  auto sk = pk->Visit(
      HE_DISPATCH_RET(std::shared_ptr<SecretKey>, GEN_KEY_AND_INIT_DEFAULT));
  Setup(std::move(pk), std::move(sk));
}

#define HE_SPECIAL_SETUP_BY_PK(ns)                                             \
  [&](const ns::PublicKey &pk1) {                                              \
    evaluator_ =                                                               \
        std::make_shared<Evaluator>(schema_type_, ns::Evaluator(pk1));         \
    EncryptorSetupHelper<ns::Encryptor, ns::PublicKey,                         \
                         ns::SecretKey>::setupWithPk(encryptor_, schema_type_, \
                                                     pk1);                     \
  }

#define HE_SPECIAL_SETUP_BY_SK(ns)                                             \
  [&](const ns::SecretKey &sk1) {                                              \
    const auto &pk1 = public_key_->As<ns::PublicKey>();                        \
    decryptor_ =                                                               \
        std::make_shared<Decryptor>(schema_type_, ns::Decryptor(pk1, sk1));    \
    EncryptorSetupHelper<ns::Encryptor, ns::PublicKey,                         \
                         ns::SecretKey>::setupWithSk(encryptor_, schema_type_, \
                                                     pk1, sk1);                \
  }

HeKit::HeKit(std::shared_ptr<PublicKey> pk, std::shared_ptr<SecretKey> sk) {
  Setup(std::move(pk), std::move(sk));
  public_key_->Visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_PK));
  secret_key_->Visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_SK));
}

HeKit::HeKit(yacl::ByteContainerView pk_buffer,
             yacl::ByteContainerView sk_buffer) {
  auto pk = std::make_shared<PublicKey>();
  pk->Deserialize(pk_buffer);
  auto sk = std::make_shared<SecretKey>();
  sk->Deserialize(sk_buffer);

  Setup(std::move(pk), std::move(sk));
  public_key_->Visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_PK));
  secret_key_->Visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_SK));
}

#define HE_DEST_SETUP_BY_PK(ns)                                        \
  [&](const ns::PublicKey &pk1) {                                      \
    evaluator_ =                                                       \
        std::make_shared<Evaluator>(schema_type_, ns::Evaluator(pk1)); \
    DestEncryptorSetupHelper<ns::Encryptor, ns::PublicKey>::setup(     \
        encryptor_, schema_type_, pk1);                                \
  }

DestinationHeKit::DestinationHeKit(std::shared_ptr<PublicKey> pk) {
  Setup(std::move(pk));
  public_key_->Visit(HE_DISPATCH(HE_DEST_SETUP_BY_PK));
}

DestinationHeKit::DestinationHeKit(yacl::ByteContainerView pk_buffer) {
  auto pk = std::make_shared<PublicKey>();
  pk->Deserialize(pk_buffer);
  Setup(std::move(pk));
  public_key_->Visit(HE_DISPATCH(HE_DEST_SETUP_BY_PK));
}

}  // namespace heu::lib::phe
