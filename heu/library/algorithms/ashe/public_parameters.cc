#include "heu/library/algorithms/ashe/public_parameters.h"

namespace heu::lib::algorithms::ashe {
PublicParameters::PublicParameters(int64_t k_r1, int64_t k_p, int64_t k_q,
                                   int64_t k_r2, int64_t k_m) {
  this->k_r1 = k_r1;
  this->k_p = k_p;
  this->k_q = k_q;
  this->k_r2 = k_r2;
  this->k_m = k_m;
  Init();
}

PublicParameters::PublicParameters(int64_t k_r1, int64_t k_p, int64_t k_q,
                                   int64_t k_r2, int64_t k_m,
                                   const std::vector<BigInt> &zeros)
    : PublicParameters(k_r1, k_p, k_q, k_r2, k_m) {
  this->randomZeros = zeros;
}

std::string PublicParameters::ToString() const {
  return fmt::format(
      "ashe PP: k_r1={}, k_p={}, k_q={}, "
      "k_r2={}, k_m={}, randomZeros={}[size:{}]",
      std::to_string(k_r1), std::to_string(k_p), std::to_string(k_q),
      std::to_string(k_r2), std::to_string(k_m), ToHexString(randomZeros),
      randomZeros.size());
}

void PublicParameters::Init() {
  this->M[1] = BigInt(2).Pow(k_m - 1) - BigInt(1);
  this->M[0] = -this->M[1];
}
}  // namespace heu::lib::algorithms::ashe
