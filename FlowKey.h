#ifndef SKETCHLAB_CPP_FLOWKEY_H
#define SKETCHLAB_CPP_FLOWKEY_H

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>

#define BYTE(n) ((n) >> 3)
#define BIT(n) ((n)&7)

namespace SketchLab {
class FlowKeyOutOfRange : public std::out_of_range {
private:
public:
  FlowKeyOutOfRange(int32_t pos, int32_t offset, int32_t total_len)
      : std::out_of_range("FlowKey Out of Range: pos: " + std::to_string(pos) +
                          ", offset: " + std::to_string(offset) +
                          ", total_len: " + std::to_string(total_len)) {}
};
template <int32_t key_len> class FlowKey {
private:
  friend class std::hash<FlowKey<key_len>>;
  friend class std::equal_to<FlowKey<key_len>>;

  uint8_t key_[key_len];

public:
  FlowKey() { std::fill_n(key_, key_len, 0); }
  FlowKey(const uint8_t *key) { std::copy(key, key + key_len, key_); }
  template <int32_t other_len> friend class FlowKey;

  template <int32_t other_len>
  FlowKey &copy(int32_t pos, const FlowKey<other_len> &otherkey, int32_t o_pos,
                int32_t len) {
    if (pos + len > key_len) {
      throw FlowKeyOutOfRange(pos, len, key_len);
    }
    if (o_pos + len > other_len) {
      throw FlowKeyOutOfRange(o_pos, len, other_len);
    }
    const uint8_t *o_key = otherkey.cKey();
    std::copy(o_key + o_pos, o_key + o_pos + len, key_ + pos);
    return *this;
  }

  FlowKey &copy(int32_t pos, const uint8_t *key, int32_t len) {
    if (pos + len > key_len) {
      throw FlowKeyOutOfRange(pos, len, key_len);
    }
    std::copy(key, key + len, key_ + pos);
    return *this;
  }
  const uint8_t *cKey() const { return key_; }

  bool operator==(const FlowKey &otherkey) const {
    for (int32_t i = 0; i < key_len; ++i) {
      if (key_[i] != otherkey.key_[i]) {
        return false;
      }
    }
    return true;
  }

  bool operator<(const FlowKey &otherkey) const {
    for (int32_t i = 0; i < key_len; ++i) {
      if (key_[i] < otherkey.key_[i]) {
        return true;
      } else if (key_[i] > otherkey.key_[i]) {
        return false;
      }
    }
    return false;
  }
  inline void setBit(int32_t pos, bool one) {
    if (BYTE(pos) >= key_len) {
      throw FlowKeyOutOfRange(pos, 0, key_len);
    }
    if (one) {
      key_[BYTE(pos)] |= (1 << BIT(pos));
    } else {
      key_[BYTE(pos)] &= ~(1 << BIT(pos));
    }
  }
  inline uint8_t getBit(int32_t pos) const {
    if (BYTE(pos) >= key_len) {
      throw FlowKeyOutOfRange(pos, 0, key_len);
    }
    return (key_[BYTE(pos)] >> BIT(pos)) & 1;
  }
  FlowKey *operator^=(const FlowKey &otherkey) {
    for (int i = 0; i < key_len; ++i) {
      key_[i] ^= otherkey.key_[i];
    }
    return this;
  }
};

template <> class FlowKey<4> {
  friend class std::hash<FlowKey<4>>;
  friend class std::equal_to<FlowKey<4>>;

private:
  union {
    uint8_t key_[4];
    uint32_t ipaddr_;
  } u;

public:
  FlowKey() { u.ipaddr_ = 0; }
  FlowKey(uint32_t ipaddr) { u.ipaddr_ = ipaddr; }
  FlowKey(const uint8_t *key) { std::copy(key, key + 4, u.key_); }
  template <int32_t other_len> friend class FlowKey;

  template <int32_t other_len>
  FlowKey &copy(int32_t pos, const FlowKey<other_len> &otherkey, int32_t o_pos,
                int32_t len) {
    if (pos + len > 4) {
      throw FlowKeyOutOfRange(pos, len, 4);
    }
    if (o_pos + len > other_len) {
      throw FlowKeyOutOfRange(o_pos, len, other_len);
    }
    const uint8_t *o_key = otherkey.cKey();
    std::copy(o_key + o_pos, o_key + o_pos + len, u.key_ + pos);
    return *this;
  }

  FlowKey &copy(int32_t pos, const uint8_t *key, int32_t len) {
    if (pos + len > 4) {
      throw FlowKeyOutOfRange(pos, len, 4);
    }
    std::copy(key, key + len, u.key_ + pos);
    return *this;
  }
  const uint8_t *cKey() const { return u.key_; }
  bool operator==(const FlowKey &otherkey) const {
    return u.ipaddr_ == otherkey.u.ipaddr_;
  }

  bool operator<(const FlowKey &otherkey) const {
    return u.ipaddr_ < otherkey.u.ipaddr_;
  }

  uint32_t getIp() const { return u.ipaddr_; }

  inline void setBit(int32_t pos, bool one) {
    if (BYTE(pos) >= 4) {
      throw FlowKeyOutOfRange(pos, 0, 4);
    }
    if (one) {
      u.key_[BYTE(pos)] |= (1 << BIT(pos));
    } else {
      u.key_[BYTE(pos)] &= ~(1 << BIT(pos));
    }
  }

  inline uint8_t getBit(int32_t pos) const {
    if (BYTE(pos) >= 4) {
      throw FlowKeyOutOfRange(pos, 0, 4);
    }
    return (u.key_[BYTE(pos)] >> BIT(pos)) & 1;
  }
  FlowKey *operator^=(const FlowKey &otherkey) {
    for (int i = 0; i < 4; ++i) {
      u.key_[i] ^= otherkey.u.key_[i];
    }
    return this;
  }
};

template <> class FlowKey<8> {
private:
  friend class std::hash<FlowKey<8>>;
  friend class std::equal_to<FlowKey<8>>;

  union {
    struct {
      uint32_t srcip_;
      uint32_t dstip_;
    } s;
    uint8_t key_[8];
  } u;
  inline uint8_t *getKey() { return u.key_; }

public:
  FlowKey() { u.s.srcip_ = u.s.dstip_ = 0; }
  FlowKey(const uint8_t *key) { std::copy(key, key + 8, u.key_); }
  FlowKey(uint32_t srcip, uint32_t dstip) {
    u.s.srcip_ = srcip;
    u.s.dstip_ = dstip;
  }
  template <int32_t other_len> friend class FlowKey;

  template <int32_t other_len>
  FlowKey &copy(int32_t pos, FlowKey<other_len> &otherkey, int32_t o_pos,
                int32_t len) {
    if (pos + len > 8) {
      throw FlowKeyOutOfRange(pos, len, 8);
    }
    if (o_pos + len > other_len) {
      throw FlowKeyOutOfRange(o_pos, len, other_len);
    }
    uint8_t *o_key = otherkey.getKey();
    std::copy(o_key + o_pos, o_key + o_pos + len, u.key_ + pos);
    return *this;
  }

  FlowKey &copy(int32_t pos, const uint8_t *key, int32_t len) {
    if (pos + len > 8) {
      throw FlowKeyOutOfRange(pos, len, 8);
    }
    std::copy(key, key + len, u.key_ + pos);
    return *this;
  }

  const uint8_t *cKey() const { return u.key_; }

  bool operator==(const FlowKey &otherkey) const {
    return u.s.srcip_ == otherkey.u.s.srcip_ &&
           u.s.dstip_ == otherkey.u.s.dstip_;
  }

  bool operator<(const FlowKey &otherkey) const {
    if (u.s.srcip_ != otherkey.u.s.srcip_) {
      return u.s.srcip_ < otherkey.u.s.srcip_;
    }
    if (u.s.dstip_ != otherkey.u.s.dstip_) {
      return u.s.dstip_ < otherkey.u.s.dstip_;
    }
    return false;
  }

  uint32_t getSrcip() const { return u.s.srcip_; }
  uint32_t getDstip() const { return u.s.dstip_; }

  inline void setBit(int32_t pos, bool one) {
    if (BYTE(pos) >= 8) {
      throw FlowKeyOutOfRange(pos, 0, 8);
    }
    if (one) {
      u.key_[BYTE(pos)] |= (1 << BIT(pos));
    } else {
      u.key_[BYTE(pos)] &= ~(1 << BIT(pos));
    }
  }

  inline uint8_t getBit(int32_t pos) const {
    if (BYTE(pos) >= 8) {
      throw FlowKeyOutOfRange(pos, 0, 8);
    }
    return (u.key_[BYTE(pos)] >> BIT(pos)) & 1;
  }

  FlowKey *operator^=(const FlowKey &otherkey) {
    for (int i = 0; i < 8; ++i) {
      u.key_[i] ^= otherkey.u.key_[i];
    }
    return this;
  }
};

template <> class FlowKey<13> {
private:
  friend class std::hash<FlowKey<13>>;
  friend class std::equal_to<FlowKey<13>>;

  union {
    struct {
      uint32_t srcip_;
      uint32_t dstip_;
      uint16_t srcport_;
      uint16_t dstport_;
      uint8_t protocol_;
    } s;
    uint8_t key_[13];
  } u;

public:
  FlowKey() {
    u.s.srcip_ = u.s.dstip_ = 0;
    u.s.srcport_ = u.s.dstport_ = 0;
    u.s.protocol_ = 0;
  }
  FlowKey(const uint8_t *key) { std::copy(key, key + 13, u.key_); }
  FlowKey(uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport,
          uint8_t protocol) {
    u.s.srcip_ = srcip;
    u.s.dstip_ = dstip;
    u.s.srcport_ = srcport;
    u.s.dstport_ = dstport;
    u.s.protocol_ = protocol;
  }
  template <int32_t other_len> friend class FlowKey;

  template <int32_t other_len>
  FlowKey &copy(int32_t pos, const FlowKey<other_len> &otherkey, int32_t o_pos,
                int32_t len) {
    if (pos + len > 13) {
      throw FlowKeyOutOfRange(pos, len, 13);
    }
    if (o_pos + len > other_len) {
      throw FlowKeyOutOfRange(o_pos, len, other_len);
    }
    const uint8_t *o_key = otherkey.cKey();
    std::copy(o_key + o_pos, o_key + o_pos + len, u.key_ + pos);
    return *this;
  }

  FlowKey &copy(int32_t pos, const uint8_t *key, int32_t len) {
    if (pos + len > 13) {
      throw FlowKeyOutOfRange(pos, len, 13);
    }
    std::copy(key, key + len, u.key_ + pos);
    return *this;
  }

  inline const uint8_t *cKey() const { return u.key_; }

  bool operator==(const FlowKey &otherkey) const {
    return u.s.srcip_ == otherkey.u.s.srcip_ &&
           u.s.dstip_ == otherkey.u.s.dstip_ &&
           u.s.srcport_ == otherkey.u.s.srcport_ &&
           u.s.dstport_ == otherkey.u.s.dstport_ &&
           u.s.protocol_ == otherkey.u.s.protocol_;
  }

  bool operator<(const FlowKey &otherkey) const {
    if (u.s.srcip_ != otherkey.u.s.srcip_) {
      return u.s.srcip_ < otherkey.u.s.srcip_;
    }
    if (u.s.dstip_ != otherkey.u.s.dstip_) {
      return u.s.dstip_ < otherkey.u.s.dstip_;
    }
    if (u.s.srcport_ != otherkey.u.s.srcport_) {
      return u.s.srcport_ < otherkey.u.s.srcport_;
    }
    if (u.s.dstport_ != otherkey.u.s.dstport_) {
      return u.s.dstport_ < otherkey.u.s.dstport_;
    }
    if (u.s.protocol_ != otherkey.u.s.protocol_) {
      return u.s.protocol_ < otherkey.u.s.protocol_;
    }
    return false;
  }

  uint32_t getSrcip() const { return u.s.srcip_; }
  uint16_t getSrcport() const { return u.s.srcport_; }
  uint32_t getDstip() const { return u.s.dstip_; }
  uint16_t getDstport() const { return u.s.dstport_; }
  uint8_t getProtocol() const { return u.s.protocol_; }

  inline void setBit(int32_t pos, bool one) {
    if (BYTE(pos) >= 13) {
      throw FlowKeyOutOfRange(pos, 0, 13);
    }
    if (one) {
      u.key_[BYTE(pos)] |= (1 << BIT(pos));
    } else {
      u.key_[BYTE(pos)] &= ~(1 << BIT(pos));
    }
  }

  inline uint8_t getBit(int32_t pos) const {
    if (BYTE(pos) >= 13) {
      throw FlowKeyOutOfRange(pos, 0, 13);
    }
    return (u.key_[BYTE(pos)] >> BIT(pos)) & 1;
  }

  FlowKey *operator^=(const FlowKey &otherkey) {
    for (int i = 0; i < 13; ++i) {
      u.key_[i] ^= otherkey.u.key_[i];
    }
    return this;
  }
};

} // namespace SketchLab

namespace std {
template <int32_t key_len> struct hash<const SketchLab::FlowKey<key_len>> {

  std::size_t operator()(const SketchLab::FlowKey<key_len> &flowkey) const {
    size_t ret = 0;
    for (int32_t i = 0; i < key_len; ++i) {
      ret = std::hash<uint8_t>()(flowkey.cKey()[i] + ret);
    }
    return ret;
  }
};

template <int32_t key_len> struct equal_to<const SketchLab::FlowKey<key_len>> {

  std::size_t operator()(const SketchLab::FlowKey<key_len> &flowkey1,
                         const SketchLab::FlowKey<key_len> &flowkey2) const {
    for (int32_t i = 0; i < key_len; ++i) {
      if (flowkey1.cKey()[i] != flowkey2.cKey()[i])
        return false;
    }
    return true;
  }
};

} // namespace std
#undef BYTE
#undef BIT
#endif
