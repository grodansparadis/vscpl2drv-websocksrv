#ifndef VSCP_SECURE_MEMORY_H
#define VSCP_SECURE_MEMORY_H

#include <sodium.h>

#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

template <typename T>
class SecureAllocator {
public:
  using value_type = T;

  SecureAllocator() noexcept = default;
  template <typename U>
  SecureAllocator(const SecureAllocator<U> &) noexcept {}

  T *allocate(size_t count)
  {
    static const int initialized = sodium_init();
    if (initialized < 0) {
      throw std::runtime_error("Unable to initialize libsodium secure memory");
    }
    if (count > std::numeric_limits<size_t>::max() / sizeof(T)) {
      throw std::bad_array_new_length();
    }
    const size_t bytes = count * sizeof(T);
    void *memory = sodium_malloc(bytes);
    if (!memory) {
      throw std::bad_alloc();
    }
    // sodium_malloc alone can succeed even if its implicit memory lock fails.
    if (sodium_mlock(memory, bytes) != 0) {
      sodium_free(memory);
      throw std::runtime_error("Unable to lock secure memory; check the process locked-memory limit");
    }
    return static_cast<T *>(memory);
  }

  void deallocate(T *memory, size_t) noexcept
  {
    sodium_free(memory);
  }
};

template <typename T, typename U>
bool operator==(const SecureAllocator<T> &, const SecureAllocator<U> &) noexcept
{
  return true;
}

template <typename T, typename U>
bool operator!=(const SecureAllocator<T> &, const SecureAllocator<U> &) noexcept
{
  return false;
}

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using SecureBytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

#endif
