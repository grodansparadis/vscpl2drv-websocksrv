#include "userlist.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <type_traits>

#ifdef __linux__
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static void require(bool condition, const char *message)
{
  if (!condition) throw std::runtime_error(message);
}

static void requireLocked(const void *pointer)
{
#ifdef __linux__
  std::ifstream maps("/proc/self/smaps");
  require(maps.is_open(), "Cannot inspect Linux secure-memory mappings");
  const auto address = reinterpret_cast<std::uintptr_t>(pointer);
  std::string line;
  bool selected = false;
  while (std::getline(maps, line)) {
    std::istringstream range(line);
    std::uintptr_t start, end;
    char separator;
    if ((range >> std::hex >> start >> separator >> end) && separator == '-') {
      selected = start <= address && address < end;
    }
    if (selected && line.rfind("VmFlags:", 0) == 0) {
      require(line.find(" lo ") != std::string::npos, "Password memory is not locked");
      require(line.find(" dd ") != std::string::npos, "Password memory is not excluded from core dumps");
      return;
    }
  }
  throw std::runtime_error("Secure-memory mapping was not found");
#else
  (void) pointer;
#endif
}

int main(int argc, char **argv)
try {
  require(argc == 2, "Expected sample user-file path");
  SecureBytes plaintext(64, 0);
  const char fixture[] = "secret with : punctuation ";
  std::copy(std::begin(fixture), std::end(fixture), plaintext.begin());
  const std::string_view password(reinterpret_cast<const char *>(plaintext.data()), sizeof(fixture) - 1);
  requireLocked(plaintext.data());

  SecureBytes hash(crypto_pwhash_STRBYTES);
  require(crypto_pwhash_str_alg(reinterpret_cast<char *>(hash.data()), password.data(), password.size(),
                               crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                               crypto_pwhash_ALG_ARGON2ID13) == 0, "Hash generation failed");
  const std::string_view hashView(reinterpret_cast<const char *>(hash.data()));
  CUserItem user;
  user.setPassword(hashView);
  static_assert(std::is_same_v<decltype(user.getPassword()), std::string_view>);
  require(user.getPassword() == hashView, "Hash changed while storing it");
  requireLocked(user.getPassword().data());
  require(user.validatePassword(password), "Secure password verification failed");
  require(user.checkPassword(password), "checkPassword must verify Argon2id, not compare strings");
  require(!user.validatePassword("wrong"), "Wrong password was accepted");
  require(!user.validatePassword(std::string_view{}), "Empty password was accepted");
  require(!user.validatePassword(hashView), "A stored hash was accepted as a password");
  require(!user.validatePassword(password.substr(0, password.size() - 1)), "Password whitespace was discarded");

  user.setPassword(hashView);
  requireLocked(user.getPassword().data());
  std::string settings;
  require(user.getAsString(settings), "Cannot serialize masked user settings");
  require(settings.find(hashView) == std::string::npos, "User settings exposed the password hash");
  std::map<std::string, std::string> fields;
  require(user.getAsMap(fields), "Cannot serialize masked user fields");
  require(fields["password"] == std::string(hashView.size(), '*'), "Password field must be masked");

  CUserList users;
  require(users.loadUsersFromFile(argv[1]), "Secure user-file loading failed");
  auto admin = users.validateUser("admin", "secret");
  require(admin != nullptr, "Sample user login failed");
  requireLocked(admin->getPassword().data());
  require(!users.validateUser("admin", "incorrect"), "Incorrect sample password accepted");

  sodium_memzero(plaintext.data(), plaintext.size());
  require(sodium_is_zero(plaintext.data(), plaintext.size()), "Explicit password wipe failed");
  // Deallocation must also work if the caller made a guarded buffer inaccessible.
  SecureBytes guarded(32);
  require(sodium_mprotect_noaccess(guarded.data()) == 0, "Cannot protect secure allocation");

#ifdef __linux__
  const pid_t child = fork();
  require(child >= 0, "Cannot fork memory-lock failure test");
  if (child == 0) {
    const rlimit limit{0, 0};
    if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) _exit(2);
    try {
      SecureBytes blocked(32);
      _exit(3);
    } catch (const std::runtime_error &) {
      _exit(0);
    }
  }
  int status;
  require(waitpid(child, &status, 0) == child, "Cannot wait for memory-lock failure test");
  require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Lock failure did not fail closed");
#endif
  std::cout << "Secure password memory, hash masking, verification, and fail-closed tests passed\n";
  return 0;
} catch (const std::exception &error) {
  std::cerr << error.what() << '\n';
  return 1;
}
