#include "infrastructure/platform/systemcredentialstore.h"
namespace {
class Store final : public CredentialStore {
public:
    CredentialResult read(const QString &key) override { return {validKey(key)?CredentialStatus::Unavailable:CredentialStatus::InvalidArgument,{}}; }
    CredentialResult write(const QString &key,const QByteArray &) override { return read(key); }
    CredentialResult remove(const QString &key) override { return read(key); }
};
}
std::unique_ptr<CredentialStore> createSystemCredentialStore() { return std::make_unique<Store>(); }
