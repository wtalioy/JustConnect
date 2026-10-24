#include "helpertransport.h"
#include <QJsonDocument>
#include <fcntl.h>
#include <unistd.h>

xpc_object_t macHelperMessage(const QJsonObject &packet, int descriptor, const AuthorizationExternalForm *authorization)
{
    const auto data = QJsonDocument(packet).toJson(QJsonDocument::Compact);
    if (data.size() > MacHelperPacketBytes) return nullptr;
    const auto message = xpc_dictionary_create(nullptr,nullptr,0);
    xpc_dictionary_set_data(message,"packet",data.constData(),size_t(data.size()));
    if (descriptor >= 0) xpc_dictionary_set_fd(message,"device_fd",descriptor);
    if (authorization) xpc_dictionary_set_data(message,"authorization",authorization,sizeof(*authorization));
    return message;
}
bool readMacHelperMessage(xpc_object_t message, QJsonObject &packet, int *descriptor)
{
    packet = {};
    if (descriptor) *descriptor = -1;
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    const auto value = xpc_dictionary_get_value(message,"packet");
    const auto fd = xpc_dictionary_get_value(message,"device_fd");
    const auto authorization = xpc_dictionary_get_value(message,"authorization");
    if (!value || xpc_get_type(value) != XPC_TYPE_DATA || xpc_dictionary_get_count(message) != size_t(1+(fd ? 1 : 0)+(authorization ? 1 : 0))
        || (authorization && (descriptor || xpc_get_type(authorization) != XPC_TYPE_DATA || xpc_data_get_length(authorization) != sizeof(AuthorizationExternalForm)))
        || (fd && (!descriptor || xpc_get_type(fd) != XPC_TYPE_FD))) return false;
    const auto size = xpc_data_get_length(value);
    if (!size || size > MacHelperPacketBytes) return false;
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(QByteArray(static_cast<const char *>(xpc_data_get_bytes_ptr(value)),qsizetype(size)),&error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    if (authorization && document.object()["operation"] != "apply") return false;
    if (fd) {
        const int copied = xpc_dictionary_dup_fd(message,"device_fd");
        if (copied < 0) return false;
        const int flags = ::fcntl(copied,F_GETFD);
        if (flags < 0 || ::fcntl(copied,F_SETFD,flags|FD_CLOEXEC) != 0) { ::close(copied); return false; }
        *descriptor = copied;
    }
    packet = document.object(); return true;
}
