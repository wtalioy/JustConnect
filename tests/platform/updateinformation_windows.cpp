#include <QString>
#include <QVarLengthArray>
#include <qt_windows.h>
#include <commctrl.h>
#include <oleacc.h>
#include <oleauto.h>
#include <wrl/client.h>

bool acknowledgeWindowsUpdateInformation(HWND owner, const QString &title, const QString &description)
{
    const auto dialog = FindWindowW(L"#32770",title.toStdWString().c_str());
    if (!IsWindowVisible(dialog) || GetWindow(dialog,GW_OWNER) != owner) return false;
    const auto content = FindWindowExW(dialog,nullptr,L"DirectUIHWND",nullptr);
    Microsoft::WRL::ComPtr<IAccessible> accessible;
    if (!content || FAILED(AccessibleObjectFromWindow(content,OBJID_CLIENT,IID_PPV_ARGS(accessible.GetAddressOf()))))
        return false;

    LONG count = 0;
    if (FAILED(accessible->get_accChildCount(&count)) || count <= 0) return false;
    QVarLengthArray<VARIANT,8> children(count);
    LONG fetched = 0;
    if (FAILED(AccessibleChildren(accessible.Get(),0,count,children.data(),&fetched))) return false;
    bool foundContent = false;
    for (LONG i = 0; i < fetched; ++i) {
        auto &child = children[i];
        Microsoft::WRL::ComPtr<IAccessible> object = accessible;
        VARIANT id = child;
        if (child.vt == VT_DISPATCH) {
            object.Reset();
            if (child.pdispVal) child.pdispVal->QueryInterface(IID_PPV_ARGS(object.GetAddressOf()));
            id.vt = VT_I4;
            id.lVal = CHILDID_SELF;
        }
        BSTR name = nullptr;
        if (object && SUCCEEDED(object->get_accName(id,&name)) && name)
            foundContent |= QString::fromWCharArray(name,SysStringLen(name)) == description;
        SysFreeString(name);
        VariantClear(&child);
    }
    if (!foundContent) return false;
    SendMessageW(dialog,TDM_CLICK_BUTTON,IDOK,0);
    return true;
}
