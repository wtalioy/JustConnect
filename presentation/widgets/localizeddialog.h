#pragma once
#include <QEvent>
#include <functional>
#include <utility>

template<class Dialog>
class LocalizedDialog final : public Dialog {
public:
    using Dialog::Dialog;
    void setTranslation(std::function<void()> translate) { translation=std::move(translate);translation(); }
protected:
    void changeEvent(QEvent *event) override {
        Dialog::changeEvent(event);
        if(event->type()==QEvent::LanguageChange && translation)translation();
    }
private:
    std::function<void()> translation;
};
