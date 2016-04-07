#-------------------------------------------------
#
# Project created by QtCreator 2016-04-04T18:22:49
#
#-------------------------------------------------

#QT       += core

QT       -= gui

TARGET = WindowsEventParser
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    windowseventparser.cpp \
    common.cpp

HEADERS += \
    windowseventparser.h \
    common.h

LIBS += -lwevtapi
