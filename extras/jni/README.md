Android NDK build files
=======================

## Building independent library

CryptoPP library can be independently built using just one command:

    cd <cryptopp-folder>
    ndk-build NDK_PROJECT_PATH=`pwd`/extras

This will build shared library `libcryptopp_shared.so` in `extras/libs/`, static library `libcryptopp_static.a` in `extras/obj/`, and `cryptest.exe` binary.

## Integrate CryptoPP into application

It is also possible to integrate CryptoPP into applications build process.
For example, if application source has the following structure:

    ├── AndroidManifest.xml
    ├── java
    │   ├── ...
    │   └── ...
    ├── jni
    │   ├── Android.mk
    │   └── Application.mk
    └── res
        ├── ...
        └── ...

- Copy CryptoPP source code (or create git submodule) in `jni/cryptopp`.

- In application's `Android.mk` add the desired version of the library.

  For shared version:

        LOCAL_PATH := $(call my-dir)
        LOCAL_PATH_SAVED := $(LOCAL_PATH)

        include $(CLEAR_VARS)
        LOCAL_MODULE := my-local-module
        LOCAL_SHARED_LIBRARIES := cryptopp_shared ...
        include $(BUILD_SHARED_LIBRARY)

        include $(LOCAL_PATH_SAVED)/cryptopp/extras/jni/cryptopp-shared.mk

  For static version:

        LOCAL_PATH := $(call my-dir)
        LOCAL_PATH_SAVED := $(LOCAL_PATH)

        include $(CLEAR_VARS)
        LOCAL_MODULE := my-local-module
        LOCAL_STATIC_LIBRARIES := cryptopp_static ...
        include $(BUILD_SHARED_LIBRARY)

        include $(LOCAL_PATH_SAVED)/cryptopp/extras/jni/cryptopp-static.mk
