# CertViewer

Certificate viewer is a plugin for Altap Salamander, allowing a user to view information about encrypted certificate files. Currently it supports viewing of X.509 certificates in the following formats: PEM (Base64 encoding), DER (encoded binary).

The plugin is based on the [OpenSSL project](http://www.openssl.org/) and it automates `openssl` commands,
that parse and dump information from certificate files. Moreover, it does automatic detection of a file format, and supports most of the common certificate file formats.

## Building the plugin

To get started, download and install the [Altap Salamander SDK](https://www.altap.cz/salamander/downloads/sdk/). This project was developed with the latest version **3.8** (ftp://ftp.altap.cz/pub/altap/salamand/as308sdk.7z). Download and unpack the archive with SDK into your project directory. Project file is preconfigured to use the Altap Salamander SDK, so it has to be cloned into path: `as308sdk\salamand\plugins\certviewer`.

Project depends also on the [OpenSSL](http://openssl.org) library, it was depeloped and tested with version **1.0.2p**. Porting it to a never version should be smooth. Poject is preconfigured to use [vcpkg](https://github.com/Microsoft/vcpkg) utility, which automates installation of 3rd party libraries, and Visual Studio can then automatically detect and use the installed libraries.

Clone the `vcpkg` repository into your project directory.

```
c:\projects> git clone https://github.com/Microsoft/vcpkg.git
c:\projects> cd vcpkg
c:\projects\vcpkg> vcpkg integrate install
```

Build the `vcpkg` utility:

```
c:\projects\vcpkg> bootstrap-vcpkg.bat
```

And install the **OpenSSL** library (both x86 and x64 static libraries):

```
c:\projects\vcpkg> vcpkg install openssl:x86-windows-static
c:\projects\vcpkg> vcpkg install openssl:x64-windows-static
```

We have the development environment ready. Now you can open this project in Visual Studio, project files are in `as308sdk\salamand\plugins\certviewer\vcproj\`. Project is preconfigured for Visual Studio 2017, but it would be easy to downgrade it to older versions (some tips are [here](https://stackoverflow.com/questions/30741185/convert-downgrade-visual-studio-2015-solution-file-to-2013)). Compilation should be successful.

## Debugging

Altap Salamander SDK contains a special version of `salamand.exe`, which should be used for debugging plugins under developent. It can be found here: `as308sdk\bin\vc2008\SDK_x86\salamand.exe` (or under `SDK_X64`). Configure your project in Visual Studio, let it starts this executable for debugging the plugin. Once salamander is running, open *Plugins Manager* dialog from *Plugins* menu, press *Add...* button and find the `certview.spl` file, that was compiled by this project.

## Using the plugin

The CertView plugin views information of the most common certificate files. List of the registered file extensions can be seen in *Configuration* dialog from *Options* menu, under path *Viewers and Editors/Viewers*.

This is a viewer plugin, so select a certificate file in Salamander, press `F3` key and the viewer will show information about the certificate. If you wand to see the raw data instead, press `Shift+F3` keys.

## Contributing

This is my first project where I used the *OpenSSL* library. I don't feel as a security expert, so your contributions are welcome. Here are some ways you can contribute:

* [Submit Issues](https://github.com/lejcik/certviewer/issues)
* [Submit Fixes and New Packages](https://github.com/lejcik/certviewer/pulls)

## Future development

* Resolve TODOs in the code.
* Improve certificate file format detection. Current way is not optimal, but for a viewer it should be ok.
* Support viewing password-protected certificates.

## License

Code licensed under the [Unilicense](LICENSE.txt).
