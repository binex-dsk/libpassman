# libpassman
Library for interacting with passman++ databases.

# Building
You need the Qt 6 and Botan libraries before building. CMake will throw an error if you don't have these.

Simply run:
```bash
$ cmake -S . -B build
```

To install, run (as root):
```bash
# cmake --build build --target install
```

Also available from the AUR as `libpassman`:
```bash
$ git clone https://aur.archlinux.org/libpassman.git
$ cd libpassman
$ makepkg -si
```

Or with yay:
```bash
$ yay -S libpassman
```

# Usage
Docs coming eventually. You can see its use in [passman++](https://github.com/binex-dsk/passmanpp) though.
