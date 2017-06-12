# pedit
## v1.1.0
## About
Pedit, portable executable resource editor.

The peedit python application starts the interactive session to allow the user
to select the desired resource to edit and provide means to edit resources.

Pedit makes use of the pefile module and utilizes many data structures of such.

When loaded, pedit with instantiate a pe container which will contain the pe
object, chosen resources and respective values.
## How To
### TL;DR
```
python3 pedit.py <filename>
```
and magic happens.

### Detailed usage
```
pedit.py [OPTIONS] FILENAME
-h, --help
    Shows the help dialog

-i, --insert
    Insert a file into a resource directory

-r, --resource
    Specify resource type and directory. Use type codes e.g. 10, 101

-f, --fast-load
    Load large PEs faster by not not parsing all directories.
```

## Set-up
### Dependencies
#### python3-pefile
- pip
```
sudo pip3 install pefile
```
- DEB base
```
sudo apt-get install python3-pefile
```

- RPM base
```
sudo yum install python3-pefile
```
