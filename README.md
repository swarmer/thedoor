# thedoor
A horrible linux backdoor module

This is a linux kernel module that adds a device `/dev/door`.
When a correct password is written to this file,
you are immediately made root without any checks.

## Building
A linux source tree has to be in `./linux`.
Don't forget to make the device file accesible to everyone if you want
for unprivileged users to be able to write to it.

## License
Don't use this. Please.
