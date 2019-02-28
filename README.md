# PassGen

## Description

A simple password generator written with the use of secure memory and utilization of SHA256 to generate a unique password.

This program requires gcrypt to compile.

## Usage

~~~
./bin/passgen.out
~~~

Use a master password to secure future generated passwords. Enter different locations to make a new password, which will be different depending on what master password you entered before and the specific location entered. Identical master passwords and locations will generate the same password but a generated password should be impossible to reverse back to these items (until SHA256 is broken).

## Build

~~~
make all
~~~
