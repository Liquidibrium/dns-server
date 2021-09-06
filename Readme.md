# DNS Server

## Instructions

details are written in the `DNS Server.docx` document

## Requirement

* `python 3.X`

## run tests

* on linux/ubuntu -  Run command: `./test.sh`

* on Windows - use wsl2

## run tests in docker

1. Install docker
2. Build dockerfile: `docker build -t assignment-2-tester .`
3. Go to assignment project directory and run:
    * Linux: `docker run -it -v "$(pwd)":/sandbox assignment-2-tester`
    * Windows PowerShell: `docker run -it -v $(PWD):/sandbox assignment-2-tester`
    * Windows CMD: `docker run -it -v %cd%:/sandbox assignment-2-tester`
4. At this point you can assume that you'r running `Ubuntu 20.04` with all the necessary dependencies installed, to run
tests multiple times during development it's not necessary to restart the docker, it is able to see all the changes you
make in the folder (because of `mounting` the folder with this command `-v "$(pwd)":/sandbox`)
5. To start tests run: `./test.sh`
6. To exit run: `exit`
