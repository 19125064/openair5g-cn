## Content
The aim of this page is to help all developers to start with the use of OpenAPI / Swagger tools under a Linux station, coding in C++. The focus will be set, in a first time, to the code generation tool (codegen) and all necessary dependencies.
<br><br>

## Requirements
### Common part
* Java 7 or higher
<pre>
$ sudo apt-get install openjdk-9-jdk
</pre>

* Maven
<pre>
$ sudo apt-get install mvn
</pre>

* cmake
<pre>
$ sudo apt-get install cmake
</pre>


### Server part
* Pistache : This is a C++ framework used to implement the C++ Server stub part. See [Installation](#Installation)

* JSON for Modern C++ : Download the json.hpp file from [nlohmann git repository](https://github.com/nlohmann/json/releases) and put it under the model folder as soon as your code will be generated. This is due to the dependence of Pistache framework with this file. Strange that the framework installation does not import it automatically :/

### Client part
* cpprest-sdk
<pre>
$ sudo apt-get install libcpprest-dev
</pre>
<br><br>

## Installation
### Pistache
First of all, I decided to use the C++ generated code based on Pistache framework (see [Recommendations](#Recommendations)), so please follow [Pistache installation page](http://pistache.io/quickstart#installing-pistache)


### openapi-generator
Install the code generation tool  
Due to the permanent evolution of the opensource project, I recommend to clone the openapi-generator and build it. It is compliant with the openAPI V3 specifications.

<pre>
$ cd ~/ ; mkdir openapitools ; cd openapitools 
$ git clone https://github.com/OpenAPITools/openapi-generator.git
$ cd openapi-generator
$ mvn clean package
</pre>

After that, your openapi-generator-cli tool should be usable. Check it (you may see the help page)
<pre>
$ java -jar ${HOME}/openapitools/openapi-generator/modules/openapi-generator-cli/target/openapi-generator-cli.jar help
</pre>


### openapi-generator-cli.sh
For convenience, you may create a script that will call the previous line. This is optional, of course

<pre>
$ mkdir ~/bin
$ echo '#!/bin/bash' > ~/bin/openapi-generator-cli.sh
$ echo 'java -jar ${HOME}/openapitools/openapi-generator/modules/openapi-generator-cli/target/openapi-generator-cli.jar "$@"' >> ~/bin/openapi-generator-cli.sh
$ chmod +x ~/bin/openapi-generator-cli.sh
</pre>

Add the ${HOME}/bin to your PATH variable in your ~/.profile and then logout / login or reload your ~/.profile file. You are now able to call the script from everywhere 
<pre>
$ openapi-generator-cli.sh help
</pre>
<br><br>

## Recommendations
### C++ Server stub
The openapi-generator-cli tool is able to generate two different C++ <u>server</u> code (Restbed and Pistache) and we have to choose one of them. I decided to retain the pistache-server for two reasons :
1. The generated code is more structured : different folders are produced whereas the restbed-server is flat
2. The performances seems better within pistache framework see below : 


| Language : Framework | Max time amongst 98% of requests ms, smaller is better | Average requests per second #/sec, larger is better | Lines of code in sample #, count without blanks |
| --- | --- | --- | --- |
| C++ : cpprestsdk / default JSON implementation | 51 ![#f03c15](https://placehold.it/15/f03c15/000000?text=+) |  30.70 ![#f03c15](https://placehold.it/15/f03c15/000000?text=+) | 48 ![#f03c15](https://placehold.it/15/f03c15/000000?text=+) |
| C++ : cpprestsdk / RapidJSON | 44 | 47.06 | 47 |
| C++ : restbed | 7 | 224.18 | 39 |
| C++ : pistache | 6 ![#c5f015](https://placehold.it/15/c5f015/000000?text=+) | 319.99  ![#c5f015](https://placehold.it/15/c5f015/000000?text=+) | 40 |
| PHP : Native implementation |10 | 146.95 | 14 ![#c5f015](https://placehold.it/15/c5f015/000000?text=+) |  



### Namespaces
For convenience and some kind of standardization inside the project, I would recommend to use namespaces like this :

<pre>
com::bcom::&lt;network function&gt;::microservice::&lt;client or server&gt;::&lt;micro service&gt;::&lt;scope&gt;
</pre>

For example :
<pre>
com::bcom::amf::microservice::server::ms1::model
com::bcom::amf::microservice::server::ms1::api

com::bcom::amf::microservice::client::ms2::model
com::bcom::amf::microservice::client::ms2::api
</pre>
<br><br>

## Use a configuration file
A codegen configuration file will be generated automatically by the Makefile process. This configuration file (config.json) will hold and describe some namespaces implemented inside the produced  C++ code (server and client). The namespaces hierarchy will be as below

**config.json**
<pre>
{
    "modelPackage"   : "com.bcom.nf.microservice.server.&lt;micro service name&gt;.model",
    "apiPackage"     : "com.bcom.nf.microservice.server.&lt;micro service name&gt;.api"
}
</pre>

Of course, the user (developer) may want to define its own configuration file. This is possible and the Makefile process will not erase it. This is just for convenience that the code production tool produces a default config.json file, if none has been defined by the developer.
More over, if the developer wants to use this namespace template, it has to rename the \<nf\> stair in the appropriated network function name (for example amf, smf, ... etc)


<u>Note</u> :
The \<micro service name\> is auto-determined depending on the client/server directory name. See below for more information about the [C++ MicroService Production Environment](#C-MicroService-Production-Environment)
<br><br>

## C++ MicroService Production Environment
### Installation
To facilitate the development of micro-services, I developed a production environment based on make and cmake tools. 

The skeleton that should (must ?) be used to start a micro-service development have to be downloaded from its repository and stored inside the folder **src** of the defined structure. See [the folders structure](#Structure-content).



### Structure content
The folder structure looks like :

<pre>
/
├── api-service                       : API node containing the OpenApi definition file
│   └── openapi.yaml                  : OpenApi definition file
└── src                               : Container of the effective microservice code
    ├── server                        : Server node
    │   ├── api                       : Generated files representing the C++ API. Folder reserved to openapi-generator
    │   ├── impl                      : Generated files describing the empty skeleton inherited from the api. 
    │   │                               These files have to be duplicated and renamed, then the inner methods 
    │   │                               may be filled to fit to your needs.
    │   │                               &lt;impl&gt; is the only folder where the developer may store its code
    │   ├── model                     : Generated files representing all classes. Folder reserved to openapi-generator
    │   │   └── json.hpp              : Additional file needed by the pistache-server framework
    │   └── Makefile                  : Entry point to build the micro-service server part. It may be specialized
    │                                   by the developer. See &lt;make help&gt; command line and the file content itself
    ├── client                        : Client node - It may contains several clients as shown for illustration
    │   ├── client-ms2                : Client of the micro-service named &lt;ms2&gt;
    │   │   ├── api-ms2               : Contains the api of the &lt;ms2&gt; micro-service. This should be a git submodule or a git clone ? TBD
    │   │   │   └── openapi.yaml      : The OpenApi file
    │   │   └── Makefile              : Entry point to build the micro-service client part. It may be specialized
    │   │                               by the developer. See &lt;make help&gt; command line and the file content itself
    │   ├── client-ms3                : A client of an another micro-service &lt;ms3&gt;
    │   │   ├── api-ms3
    │   │   │   └── openapi.yaml
    │   │   └── Makefile
    │   └── Makefile                  : Entry point to build ALL micro-services clients under its folder
    │                                   It may NOT be modified
    ├── Makefile                      : Entry point to build ALL clients and the server
    │                                   It may NOT be modified
    ├── debug.mk                      : Target declaration useful in Makefiles debugging
    ├── rules.mk                      : General Makefile rules declaration to apply automatics rules
    └── variables.mk                  : General Makefile variables declarations

</pre>

The skeleton holds directories and all files to be able to build a micro-service server and several clients libraries.
Enter <pre>$ make</pre> under the root directory described above and all C++ files will be generated, compiled and linked. 

All clients described under this structure will be generated as some C++ libraries and the server will link automatically with all these libraries

This generation is, of course, dependent of the Open API file(s) in their appropriate folders :
* ./client/client-&lt;micro-service&gt;/api-&lt;micro-service&gt; for the clients nodes
* ../api-&lt;micro-service&gt; for the server node. (This is a b-com internal convention)


<b>Note 1</b>:
The global build can't succeed till the server does not describe an API. The make may succeed only inside the clients folder

<b>Note 2</b>:
If no client interface is needed, the developer may delete all client-&lt;micro-service&gt; directories but NOT the client directory

OK:
<pre>
$ rm -rf ./client/client-ms2 ./client/client-ms3 
</pre>
Wrong:
<pre>
$ rm -rf ./client
</pre>


### Specialization
This automatic production environment uses default values to name some files, for example, but the developer may want to modify and specialize some kind of automatic decisions. 
Under server or clients folders, the developer may use the command line 
<pre>
$ make help
</pre>
to get a short manual.

It describes a simple general usage and to specialize the real Makefile behavior, please have a look to the Makefile content it self. At the begin of the file, it contains an identified section the developer may modify. See below an extract from the server/Makefile (for illustration) :


<pre>
########################################################
# User may redefines some default values, see below
########################################################
#


# Default Micro Service name
# This is the name retrieve from the directory name where the OpenApi file is
# stored (the directory must fit the syntax : "api-<ms name>"
MS_NAME := $(patsubst ../../api-%,%, $(wildcard ../../api-*))

# Project name is the server name (binary file)
PROJECT_NAME := server-$(MS_NAME)

# Default OpenApi input file
CODEGEN_INPUT := $(wildcard ../../api-*/openapi.yaml)

# Default code generator configuration file
# If no configuration file is created by the user, the makefile process
# will automatically create one
CODEGEN_CONF := ./config.json

# Add the generated folders to the include path research
CPPFLAGS += -I./api -I./model -I./impl

# Add automatically all the client include path
CPPFLAGS += $(addprefix -I, $(wildcard ../client/*/gen-cpp/api))

# Add automatically all OpenApi Client libs declared inside this Micro Service
LIBS += $(wildcard ../client/*/gen-cpp/lib/*.a)

# External library installed on the station (not project libs)
EXT_LIB = -lpistache -lpthread

TARGET  := $(PROJECT_NAME)

#
##########################################################
# User is not supposed to modify something below this line
##########################################################
</pre>


## Write an API file
A micro-service is designed, first, thanks to its API and have to be described using the Open API V3 syntax (in YAML) in a dedicated file stored under its dedicated folder (again this is a b-com internal convention)


## Build
As already described above, the only command line that will produce <u>everything</u> is, under the **src** folder (*root* from the structure described previously) :

<pre>
$ make
</pre>


<b>Note</b> :
The link may failed due to the entry point __main not found. This is expected.
The code generation produces a file named *xxxxApiMainServer.cpp* that contains an example of what should be a really simple C++ main but this file is not taken into account by the Makefile. 
To get a succeeded build process, please copy (or link) this file inside the *impl* folder. Relaunch the make and now the build should succeed.
This *main()* file is only an example and should not stay like this. The developer have to code his own main entry point.

In case the developer wants to build only the server (ie client) part, the same command line have to be launch under the corresponding folder : server or one of the client folder. That's it.


<b>Additional structure information and implementation advice</b> :

The three folders below are used by the openapi code generation tool to store some kind of files. Have a look to this current extract openapi-generator-cli documentation 

* **api**: This folder contains the handlers for each method specified in the openapi definition. Every handler extracts the path and body parameters (if any) from the requests and tries to parse and possibly validate them. Once this step is completed, the main API class calls the corresponding abstract method that should be implemented by the developer (a basic implementation is provided under the impl folder)


* **impl**: As written above, the implementation folder contains, for each API, the corresponding implementation class, which extends the main API class and implements the abstract methods. Every method receives the path and body parameters as constant reference variables and a reference to the response object, that should be filled with the right response and sent at the end of the method with the command: response.send(returnCode, responseBody, [mimeType])


* **model**: This folder contains the corresponding class for every object schema found in the openapi specification.


## After the first build
### impl/files
Two files (at least) are generated in the *impl* folder :
* xxxxApiImpl.cpp
* xxxxApiImpl.h


These files represent an implementation example of the API described in the YAML file. They illustrate how to interface the code with the generated API and show an empty skeleton. All empty methods should be filled in with a dedicated code corresponding to the expected behavior.
The developer MUST add these files in the generator ignore list in this case.


What for ?

Because each time the generation tool will be re-launched, each time it will erase the *impl/xxxxApilImpl.\** files, so make sure your code is protected from it.


### Avoid non needed files
The openapi code generation tool read the dedicated file *.openapi-generator-ignore* to avoid some generation. For example, after the developer copy/paste the *xxxxApiMainServer.cpp* into its own main entry point file (inside impl/ folder would be a nice idea) , there is no need to generate it again. Place the file name inside this ignore list and *openapi-generator-cli* will ignore its generation. It works like *.gitignore*
Same job to do with the *impl/xxxxApilImpl.\** files.


<u>Note 1</u> : The developer may want to name its implementation files in another way, so, rename the *impl/xxxxApilImpl.\** with a suitable name and add also the *impl/xxxxApilImpl.\** files into the ignore list.

<u>Note 2</u> : Considering the *impl/xxxxApilImpl.\** files have been filled to fit to the wanted behavior, each time the OpenApi file changes (and after the generator had been ran), the new generated API will have to be copied from the *api/xxxxApi.\** into *impl/xxxxApilImpl.\**
<br><br>

## Tools

* [Online yaml-formatter](https://jsonformatter.org/yaml-formatter)
* [Online json-editor](https://jsonformatter.org/json-editor )
* [Online yaml to json](https://jsonformatter.org/yaml-to-json )
* [Online markdown editor](https://dillinger.io/)
<br><br>

## References
* OpenAPI Specifications  [Swagger](https://swagger.io/specification/) and [Github](https://github.com/OAI/OpenAPI-Specification/tree/master/versions )
* [OpenAPITools](https://github.com/OpenAPITools/openapi-generator)
* [Swagger](https://swagger.io)
* [Pistache](http://pistache.io/)
* [C++ REST API frameworks benchmark](https://blog.binaryspaceship.com/2017/cpp-rest-api-frameworks-benchmark/ )
* [Swagger Petstore example / Pistache generation](https://github.com/swagger-api/swagger-codegen/blob/master/samples/server/petstore/pistache-server/README.md)
* [C++ namespaces](http://en.cppreference.com/w/cpp/language/namespace)
* [C++17 Support in GCC](https://gcc.gnu.org/projects/cxx-status.html#cxx17) (see "Nested namespace definitions" for namespace syntax compliance)
* [cmake](https://cmake.org/)
* [make](https://www.gnu.org/software/make/manual/make.html )


