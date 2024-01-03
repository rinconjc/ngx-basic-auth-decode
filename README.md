# Nginx Basic Authentication Decode Module

## Introduction

The `ngx-basic-auth-decode` module for Nginx is designed to enhance the server's capabilities by extracting the username and password from the request Authorization header and exposing them as variables for use in the Nginx configuration. This module simplifies the retrieval of basic authentication credentials, allowing for more flexible and dynamic configurations.

## Installation

1. You can download the module binaries from the release page, or build it from the source code.

2. The easiest way to build from sources is to build using the provided Dockerfile.

```shell
docker buildx build --build-arg NGX_VERSION=1.23.3 -t ngx-basic-auth-decode . && \
docker_id=$(docker create --rm ngx-basic-auth-decode) && \
docker cp $docker_id:/etc/nginx/modules/libngx_basic_auth_decode.so ./
docker stop $docker_id
```
3. Copy the module `libngx_basic_auth_decode.so` to the nginx modules directory: `/etc/nginx/modules/`

## Usage

Once the `ngx-basic-auth-decode` module is installed and configured, you can use the variables `$basic_auth_user` and `$basic_auth_pass` in your Nginx configuration. These variables will contain the extracted username and password from the Authorization header, respectively.

For example:

```nginx

# Load the ngx-basic-auth-decode module
load_module modules/libngx-basic-auth-decode_module.so;

location / {
    # ...

    # Pass credentials to a backend application
    proxy_pass http://backend/something

    # Use credentials in a conditional statement
    if ($basic_auth_user = "admin") {
        # Do something for admin users
    }

    # ...
}

```

## License

This module is released under the MIT License. Feel free to use, modify, and distribute it according to your needs.
