# Nginx Basic Authentication Decode Module

## Introduction

The `basic_auth_decode` module for Nginx is designed to enhance the server's capabilities by extracting the username and password from the request Authorization header and exposing them as variables for use in the Nginx configuration. This module simplifies the retrieval of basic authentication credentials, allowing for more flexible and dynamic configurations.

## Installation

You can download the module binaries from the release page, or build from the source code.

The easiest way to build from sources is to build using the provided Dockerfile.

```shell
docker buildx build --build-arg NGX_VERSION=1.23.3 -t ngx-auth-decode .
```

## Configuration

To enable the `basic_auth_decode` module in your Nginx configuration, add the following lines to your nginx.conf file:

```nginx
http {
    # ...

    # Load the ngx_basic_auth_decode module
    load_module modules/ngx_basic_auth_decode_module.so;

    # ...

    server {
        # ...

        location / {
            # ...

            # Use $basic_auth_user and $basic_auth_pass in your configuration
            # For example, you can pass them to a backend application or use them in conditional statements.
            
            # ...
        }

        # ...
    }

    # ...
}

```

## Usage

Once the `ngx_basic_auth_decode` module is installed and configured, you can use the variables `$basic_auth_user` and `$basic_auth_pass` in your Nginx configuration. These variables will contain the extracted username and password from the Authorization header, respectively.

For example:

```nginx
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
