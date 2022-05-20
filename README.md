# TLS Echo Server

Class: CSE544
Name:: Ashita
Roll No: 2019028
Type: Assignment  4

# Creating certificates and keys

1. Generate private key for CA : `openssl genrsa 2048 > ca-key.pem`
2. Generate the X509 certificate for the CA: `openssl req -new -x509 -nodes -days 365000 -key ca-key.pem -out ca-cert.pem`
3. Create Server Certificate and keys
    1. Generate the private key and certificate request:`openssl req -newkey rsa:2048 -nodes -days 365000 -keyout server-key.pem  -out server-req.pem`
        1. Dont forget to keep Common Name as <our IP address or hostname> , here it is localhost
    2. Generate  X509 certificate for the server : `openssl x509 -req -days 365000 -set_serial 01 -in server-req.pem -out server-cert.pem -CA ca-cert.pem -CAkey ca-key.pem`
4. Create Client Certificate and keys
    1. Generate the private key and certificate request:`openssl req -newkey rsa:2048 -nodes -days 365000 -keyout client-key.pem  -out client-req.pem`
        1. Dont forget to keep Common Name as <our IP address or hostname> , here it is localhost
    2. Generate  X509 certificate for the client : `openssl x509 -req -days 365000 -set_serial 01 -in client-req.pem -out client-cert.pem -CA ca-cert.pem -CAkey ca-key.pem`
5. Sample output 
    
    ![Screenshot from 2022-04-17 17-35-25.png](TLS%20Echo%20Server%20decf3cbd447a49ac81c0fb318494bb27/Screenshot_from_2022-04-17_17-35-25.png)
    

# Working of echo server

## Server Side

1. Construct SSL context `ssl_init()` , include all algorithms, TLS method, error strings and then returns context pointer , for furthur understanding can refer [this](https://wiki.openssl.org/index.php/Simple_TLS_Server).
    1. `TLSv1_2_server_method()` :The TLS server method is used to establish a server that will negotiate the highest version of SSL/TLS enabled by the client it is connecting to. 
2. After that, the context is set up by specifying the certificate and private key to be used using `send_certificates()`
3. Created socket to listen to connections as shown in  `create_socket()`. We call accept as normal whenever we get a new connection. 
4. To deal with TLS, we establish a separate SSL structure that stores information about this specific connection using : `SSL_new()`
5. Start verification of the connection, for more info go [here](https://wiki.openssl.org/index.php/SSL/TLS_Client)
    1. **SSL_CTX_set_verify** : This guarantees that the chain is verified in accordance with [RFC 4158](http://tools.ietf.org/html/rfc4158) and that information about the Issuer and Subject can be printed.If no custom processing need to be done to the certificate (as in our case, callback can be set NULL).
    2. **SSL_CTX_set_verify_depth** : To set the depth or the extent to verify the parent issuer.
    3. **SSL_CTX_set_options**: Sets flags such as SSL_OP_ALL, SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_COMPRESSION which removes SSL protocols leaving only TLS.
    4. **SSL_CTX_load_verify_locations**: Loads certificate chain of the host.Need to pass CA certificate and CA key .
    5. **SSL_get_peer_certificate**: To get the certificate , and see its subject and Issuer
    6. **SSL_get_verify_result**: To verify the certificate with the provided CA.Returns various verfication codes and returns 0 if verification is done correctly.
6. Last two methods are mentioned in `function vertify_certs()`
7.  To notify openssl the file descriptor to utilise for communication, we use SSL set fd. We use `SSL accept()` to handle the server side of the TLS handshake in this example, then `SSL write()` ****to transmit our message. Here the server converts the recieved message to uppercase and writes to the client using ssl write.
8. Connection is persistent, various clients can connect to it, client is also verified before connection establishment.
9. Last but not least, we clean up the various structures.

## Client Side

1. Every function is same as mentioned above till 6th point
2. Server is verified before connection established as mentioned in 5th point in server code.
3. To connect to the connection we use `ssl_connect()` once connected , send the message using `SSLwrite()` and recieve messsage using `SSLread()`
4. Once we recieve data connection is closed and all structures are freed using `SSL_free()`

## Correct compilation output:

`gcc -Wall -o client  client.c -L/usr/lib -lssl -lcrypto
gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto`

![Screenshot from 2022-04-17 17-25-24.png](TLS%20Echo%20Server%20decf3cbd447a49ac81c0fb318494bb27/Screenshot_from_2022-04-17_17-25-24.png)

Here we can see, client is verfied by server and server is verified by client.

## Wireshark Output

1. The moment a client connects to server , a new tls handshake is done
    
    ![Screenshot from 2022-04-17 17-22-10.png](TLS%20Echo%20Server%20decf3cbd447a49ac81c0fb318494bb27/Screenshot_from_2022-04-17_17-22-10.png)
    
2. Opening the row , we can see the protocol with version specified : TLS 1.2v
    
    ![Screenshot from 2022-04-17 17-22-29.png](TLS%20Echo%20Server%20decf3cbd447a49ac81c0fb318494bb27/Screenshot_from_2022-04-17_17-22-29.png)
    
3. Looking the application data, we can see its encrypted
    
    ![Screenshot from 2022-04-17 17-23-28.png](TLS%20Echo%20Server%20decf3cbd447a49ac81c0fb318494bb27/Screenshot_from_2022-04-17_17-23-28.png)
    

### References:

[https://wiki.openssl.org/index.php/Simple_TLS_Server](https://wiki.openssl.org/index.php/Simple_TLS_Server)

[https://gist.github.com/kylelemons/1135155/feef1024cc97952de7b7e24d0875b695de12cbea](https://gist.github.com/kylelemons/1135155/feef1024cc97952de7b7e24d0875b695de12cbea)

[https://aticleworld.com/ssl-server-client-using-openssl-in-c/](https://aticleworld.com/ssl-server-client-using-openssl-in-c/)

[http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html](http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html)

[https://fm4dd.com/openssl/sslconnect.shtm](https://fm4dd.com/openssl/sslconnect.shtm)

[https://mariadb.com/docs/security/encryption/in-transit/create-self-signed-certificates-keys-openssl/](https://mariadb.com/docs/security/encryption/in-transit/create-self-signed-certificates-keys-openssl/)