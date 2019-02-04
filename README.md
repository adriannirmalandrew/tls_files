# tls_files
A simple, multithreaded file server written in Java, which utilizes TLS.

Current status: Alpha. File upload functionality missing (for now).

Instructions for running server:

Server <directory> <portno> <tls_keystore> <password>
  directory - The directory to be served by the Server.
  portno - The port that the Server will be listening on.
  tls_keystore - Path to the keystore with the TLS certificate. Password will be requested on server startup.
  password (optional) - Password for login.
  
The client I will be writing won't have automatic SSL certificate retrieval, so the certificate will have to be manually loaded.
