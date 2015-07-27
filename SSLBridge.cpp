/*
 * Copyright (c) 2002-2009 Moxie Marlinspike
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include "SSLBridge.hpp"
#include <string.h>
#include <errno.h>

using namespace boost::asio;

X509* SSLBridge::getServerCertificate() {
  return SSL_get_peer_certificate(serverSession);
}

void SSLBridge::buildClientContext(SSL_CTX *context, Certificate *leaf, std::list<Certificate*> *chain) {

  SSL_CTX_sess_set_new_cb(context, &SessionCache::setNewSessionIdTramp);
  SSL_CTX_sess_set_get_cb(context, &SessionCache::getSessionIdTramp);

  SSL_CTX_use_certificate(context, leaf->getCert());
  SSL_CTX_use_PrivateKey(context, leaf->getKey());

  if (SSL_CTX_check_private_key(context) == 0) {
    std::cerr << "*** Assertion Failed - Generated PrivateKey Doesn't Work." << std::endl;
    throw SSLConnectionError();
  }

  std::list<Certificate*>::iterator i   = chain->begin();
  std::list<Certificate*>::iterator end = chain->end();

  for (;i != end; i++) {
    SSL_CTX_add_extra_chain_cert(context, (*i)->getCert());
  }

  // if (chain != NULL)
  //   SSL_CTX_add_extra_chain_cert(context, chain->getCert());

  SSL_CTX_set_mode(context, SSL_MODE_AUTO_RETRY);
}

ip::tcp::endpoint SSLBridge::getRemoteEndpoint() {
  return serverSocket->remote_endpoint();
}

void SSLBridge::setServerName() {
  X509 *serverCertificate    = getServerCertificate();
  X509_NAME *serverNameField = X509_get_subject_name(serverCertificate);
  char *serverNameStr        = X509_NAME_oneline(serverNameField, NULL, 0);

  this->serverName = std::string((const char*)serverNameStr);
  int commonNameIndex;

  if ((commonNameIndex = this->serverName.find("CN=")) != std::string::npos)
    this->serverName = this->serverName.substr(commonNameIndex+3);
  
  free(serverNameStr);
}

DH* SSLBridge::setupDH() {
  DH *DH_parameters;
  FILE *parameter_file;
  parameter_file = fopen("DH_params.pem", "r");
  if (parameter_file) {
    DH_parameters = PEM_read_DHparams(parameter_file, NULL, NULL, NULL);
    fclose(parameter_file);
  } else std::cout << "unable to open DH parameter file: DH_params.pem" << std::endl;

  if (!DH_parameters) std::cout << "Unable to read DH parameters" << std::endl;
  int codes;
  if (DH_check(DH_parameters, &codes) != 1) std::cout << "Error while checking DH parameters: " + getErrorString(NULL, 0) << std::endl;
  if (DH_generate_key(DH_parameters) != 1) std::cout << "Error generating keys: " + getErrorString(NULL, 0) << std::endl;
  return DH_parameters;
}

void SSLBridge::handshakeWithClient(CertificateManager &manager, bool wildcardOK) {
  Certificate *leaf;
  std::list<Certificate*> *chain;

  ip::tcp::endpoint endpoint = getRemoteEndpoint();
  certificateManager.getCertificateForTarget(endpoint, wildcardOK, getServerCertificate(), &leaf, &chain);
  
  setServerName();
  
  SSL_CTX *clientContext = SSL_CTX_new(SSLv23_server_method());

  DH *DH_parameters = setupDH();
  if (SSL_CTX_set_tmp_dh(clientContext, DH_parameters));

  buildClientContext(clientContext, leaf, chain);

  SSL *clientSession = SSL_new(clientContext);
  SSL_set_fd(clientSession, clientSocket->native_handle());

  int ssl_accept_ret;
  if ( (ssl_accept_ret = SSL_accept(clientSession)) != 1) {
    std::string errString = getErrorString(clientSession, ssl_accept_ret);
    Logger::logError("SSL Accept Failed: " + errString);
    throw SSLConnectionError();
  }
  this->clientSession = clientSession;
}

std::string SSLBridge::getErrorString(SSL *session, int errNo) {
  std::string errString;
  std::string sysErr = strerror(errno);
  errString += "SYSTEM: " + sysErr;

  if (session) {
    std::ostringstream conversion;
    conversion << errNo;
    std::string sslError(ERR_error_string(SSL_get_error(session, errNo), NULL));
    errString += "; SSL (" + conversion.str() + "): " + sslError;
  }

  int err;
  while ((err = ERR_get_error()) != 0) {
    std::string prim(ERR_error_string(err, NULL));
    errString += "; ERR: " + prim;
  }

  return errString;
}

void SSLBridge::handshakeWithServer() {
  int bogus;

  ip::address_v4 serverAddress = serverSocket->remote_endpoint().address().to_v4();
  SSL_CTX *serverCtx           = SSL_CTX_new(SSLv23_client_method());;
  SSL *serverSession           = SSL_new(serverCtx);;
  SSL_SESSION *sessionId       = cache->getSessionId(serverSession, 
						     serverAddress.to_bytes().data(), 
						     serverAddress.to_bytes().size(),
						     &bogus);

  if (sessionId != NULL) {
    SSL_set_session(serverSession, sessionId);
    SSL_SESSION_free(sessionId);
  }



  SSL_set_connect_state(serverSession);
  SSL_set_fd(serverSession, serverSocket->native_handle());
  SSL_set_options(serverSession, SSL_OP_ALL);
  
  int ssl_connect_ret;
  if ( (ssl_connect_ret = SSL_connect(serverSession)) != 1) {
    std::string errString = getErrorString(serverSession, ssl_connect_ret);
    Logger::logError("Error on SSL Connect: " + errString);
    throw SSLConnectionError();
  }

  cache->setNewSessionId(serverSession, SSL_get1_session(serverSession), 
			 serverAddress.to_bytes().data(), 
			 serverAddress.to_bytes().size());

  this->serverSession = serverSession;
}

void SSLBridge::shuttleData() {
  struct pollfd fds[2] = {{clientSocket->native_handle(), POLLIN | POLLPRI | POLLHUP | POLLERR, 0},
			  {serverSocket->native_handle(), POLLIN | POLLPRI | POLLHUP | POLLERR, 0}};

  for (;;) {
    if (poll(fds, 2, -1) < 0)        return;
    if (isAvailable(fds[0].revents)) if (!readFromClient()) return;
    if (isAvailable(fds[1].revents)) if (!readFromServer()) return;
    if (isClosed(fds[0].revents))    return;
    if (isClosed(fds[1].revents))    return;
  }

}

int SSLBridge::isAvailable(int revents) {
  return revents & POLLIN || revents & POLLPRI;
}

int SSLBridge::isClosed(int revents) {
  return revents & POLLERR || revents & POLLHUP;
}

bool SSLBridge::readFromClient() {
  char buf[16384];
  int bytesRead;
  int bytesWritten;
  
  do {
    std::cout << "Reading from client" << std::endl;
    if ((bytesRead = SSL_read(clientSession, buf, sizeof(buf))) <= 0) {
      int sslError = SSL_get_error(clientSession, bytesRead);
      return  sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE;
    }

    if ((bytesWritten = SSL_write(serverSession, buf, bytesRead)) <= 0) {
      int sslError = SSL_get_error(serverSession, bytesWritten);
      return  sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE;
    }

    Logger::logFromClient(serverName, buf, bytesRead);

    ip::tcp::endpoint endpoint = getRemoteEndpoint();
    certificateManager.lockCandidateCertificate(endpoint);

  } while (SSL_pending(clientSession));

  return true;
}

bool SSLBridge::readFromServer() {
  char buf[16384];
  int bytesRead;
  int bytesWritten;

  do {
    std::cout << "Reading from server" << std::endl;
    if ((bytesRead = SSL_read(serverSession, buf, sizeof(buf))) <= 0) {
      int sslError = SSL_get_error(serverSession, bytesRead);
      return  sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE;
    }

    if ((bytesWritten = SSL_write(clientSession, buf, bytesRead)) <= 0) {
      int sslError = SSL_get_error(clientSession, bytesWritten);
      return  sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE;
    }

    Logger::logFromServer(serverName, buf, bytesRead);

    ip::tcp::endpoint endpoint = getRemoteEndpoint();
    certificateManager.lockCandidateCertificate(endpoint);

  } while (SSL_pending(serverSession));

  return true;
}

void SSLBridge::close() {
  if (closed)        return;
  else               closed = true;

  if (serverSession) SSL_free(serverSession);
  if (clientSession) SSL_free(clientSession);
  
  clientSocket->close();
  serverSocket->close();
}

