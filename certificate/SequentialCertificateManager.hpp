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

#ifndef __SEQUENTIAL_CERTIFICATE_MANAGER_H__
#define __SEQUENTIAL_CERTIFICATE_MANAGER_H__

#include <string>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <boost/asio.hpp>

#include "Certificate.hpp"
#include "CertificateManager.hpp"

class SequentialCertificateManager : public CertificateManager {

private:
  std::list<Certificate*> authorities;
  std::list<Certificate*> certs;
  std::list<Certificate*> chainList;

	EVP_PKEY *leafKeys;
	EVP_PKEY* buildKeysForClient();
	unsigned int generateRandomSerial();
  void readTargetedCertificate(boost::filesystem::directory_iterator &iter);
  void readCAcertificate(boost::filesystem::directory_iterator &iter);
  bool isCAcert(boost::filesystem::directory_iterator &iter);

public:
  SequentialCertificateManager(std::string &file, std::string &chain);

  virtual bool isOCSPAddress(boost::asio::ip::tcp::endpoint &endpoint);
  virtual void getCertificateForTarget(boost::asio::ip::tcp::endpoint &endpoint,
             bool wildcardOK,
             X509 *serverCertificate,
             Certificate **cert, std::list<Certificate*> **chain);

  virtual bool isValidTarget(boost::asio::ip::tcp::endpoint &endpoint, bool wildcardOK);
};


class NoSuchDirectoryException : public std::exception {
public:
  virtual const char* what() const throw() {
    return "No such directory...";
  }
};


#endif
