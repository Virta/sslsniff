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

#include "AuthorityCertificateManager.hpp"


AuthorityCertificateManager::AuthorityCertificateManager(std::string &file, std::string &chain, std::string &keyLocation) {
  path certPath(file);
  path chainPath(chain);
  path keyPath(keyLocation);

  this->authority = readCredentialsFromFile(certPath, false);
  chainList.push_back(this->authority);

  if (!chain.empty()) {
    Certificate *chain = readCredentialsFromFile(chainPath, false);
    chainList.push_back(chain);
  }

  if (!keyLocation.empty() && !boost::filesystem::exists(keyPath)) throw std::runtime_error(std::string("No such file: " + keyLocation));
  if (!keyLocation.empty()) this->leafPair = readKeyFile(system_complete(keyPath).string().c_str());
  else                      this->leafPair = buildKeysForClient();
}

bool AuthorityCertificateManager::isOCSPAddress(boost::asio::ip::tcp::endpoint &endpoint) {
  boost::asio::ip::address address      = endpoint.address();
  return this->authority->isOCSPAddress(address);
}

bool AuthorityCertificateManager::isValidTarget(boost::asio::ip::tcp::endpoint &end, 
						bool wildcardOK) 
{
  return true;
}

void AuthorityCertificateManager::getCertificateForTarget(boost::asio::ip::tcp::endpoint &endpoint,
							  bool wildcardOK,
							  X509 *serverCertificate,
							  Certificate **cert,
							  std::list<Certificate*> **chainList)
{
  X509_NAME *serverName   = X509_get_subject_name(serverCertificate);
  X509_NAME *issuerName   = X509_get_subject_name(authority->getCert());
  X509 *request           = X509_new();

  X509_set_version(request, 3);
  X509_set_subject_name(request, serverName);
  X509_set_issuer_name(request, issuerName);

  ASN1_INTEGER_set(X509_get_serialNumber(request), generateRandomSerial());
  X509_gmtime_adj(X509_get_notBefore(request), -365);
  X509_gmtime_adj(X509_get_notAfter(request), (long)60*60*24*365);
  X509_set_pubkey(request, this->leafPair);

  X509_sign(request, authority->getKey(), EVP_sha1());

  Certificate *leaf = new Certificate();
  leaf->setCert(request);
  leaf->setKey(this->leafPair);

  *cert  = leaf;
  *chainList = &(this->chainList);
  // *chain = this->authority;
}

unsigned int AuthorityCertificateManager::generateRandomSerial() {
  unsigned int serial;
  RAND_bytes((unsigned char*)&serial, sizeof(serial));

  return serial;
}

EVP_PKEY* AuthorityCertificateManager::buildKeysForClient() {
  RSA *rsaKeyPair = RSA_generate_key(1024, RSA_F4, NULL, NULL);

  RSA_blinding_on(rsaKeyPair, NULL);

  std::string fileName;
  std::cout << "Save private key to file (rsa.key): ";
  std::getline(std::cin, fileName);
  if (fileName.length() == 0) fileName = "rsa.key";

  BIO* rsaPrivateBio = BIO_new_file(fileName.data(), "w");
  PEM_write_bio_RSAPrivateKey(rsaPrivateBio, rsaKeyPair, NULL, NULL, 0, NULL, NULL);
  BIO_free(rsaPrivateBio);
  std::cout << "Dumped private key to file: " << fileName << std::endl;

  EVP_PKEY *rsaKeyPairSpec = EVP_PKEY_new();
  
  EVP_PKEY_assign_RSA(rsaKeyPairSpec, rsaKeyPair);

  return rsaKeyPairSpec;
}

EVP_PKEY* AuthorityCertificateManager::readKeyFile(const char* keyPath) {
  BIO *rsaPrivateBio = BIO_new_file(keyPath, "r");
  RSA *privateKey = PEM_read_bio_RSAPrivateKey(rsaPrivateBio, NULL, NULL, NULL);

  BIO_free(rsaPrivateBio);

  EVP_PKEY *rsaKeyPairSpec = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(rsaKeyPairSpec, privateKey);
  return rsaKeyPairSpec;
}
