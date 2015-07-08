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

#include "SequentialCertificateManager.hpp"


SequentialCertificateManager::SequentialCertificateManager(std::string &directory, std::string &chain) {
	boost::filesystem::path certDir(directory);
	boost::filesystem::path chainPath(chain);

	if (!boost::filesystem::exists(certDir)) throw NoSuchDirectoryException();
	
	boost::filesystem::directory_iterator ender;

	for (boost::filesystem::directory_iterator iter(certDir); iter!=ender; iter++) {
		if (!boost::filesystem::is_directory(iter->status())) {
			if (!isCAcert(iter)) readTargetedCertificate(iter);
			else {
				readCAcertificate(iter);
			}
		}
	}

	if (!chain.empty()) {
		Certificate *chain = readCredentialsFromFile(chainPath, false, true);
		chainList.push_back(chain);
	}

	if (certs.empty() && authorities.empty()) throw NoSuchDirectoryException();

	this->leafKeys = buildKeysForClient();
}


bool SequentialCertificateManager::isCAcert(boost::filesystem::directory_iterator &iter) {
	return iter->path().filename().native().find("CA") != std::string::npos;
}


void SequentialCertificateManager::readCAcertificate(boost::filesystem::directory_iterator &iter) {
	Certificate *cert = readCredentialsFromFile(iter->path(), false);
	this->authorities.push_back(cert);
}


void SequentialCertificateManager::readTargetedCertificate(boost::filesystem::directory_iterator &iter) {
	Certificate *target = readCredentialsFromFile(iter->path(), true, true);

	if (target->isWildcard()) certs.push_back(target);
	else certs.push_front(target);
}


bool SequentialCertificateManager::isOCSPAddress(boost::asio::ip::tcp::endpoint &endpoint) {
	return false;
}


bool SequentialCertificateManager::isValidTarget(boost::asio::ip::tcp::endpoint &endpoint, bool wildcardOK) {
	return false;
}


void SequentialCertificateManager::getCertificateForTarget(boost::asio::ip::tcp::endpoint &endpoint,
												bool wildcardOK,
												X509 *serverCert,
												Certificate **cert,
												std::list<Certificate*> **chain) {

}


unsigned int SequentialCertificateManager::generateRandomSerial() {
	return (unsigned int) 0;
}


EVP_PKEY* SequentialCertificateManager::buildKeysForClient() {
	RSA *rsaKeyPair = RSA_generate_key(1024, RSA_F4, NULL, NULL);

	RSA_blinding_on(rsaKeyPair, NULL);

	std::string filename;
	std::cout << "Save private key to file (rsa.key): ";
	std::getline(std::cin, filename);
	if (filename.length() == 0) filename = "rsa.key";

	BIO *rsaPrivateBio = BIO_new_file(filename.data(), "w");
	PEM_write_bio_RSAPrivateKey(rsaPrivateBio, rsaKeyPair, NULL, NULL, 0, NULL, NULL);
	BIO_free(rsaPrivateBio);
	std::cout << "Dumped private key to file: " << filename << std::endl;

	EVP_PKEY *rsaKeyPairSpec = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(rsaKeyPairSpec, rsaKeyPair);

	return rsaKeyPairSpec;
}






