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

SequentialCertificateManager::SequentialCertificateManager(std::string &directory, std::string &chain, std::string &keyLocation) {
	boost::filesystem::path certDir(directory);
	boost::filesystem::path chainPath(chain);
	boost::filesystem::path keyPath(keyLocation);

	if (!boost::filesystem::exists(certDir)) throw std::runtime_error(std::string("No such directory: " + directory));
	
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

	if (!keyLocation.empty() && !boost::filesystem::exists(keyPath)) throw std::runtime_error(std::string("No such file: " + keyLocation));
	if (!keyLocation.empty()) 	this->leafKeys = readKeyFile(system_complete(keyPath).string().c_str());
	else 						this->leafKeys = buildKeysForClient();
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
	boost::asio::ip::address address = endpoint.address();

	std::list<Certificate*>::iterator iter = certs.begin();
	std::list<Certificate*>::iterator last = certs.end();
	for (; iter != last; iter++) if ( (*iter)->isOCSPAddress(address) ) return true;

	iter = authorities.begin();
	last = authorities.end();
	for (; iter != last; iter++) if ( (*iter)->isOCSPAddress(address) ) return true;

	return false;
}


bool SequentialCertificateManager::isValidTarget(boost::asio::ip::tcp::endpoint &endpoint, bool wildcardOK) {
	boost::asio::ip::address address = endpoint.address();

	std::list<Certificate*>::iterator iter = certs.begin();
	std::list<Certificate*>::iterator last = certs.end();
	for(; iter != last; iter++ ) if ( (*iter)->isValidTarget(address, wildcardOK) ) return true;

	if (!authorities.empty()) return true;
	return false;
}


void SequentialCertificateManager::getCertificateForTarget(boost::asio::ip::tcp::endpoint &endpoint,
												bool wildcardOK,
												X509 *serverCert,
												Certificate **cert,
												std::list<Certificate*> **chain) {
	std::cout << "Getting cert for endpoint: " << endpoint.address().to_string() << std::endl;
	std::map<boost::asio::ip::tcp::endpoint, bool>::iterator lock = endpointCertLock.find(endpoint);
	std::cout << " Lock check" << std::endl;

	if (lock == endpointCertLock.end()) {
		std::cout << " No entry for endpoint" << std::endl;
		endpointCertLock[endpoint] = false;
		certMap[endpoint] = certs.begin();
		authMap[endpoint] = authorities.begin();
	} else if (lock->second) {
		std::cout << " Entry found, returning previous cert" << std::endl;
		*chain = &(this->chainList);
		*cert = candidate;
		return;
	}

	std::cout << " Fetching cert for unlocked endpoint" << std::endl;
	std::map<boost::asio::ip::tcp::endpoint,
					std::list<Certificate*>::iterator>::iterator mapIter;

	std::cout << " Checking targeted certs" << std::endl;
	mapIter = certMap.find(endpoint);
	if ((mapIter->second) != certs.end()) {
		std::cout << " Found potential targeted cert, verifying" << std::endl;
		fetchNextTargetedCert(endpoint, wildcardOK, serverCert, cert, chain, mapIter->second);
		std::cout << " Exited target cert check" << std::endl;
		if (*cert) return;
	}

	std::cout << " Generating new from CA" << std::endl;
	mapIter = authMap.find(endpoint);
	if ((mapIter->second) != authorities.end()) {
		fetchNextGeneratedCert(endpoint, wildcardOK, serverCert, cert, chain, mapIter->second);
		if (*cert) return;
	}

	std::cout << " No cert!" << std::endl;

}


void SequentialCertificateManager::fetchNextTargetedCert(boost::asio::ip::tcp::endpoint &endpoint,
												bool wildcardOK,
												X509 *serverCert,
												Certificate **cert,
												std::list<Certificate*> **chain,
												std::list<Certificate*>::iterator &iter) {
	boost::asio::ip::address address = endpoint.address();
	*chain = &(this->chainList);

	std::list<Certificate*>::iterator i = iter;
	std::list<Certificate*>::iterator end = certs.end();

	std::cout << " Checking targeted certs from list" << std::endl;
	for ( ; i != end; i++) {
		if ((*i)->isValidTarget(address, wildcardOK)) {
			certMap[endpoint] = i;
			*cert = (*i);
			candidate = (*i);
			return;
		}
	}

	std::cout << " No targeted cert found valid for target" << std::endl;

	certMap[endpoint] = certs.end();
	candidate = NULL;
	*cert = NULL;
	return;
}


void SequentialCertificateManager::fetchNextGeneratedCert(boost::asio::ip::tcp::endpoint &endpoint,
												bool wildcardOK,
												X509 *serverCert,
												Certificate **cert,
												std::list<Certificate*> **chain,
												std::list<Certificate*>::iterator &iter) {
	if (iter == authorities.end()) {
		*cert = NULL;
		candidate = NULL;
		return;
	}

	X509_NAME *serverName   = X509_get_subject_name(serverCert);
	X509_NAME *issuerName   = X509_get_subject_name((*iter)->getCert());
	X509 *request           = X509_new();

	X509_set_version(request, 3);
	X509_set_subject_name(request, serverName);
	X509_set_issuer_name(request, issuerName);

	ASN1_INTEGER_set(X509_get_serialNumber(request), generateRandomSerial());
	X509_gmtime_adj(X509_get_notBefore(request), -365);
	X509_gmtime_adj(X509_get_notAfter(request), (long)60*60*24*365);
	X509_set_pubkey(request, this->leafKeys);

	X509_sign(request, (*iter)->getKey(), EVP_sha1());

	Certificate *leaf = new Certificate();
	leaf->setCert(request);
	leaf->setKey(this->leafKeys);

	*cert  = leaf;
	*chain = &(this->chainList);
	candidate = leaf;
	authMap[endpoint] = (++iter);
}


void SequentialCertificateManager::lockCandidateCertificate(boost::asio::ip::tcp::endpoint &endpoint){
	std::map<boost::asio::ip::tcp::endpoint, bool>::iterator lock = endpointCertLock.find(endpoint);
	if (lock != endpointCertLock.end()) {
		endpointCertLock[endpoint] = true;
	} else {
		throw std::runtime_error(std::string("Can't lock an endpoint cert that is not stored!"));
	}
}


unsigned int SequentialCertificateManager::generateRandomSerial() {
	unsigned int serial;
	RAND_bytes((unsigned char*)&serial, sizeof(serial));

	return serial;
}


EVP_PKEY* SequentialCertificateManager::readKeyFile(const char* keyPath) {
	BIO *rsaPrivateBio = BIO_new_file(keyPath, "r");
	RSA *privateKey = PEM_read_bio_RSAPrivateKey(rsaPrivateBio, NULL, NULL, NULL);

	BIO_free(rsaPrivateBio);

	EVP_PKEY *rsaKeyPairSpec = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(rsaKeyPairSpec, privateKey);
	return rsaKeyPairSpec;
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






