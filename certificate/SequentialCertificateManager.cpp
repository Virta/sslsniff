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


 SequentialCertificateManager::SequentialCertificateManager(std::string &file, std::string &chain) {

 }


 bool SequentialCertificateManager::isOCSPAddress(boost::asio::ip::tcp::endpoint &endpoint) {

 }


 bool SequentialCertificateManager::isValidTarget(boost::asio::ip::tcp::endpoint &endpoint, bool wildcardOK) {

 }


 void SequentialCertificateManager::getCertificateForTarget(boost::asio::ip::tcp::endpoint &endpoint,
													bool wildcardOK.
													X509 *serverCert,
													Certificate **cert,
													std::list<Certificate*> **chain) {

}


 unsigned int SequentialCertificateManager::generateRandomSerial() {

}


EVP_PKEY* SequentialCertificateManager::buildKeysForClient() {
	
}