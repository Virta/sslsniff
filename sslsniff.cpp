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

#include <openssl/ssl.h>

#include <string>
#include <sys/types.h>
#include <unistd.h>

#include <boost/asio.hpp>

#include "SSLConnectionManager.hpp"
#include "UpdateManager.hpp"
#include "http/HttpConnectionManager.hpp"
#include "certificate/TargetedCertificateManager.hpp"
#include "certificate/AuthorityCertificateManager.hpp"
#include "certificate/SequentialCertificateManager.hpp"
#include "sslsniff.hpp"
#include "Logger.hpp"
#include "FingerprintManager.hpp"

static void printUsage(char *command) {
  fprintf(stderr, "Usage: %s [options]\n\n"
	  "Modes:\n"
	  "-a\t Authority mode.  Specify a certificate that will act as a CA.\n"
	  "-t\t Targeted mode.  Specify a directory full of certificates to target.\n"
    "-q\t Sequential mode. Speficy a directory containing certificates that will be used for certificate rolling.\n"
    "-l\t Get help on sequential mode certificate filename formatting and usage.\n\n"
	  "Required Options:\n" 
	  "-c <file|directory>\tFile containing CA cert/key (authority mode) or \n\t\t\tdirectory containing a collection of certs/keys\n\t\t\t(targeted and sequential mode)\n"
	  "-s <port>\t\tPort to listen on for SSL interception.\n"
	  "-w <file>\t\tFile to log to\n"
	  "\nOptional Options:\n"
	  "-u <updateLocation>\tLoction of any Firefox XML update files.\n"
	  "-m <certificateChain>\tLocation of any intermediary certificates.\n"
	  "-h <port>\t\tPort to listen on for HTTP interception (required for\n\t\t\tfingerprinting).\n"
	  "-f <ff,ie,safari,opera,ios>\tOnly intercept requests from the specified browser(s).\n"
	  "-d\t\t\tDeny OCSP requests for our certificates.\n"
	  "-p\t\t\tOnly log HTTP POSTs\n"
	  "-e <url>\t\tIntercept Mozilla Addon Updates\n"
	  "-j <sha256>\t\tThe sha256sum value of the addon to inject\n"
    "-k <key file>\t\tSpecify an RSA key to use, instead of generating one on startup.\n\n", command);
  exit(1);
}

static void printHelp() {
  fprintf(stderr, "\nUsing the sequential certificate rolling\n\n"
    "File Naming:\n"
      "\tAll certificate authority certificates that you wish to use for certificate signing and\n"
      "\tdynamic certificate generation must contain 'CA' somewhere in the filename of the cert,\n"
      "\tideally in the begginning.\n\n"

      "\tAll other certificates that are used as targeted certificates can have any name that\n"
      "\tdoes not contain 'CA'.\n\n"
    );
}

static bool isOptionsValid(Options &options) {
       if (options.getHelp)             return true;
  else if (options.certificateLocation.empty() ||  options.sslListenPort == -1 
        || options.logLocation.empty()) return false;  // No cert, listen port, or log.
  else if (options.httpListenPort == -1   && !options.fingerprintList.empty())   return false;  // Fingerprinting but no http port.
  else if (options.httpListenPort != -1   &&  options.fingerprintList.empty())   return false;  // Http port but no fingerprinting.
  else if (!options.addonLocation.empty() &&  options.addonHash.empty())         return false;
  else                                  return true;
}

static int parseArguments(int argc, char* argv[], Options &options) {
  int c;
  extern char *optarg;

  options.denyOCSP       = false;
  options.postOnly       = false;
  options.targetedMode   = false;
  options.sequentialMode = false;
  options.getHelp        = false;
  options.sslListenPort  = -1;
  options.httpListenPort = -1;

  
  while ((c = getopt(argc, argv, "atqls:h:c:w:f:m:u:pdj:e:k:")) != -1) {
    switch (c) {
    case 'w': options.logLocation         = std::string(optarg); break;
    case 'a': options.targetedMode        = false;               break;
    case 't': options.targetedMode        = true;                break;
    case 'q': options.sequentialMode      = true;                break;
    case 'l': options.getHelp             = true;                break;
    case 'c': options.certificateLocation = std::string(optarg); break;
    case 's': options.sslListenPort       = atoi(optarg);        break;
    case 'h': options.httpListenPort      = atoi(optarg);        break;
    case 'f': options.fingerprintList     = std::string(optarg); break;
    case 'm': options.chainLocation       = std::string(optarg); break;
    case 'p': options.postOnly            = true;                break;
    case 'u': options.updateLocation      = std::string(optarg); break;
    case 'd': options.denyOCSP            = true;                break;
    case 'e': options.addonLocation       = std::string(optarg); break;
    case 'j': options.addonHash           = std::string(optarg); break;
    case 'k': options.keyLocation         = std::string(optarg); break;
    default:
      return -1;
    }
  }

  if (isOptionsValid(options)) return 1;
  else                         return -1;				 
}

static void initializeOpenSSL() {
  SSL_library_init();
  SSL_load_error_strings();
}

static void initializeLogging(Options &options) {
  Logger::initialize(options.logLocation, options.postOnly);
}

static CertificateManager* initializeCertificateManager(Options &options) {
  if (options.targetedMode) return new TargetedCertificateManager(options.certificateLocation,
								  options.chainLocation);
  else if (options.sequentialMode) return new SequentialCertificateManager(options.certificateLocation,
                  options.chainLocation, options.keyLocation);
  else                     return new AuthorityCertificateManager(options.certificateLocation,
								  options.chainLocation, options.keyLocation);
}

int main(int argc, char* argv[]) {
  Options options;
  boost::asio::io_service io_service;

  if (parseArguments(argc, argv, options) < 0) {
    printUsage(argv[0]);
  }

  if (options.getHelp) {
    printHelp();
    exit(1);
  }

  initializeLogging(options);
  initializeOpenSSL();

  CertificateManager *certs = initializeCertificateManager(options);  

  FingerprintManager::getInstance()->setValidUserAgents(options.fingerprintList);
  UpdateManager::getInstance()->initialize(options.updateLocation, options.addonLocation, options.addonHash);

  HttpConnectionManager httpConnectionManager(io_service, options.httpListenPort, *certs,
					      options.denyOCSP); 
  SSLConnectionManager sslConnectionManager(io_service, *certs, options.sslListenPort);

  std::cout << "sslsniff " << VERSION << " by Moxie Marlinspike running..." << std::endl;

  io_service.run();

  return 1;
}
