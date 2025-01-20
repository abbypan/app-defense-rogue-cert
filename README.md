# tls_cert_att

# install

    pacman -S certificate-ripper-bin python-jwcrypto jdk17-openjdk maven openssl
    
#  keystore

test CA add to system cert

    sudo keytool -import -alias CTCARootCA -file server_cert/root.cert.pem -keystore /etc/ca-certificates/extracted/java-cacerts.jks -storepass changeit
    sudo keytool -import -alias CTCAIntCA -file server_cert/int.cert.pem -keystore /etc/ca-certificates/extracted/java-cacerts.jks -storepass changeit
    
    sudo keytool -import -alias SomeOtherRootCA -file server_cert/eroot.cert.pem -keystore /etc/ca-certificates/extracted/java-cacerts.jks -storepass changeit
    sudo keytool -import -alias SomeOtherIntCA -file server_cert/eint.cert.pem -keystore /etc/ca-certificates/extracted/java-cacerts.jks -storepass changeit

# prepare attester

    ./gen_attester_cert.sh

# prepare tls certs

    perl get_certs.pl
    find . -name 'data/*.txt' -exec grep -H Issuer {} \;

# prepare crtatt

    ./gen_crtatt.py
    ./verify_crtatt.py

# ctca

    cd ctca
    mvn package

    ./ctca_benchmark.pl
