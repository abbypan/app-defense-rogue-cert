#!/usr/bin/perl
use strict;
use warnings;

my ($s_ee, $ee_dom) = @ARGV;
$s_ee ||= "ee";
$ee_dom ||= "aabbcc.example.com";

my $s_root = 'root';
my $s_int = 'int';

#generate_root_ca($s_root, 33333, 'srootpkcs12');
#generate_int_ca($s_int, 22222, 'sintpkcs12', "$s_root.priv.pem", "$s_root.cert.pem");
generate_ee($s_ee, 11111, 'seepkcs12', "$s_int.priv.pem", "$s_int.cert.pem", $ee_dom);

system(qq[cat $s_ee.cert.pem $s_int.cert.pem $s_root.cert.pem > $s_ee.cert_chain.ee.pem]);
system(qq[cat $s_int.cert.pem $s_root.cert.pem > $s_ee.cert_chain.pem]);
system(qq[cat $s_int.cert.pem > $s_ee.cert_chain.int.pem]);
system(qq[openssl pkcs12 -export -in $s_ee.cert_chain.ee.pem -inkey $s_ee.priv.pem -passout pass:seepkcs12 -out $s_ee.cert_chain.p12]);


my $e_root = 'eroot';
my $e_int = 'eint';
my $e_ee = 'evil';
#generate_root_ca($e_root, 33333, 'srootpkcs12');
#generate_int_ca($e_int, 22222, 'sintpkcs12', "$e_root.priv.pem", "$e_root.cert.pem");
generate_ee($e_ee, 11111, 'seepkcs12', "$e_int.priv.pem", "$e_int.cert.pem", $ee_dom);

system(qq[cat $e_ee.cert.pem $e_int.cert.pem $e_root.cert.pem > $e_ee.cert_chain.ee.pem]);
system(qq[cat $e_int.cert.pem $e_root.cert.pem > $e_ee.cert_chain.pem]);
system(qq[cat $e_int.cert.pem > $e_ee.cert_chain.int.pem]);
system(qq[openssl pkcs12 -export -in $e_ee.cert_chain.ee.pem -inkey $e_ee.priv.pem -passout pass:seepkcs12 -out $e_ee.cert_chain.p12]);


sub generate_root_ca {
    my ($prefix, $day, $pwd) = @_;

    system(qq[openssl ecparam -genkey -name prime256v1 -noout -out $prefix.priv.pem]);
    system(qq[openssl pkcs8 -topk8 -inform pem -in $prefix.priv.pem -outform pem -nocrypt -out $prefix.priv.pkcs8.pem]);
    system(qq[openssl ec -in $prefix.priv.pem -pubout -out $prefix.pub.pem]);

    system(qq[openssl req -new -key $prefix.priv.pem -out $prefix.csr -sha256 -config $prefix.cnf]);
    system(qq[openssl req -verify -in $prefix.csr -text -noout]);
    system(qq[openssl x509 -req -in $prefix.csr -out $prefix.cert.pem -signkey $prefix.priv.pem -days $day -sha256 -extfile $prefix.ext.cnf]);
    system(qq[openssl x509 -text -in $prefix.cert.pem]);

    system(qq[openssl pkcs12 -export -in $prefix.cert.pem -inkey $prefix.priv.pem -passout pass:$pwd -out $prefix.p12]);
    #system(qq[keytool -importkeystore -srckeystore $prefix.p12 -srcstoretype pkcs12  -srcstorepass $pwd -destkeystore $prefix.jks -deststoretype jks -deststorepass $pwd]);
    
    return $prefix;
}

sub generate_int_ca {
    my ($prefix, $day, $pwd, $signer_key, $signer_cert) = @_;

    system(qq[openssl ecparam -genkey -name prime256v1 -noout -out $prefix.priv.pem]);
    system(qq[openssl pkcs8 -topk8 -inform pem -in $prefix.priv.pem -outform pem -nocrypt -out $prefix.priv.pkcs8.pem]);
    system(qq[openssl ec -in $prefix.priv.pem -pubout -out $prefix.pub.pem]);

    system(qq[openssl req -new -key $prefix.priv.pem -out $prefix.csr -sha256 -config $prefix.cnf]);
    system(qq[openssl req -verify -in $prefix.csr -text -noout]);
    system(qq[openssl x509 -req -in $prefix.csr -out $prefix.cert.pem -CA $signer_cert -CAkey $signer_key -CAcreateserial  -days $day -sha256 -extfile $prefix.ext.cnf]);
    system(qq[openssl x509 -text -in $prefix.cert.pem]);

    system(qq[openssl pkcs12 -export -in $prefix.cert.pem -inkey $prefix.priv.pem -passout pass:$pwd -out $prefix.p12]);
    #system(qq[keytool -importkeystore -srckeystore $prefix.p12 -srcstoretype pkcs12  -srcstorepass $pwd -destkeystore $prefix.jks -deststoretype jks -deststorepass $pwd]);

    return $prefix;
}

sub generate_ee {
    my ($prefix, $day, $pwd, $signer_key, $signer_cert, $ee_dom) = @_;

    system(qq[openssl ecparam -genkey -name prime256v1 -noout -out $prefix.priv.pem]);
    system(qq[openssl pkcs8 -topk8 -inform pem -in $prefix.priv.pem -outform pem -nocrypt -out $prefix.priv.pkcs8.pem]);
    system(qq[openssl ec -in $prefix.priv.pem -pubout -out $prefix.pub.pem]);

    system(qq[openssl req -new -key $prefix.priv.pem -out $prefix.csr -sha256 -config $prefix.cnf -subj "/CN=$ee_dom"]);
    system(qq[openssl req -verify -in $prefix.csr -text -noout]);
    system(qq[openssl x509 -req -in $prefix.csr -out $prefix.cert.pem -CA $signer_cert -CAkey $signer_key -CAcreateserial  -days $day -sha256 -extfile $prefix.ext.cnf]);
    system(qq[openssl x509 -text -in $prefix.cert.pem]);

    system(qq[openssl pkcs12 -export -in $prefix.cert.pem -inkey $prefix.priv.pem -passout pass:$pwd -out $prefix.p12]);
    #system(qq[keytool -importkeystore -srckeystore $prefix.p12 -srcstoretype pkcs12  -srcstorepass $pwd -destkeystore $prefix.jks -deststoretype jks -deststorepass $pwd]);

    return $prefix;
}
