package org.apache.nifi.processors.email;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.mail.MessagingException;
import org.apache.nifi.reporting.InitializationException;
import org.apache.nifi.security.util.KeyStoreUtils;
import org.apache.nifi.security.util.TlsConfiguration;
import org.apache.nifi.security.util.TlsException;
import org.apache.nifi.ssl.SSLContextService;
import org.apache.nifi.ssl.StandardRestrictedSSLContextService;
import org.apache.nifi.ssl.StandardSSLContextService;
import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.containsString;

public class TestValidateEmailSignature {
        private static final String SSL_SERVICE_IDENTIFIER = "ssl-context";

        // Setup the fields to be used...
        String from = "NiFi <nifi@apache.org>";
        String to = "bob@nifi.apache.org";
        String subject = "Just a test email";
        String message = "Test test test chocolate";
        String hostName = "bermudatriangle";

        GenerateAttachment emailGenerator =
                        new GenerateAttachment(from, to, subject, message, hostName);

        @Test
        public void testSignedContent()
                        throws OperatorCreationException, GeneralSecurityException, IOException,
                        MessagingException, InitializationException, SMIMEException {
                final TestRunner runner = newRunner();

                final SSLContextService sslContextService = configureSslContextService(runner,
                                TlsConfiguration.getHighestCurrentSupportedTlsProtocolVersion());

                SMIMESignedGenerator gen = createSigner(sslContextService);
                runner.enqueue(emailGenerator.SimpleSignedEmail(gen));
                runner.run();

                runner.assertTransferCount(ExtractEmailHeaders.REL_SUCCESS, 1);
                runner.assertTransferCount(ExtractEmailHeaders.REL_FAILURE, 0);

                List<MockFlowFile> ffs =
                                runner.getFlowFilesForRelationship(ExtractEmailHeaders.REL_SUCCESS);
                MockFlowFile ff = ffs.get(0);

                // 3 standard attributes, 1 added by the processor
                assertThat(ff.getAttributes().size(), equalTo(4));
                assertThat(ff.getAttributes().get("email.signature.validated"), equalTo("true"));
        }

        @Test
        public void testUnsignedContent()
                        throws OperatorCreationException, GeneralSecurityException, IOException,
                        MessagingException, InitializationException, SMIMEException {
                final TestRunner runner = newRunner();

                configureSslContextService(runner, TlsConfiguration.getHighestCurrentSupportedTlsProtocolVersion());

                runner.enqueue(emailGenerator.SimpleEmail());
                runner.run();

                runner.assertTransferCount(ExtractEmailHeaders.REL_SUCCESS, 1);
                runner.assertTransferCount(ExtractEmailHeaders.REL_FAILURE, 0);

                List<MockFlowFile> ffs =
                                runner.getFlowFilesForRelationship(ExtractEmailHeaders.REL_SUCCESS);
                MockFlowFile ff = ffs.get(0);

                // 3 standard attributes, 1 added by the processor
                assertThat(ff.getAttributes().size(), equalTo(4));
                assertThat(ff.getAttributes().get("email.signature.validated"), equalTo("true"));
        }

        @Test
        public void testUnsignedContentDisallowUnsignedEmail()
                        throws OperatorCreationException, GeneralSecurityException, IOException,
                        MessagingException, InitializationException, SMIMEException {
                final TestRunner runner = newRunner();
                runner.setProperty(ValidateEmailSignature.ALLOW_UNSIGNED_EMAIL, "false");

                configureSslContextService(runner, TlsConfiguration.getHighestCurrentSupportedTlsProtocolVersion());

                runner.enqueue(emailGenerator.SimpleEmail());
                runner.run();

                runner.assertTransferCount(ExtractEmailHeaders.REL_SUCCESS, 0);
                runner.assertTransferCount(ExtractEmailHeaders.REL_FAILURE, 1);

                List<MockFlowFile> ffs =
                                runner.getFlowFilesForRelationship(ExtractEmailHeaders.REL_FAILURE);
                MockFlowFile ff = ffs.get(0);

                // 3 standard attributes, 2 added by the processor
                assertThat(ff.getAttributes().size(), equalTo(5));
                assertThat(ff.getAttributes().get("email.signature.validated"), equalTo("false"));
                assertThat(ff.getAttributes().get("email.signature.validation.error.reasons"), containsString("message is not a signed message"));
        }

        private SMIMESignedGenerator createSigner(final SSLContextService sslContextService)
                        throws TlsException, UnrecoverableKeyException, KeyStoreException,
                        NoSuchAlgorithmException, CertificateEncodingException,
                        OperatorCreationException {
                final TlsConfiguration tlsConfig = sslContextService.createTlsConfiguration();
                final KeyStore keyStore = KeyStoreUtils.loadKeyStore(tlsConfig.getKeystorePath(),
                                tlsConfig.getKeystorePassword().toCharArray(),
                                tlsConfig.getKeystoreType().getType());
                final KeyStore trustStore =
                                KeyStoreUtils.loadKeyStore(tlsConfig.getTruststorePath(),
                                                tlsConfig.getTruststorePassword().toCharArray(),
                                                tlsConfig.getTruststoreType().getType());
                final String keyAlias = "nifi-key";
                final String trustAlias = "nifi-cert";
                final X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
                final X509Certificate signCert =
                                (X509Certificate) trustStore.getCertificate(trustAlias);
                final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias,
                                tlsConfig.getKeystorePassword().toCharArray());

                SMIMESignedGenerator gen = new SMIMESignedGenerator();
                List<Certificate> certList = new ArrayList<>();
                certList.add(cert);
                certList.add(signCert);
                Store certStore = new JcaCertStore(certList);
                gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                                .setProvider("BC").build("SHA256withRSA", privateKey, cert));
                gen.addCertificates(certStore);
                return gen;
        }

        private TestRunner newRunner() {
                final ValidateEmailSignature proc = new ValidateEmailSignature();
                final TestRunner runner = TestRunners.newTestRunner(proc);

                runner.setProperty(ValidateEmailSignature.STRICT_PARSING,
                                ValidateEmailSignature.STRICT_ADDRESSING);
                return runner;
        }

        private SSLContextService configureSslContextService(final TestRunner runner,
                        final String tlsProtocol) throws InitializationException {
                final SSLContextService sslContextService =
                                new StandardRestrictedSSLContextService();
                runner.addControllerService(SSL_SERVICE_IDENTIFIER, sslContextService);
                runner.setProperty(ValidateEmailSignature.SSL_CONTEXT_SERVICE,
                                SSL_SERVICE_IDENTIFIER);
                runner.setProperty(sslContextService, StandardSSLContextService.TRUSTSTORE,
                                "src/test/resources/signing_truststore.jks");
                runner.setProperty(sslContextService, StandardSSLContextService.TRUSTSTORE_PASSWORD,
                                "passwordpassword");
                runner.setProperty(sslContextService, StandardSSLContextService.TRUSTSTORE_TYPE,
                                "JKS");
                runner.setProperty(sslContextService, StandardSSLContextService.KEYSTORE,
                                "src/test/resources/signing_keystore.jks");
                runner.setProperty(sslContextService, StandardSSLContextService.KEYSTORE_PASSWORD,
                                "passwordpassword");
                runner.setProperty(sslContextService, StandardSSLContextService.KEYSTORE_TYPE,
                                "JKS");
                runner.setProperty(sslContextService, StandardSSLContextService.SSL_ALGORITHM,
                                tlsProtocol);
                runner.enableControllerService(sslContextService);
                return sslContextService;
        }
}
