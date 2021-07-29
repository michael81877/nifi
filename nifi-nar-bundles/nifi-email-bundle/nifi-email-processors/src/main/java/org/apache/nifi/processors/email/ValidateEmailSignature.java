package org.apache.nifi.processors.email;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.PKIXParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import org.apache.nifi.annotation.behavior.EventDriven;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.SideEffectFree;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.reporting.InitializationException;
import org.apache.nifi.security.util.KeyStoreUtils;
import org.apache.nifi.security.util.TlsConfiguration;
import org.apache.nifi.security.util.TlsException;
import org.apache.nifi.ssl.SSLContextService;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.mail.smime.validator.SignedMailValidator.ValidationResult;
import org.bouncycastle.mail.smime.validator.SignedMailValidatorException;

@SupportsBatching
@EventDriven
@SideEffectFree
@Tags({"validation", "email", "signature"})
@InputRequirement(Requirement.INPUT_REQUIRED)
@CapabilityDescription("Using the flowfile content as source of data, extract from an RFC compliant an email file to validate any digital signatures and adding the relevant attributes to the flowfile. " +
        "This processor does not perform extensive RFC validation.")
@WritesAttributes({
    @WritesAttribute(attribute = "email.signature.validated", description = "Attribute indicating that the digital signature on the email has been validated"),
    @WritesAttribute(attribute = "email.signature.validation.error.reasons", description = "If applicable, attribute capturing the reasons for validation failure")
})
public class ValidateEmailSignature extends AbstractProcessor {
    public static final AllowableValue STRICT_ADDRESSING = new AllowableValue("true", "Strict Address Parsing",
        "Strict email address format will be enforced. FlowFiles will be transfered to the failure relationship if the email address is invalid.");
    public static final AllowableValue NONSTRICT_ADDRESSING = new AllowableValue("false", "Non-Strict Address Parsing",
        "Accept emails, even if the address is poorly formed and doesn't strictly comply with RFC Validation.");
    public static final PropertyDescriptor STRICT_PARSING = new PropertyDescriptor.Builder()
            .name("STRICT_ADDRESS_PARSING")
            .displayName("Email Address Parsing")
            .description("If \"strict\", strict address format parsing rules are applied to mailbox and mailbox list fields, " +
                    "such as \"to\" and \"from\" headers, and FlowFiles with poorly formed addresses will be routed " +
                    "to the failure relationship, similar to messages that fail RFC compliant format validation. " +
                    "If \"non-strict\", the processor will extract the contents of mailbox list headers as comma-separated " +
                    "values without attempting to parse each value as well-formed Internet mailbox addresses. " +
                    "This is optional and defaults to " + STRICT_ADDRESSING.getDisplayName())
            .required(false)
            .defaultValue(STRICT_ADDRESSING.getValue())
            .allowableValues(STRICT_ADDRESSING, NONSTRICT_ADDRESSING)
            .build();

    public static final PropertyDescriptor SSL_CONTEXT_SERVICE = new PropertyDescriptor.Builder()
            .name("SSL Context Service")
            .description("Specifies a SSL Context Service that will be used to validate digital email signatures")
            .required(true)
            .identifiesControllerService(SSLContextService.class)
            .build();
    
    public static final PropertyDescriptor ALLOW_UNSIGNED_EMAIL = new PropertyDescriptor.Builder()
            .name("ALLOW_UNSIGNED_EMAIL")
            .displayName("Allow Unsigned Email")
            .description("Whether or not to route email that has not been signed to the success relationship.")
            .required(true)
            .defaultValue("true")
            .allowableValues("true", "false")
            .addValidator(StandardValidators.BOOLEAN_VALIDATOR)
            .build();            

    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("Extraction was successful")
            .build();
    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("Flowfiles that could not be parsed as a RFC-2822 compliant message")
            .build();

    private Set<Relationship> relationships;
    private List<PropertyDescriptor> descriptors;
    private PKIXParameters pkixParameters;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);

        final List<PropertyDescriptor> descriptors = new ArrayList<>();

        descriptors.add(STRICT_PARSING);
        descriptors.add(SSL_CONTEXT_SERVICE);
        descriptors.add(ALLOW_UNSIGNED_EMAIL);
        this.descriptors = Collections.unmodifiableList(descriptors);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) throws InitializationException {
        final SSLContextService sslService =
                context.getProperty(SSL_CONTEXT_SERVICE).asControllerService(SSLContextService.class);
        final TlsConfiguration tlsConfig = sslService.createTlsConfiguration();
        
        // initialize pki parameters for use in the bouncy castle signature validator
        try {
            final KeyStore trustStore = KeyStoreUtils.loadTrustStore(tlsConfig.getTruststorePath(), 
                    tlsConfig.getTruststorePassword().toCharArray(), 
                    tlsConfig.getTruststoreType().getType());
            
            pkixParameters = new PKIXParameters(trustStore);
            pkixParameters.setRevocationEnabled(false);
        } catch (TlsException | KeyStoreException | InvalidAlgorithmParameterException e) {
            throw new InitializationException("Failed to initialize KeyStore for signature validation", e);
        }
    }
    
    @Override
    public void onTrigger(ProcessContext context, ProcessSession session) throws ProcessException {
        final ComponentLog logger = getLogger();
        final FlowFile originalFlowFile = session.get();
        if (originalFlowFile == null) {
            return;
        }

        final String requireStrictAddresses = context.getProperty(STRICT_PARSING).getValue();
        final boolean allowUnsignedEmail = context.getProperty(ALLOW_UNSIGNED_EMAIL).asBoolean();

        final AtomicReference<MimeMessage> messageRef = new AtomicReference<>();
        session.read(originalFlowFile, new InputStreamCallback() {
            @Override
            public void process(final InputStream rawIn) throws IOException {
                try (final InputStream in = new BufferedInputStream(rawIn)) {

                    Properties props = new Properties();
                    props.put("mail.mime.address.strict", requireStrictAddresses);
                    Session mailSession = Session.getInstance(props);
                    final MimeMessage originalMessage = new MimeMessage(mailSession, in);
                    messageRef.set(originalMessage);

                } catch (final MessagingException e) {
                    throw new IOException("Failure to process email as signed.", e);
                }
            }
        });

        try {
            List<String> errors = validateSignature(messageRef.get());

            if(errors.isEmpty()) {
                success(session, originalFlowFile);
            } else {
                logger.info("Email signature validation failed for FlowFile {}", originalFlowFile.getId());
                fail(session, originalFlowFile, errors);
            }
        } catch (final SignedMailValidatorException e) {
            if(allowUnsignedEmail && e.getMessage().contains("message is not a signed message.")) {
                success(session, originalFlowFile);
            } else {
                logger.info("Email signature validation failed for FlowFile {}, treating as failure", new Object[]{originalFlowFile, e});
                fail(session, originalFlowFile, new ArrayList<String>(){{add(e.getMessage());}});
            }
        }
    }

    private void success(final ProcessSession session, final FlowFile flowFile) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("email.signature.validated", "true");
        FlowFile updatedFlowFile = session.putAllAttributes(flowFile, attributes);
        session.transfer(updatedFlowFile, REL_SUCCESS);
    }

    private void fail(final ProcessSession session, final FlowFile flowFile, Collection<String> reasons) {
        Map<String, String> attrs = new HashMap<>();
        attrs.put("email.signature.validated", "false");
        attrs.put("email.signature.validation.error.reasons", reasons.toString());
        FlowFile updatedFlowFile = session.putAllAttributes(flowFile, attrs);
        session.transfer(updatedFlowFile, REL_FAILURE);
    }
 
    /**
     * Validate digital signatures and return a list of reasons for failure, if failure occurred.
     * 
     * An empty list indicated a successful validation.
     */
    protected List<String> validateSignature(final MimeMessage msg) throws SignedMailValidatorException {
        final Locale locale = Locale.ENGLISH;
        final SignedMailValidator signedMailValidator = new SignedMailValidator(msg, this.pkixParameters);

        // extract all validation error reasons from the validator
        return signedMailValidator.getSignerInformationStore().getSigners().stream()
            // map signer to list of error bundle lists
            .map(signer -> {
                ValidationResult validationResult;
                try {
                    validationResult = signedMailValidator.getValidationResult(signer);
                } catch (SignedMailValidatorException e) {
                    List<ErrorBundle> errorReason = new ArrayList<>();
                    errorReason.add(e.getErrorMessage());
                    return errorReason;
                }
                
                if(!validationResult.isValidSignature()) {
                    return (List<ErrorBundle>) validationResult.getErrors();
                } else {
                    return new ArrayList<ErrorBundle>();
                }
            })
            // map list of error bundles lists to list of error string lists
            .map(errorBundleList -> {
                return errorBundleList.stream()
                    .map(errorBundle -> errorBundle.getSummary(locale))
                    .collect(Collectors.toList());
            // reduce list of error string lists to single list of error strings
            }).reduce(new ArrayList<>(), (listA, listB) -> {
                return Stream.concat(listA.parallelStream(), listB.parallelStream())
                    .collect(Collectors.toList());
            });
    }
}
