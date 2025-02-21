// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ListenerSslConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ListenerSslConfigurationArgs Empty = new ListenerSslConfigurationArgs();

    /**
     * (Updatable) Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
     * 
     */
    @Import(name="certificateIds")
    private @Nullable Output<List<String>> certificateIds;

    /**
     * @return (Updatable) Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
     * 
     */
    public Optional<Output<List<String>>> certificateIds() {
        return Optional.ofNullable(this.certificateIds);
    }

    /**
     * (Updatable) A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
     * 
     */
    @Import(name="certificateName")
    private @Nullable Output<String> certificateName;

    /**
     * @return (Updatable) A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
     * 
     */
    public Optional<Output<String>> certificateName() {
        return Optional.ofNullable(this.certificateName);
    }

    /**
     * (Updatable) The name of the cipher suite to use for HTTPS or SSL connections.
     * 
     * If this field is not specified, the default is `oci-default-ssl-cipher-suite-v1`.
     * 
     * **Notes:**
     * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite. Clients cannot perform an SSL handshake if there is an incompatible configuration.
     * *  You must ensure compatibility between the ciphers configured in the cipher suite and the configured certificates. For example, RSA-based ciphers require RSA certificates and ECDSA-based ciphers require ECDSA certificates.
     * *  If the cipher configuration is not modified after load balancer creation, the `GET` operation returns `oci-default-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing listeners that predate this feature.
     * *  If the cipher configuration was modified using Oracle operations after load balancer creation, the `GET` operation returns `oci-customized-ssl-cipher-suite` as the value of this field in the SSL configuration for existing listeners that predate this feature.
     * *  The `GET` operation returns `oci-wider-compatible-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing backend sets that predate this feature.
     * *  If the `GET` operation on a listener returns `oci-customized-ssl-cipher-suite` as the value of this field, you must specify an appropriate predefined or custom cipher suite name when updating the resource.
     * *  The `oci-customized-ssl-cipher-suite` Oracle reserved cipher suite name is not accepted as valid input for this field.
     * 
     * example: `example_cipher_suite`
     * 
     */
    @Import(name="cipherSuiteName")
    private @Nullable Output<String> cipherSuiteName;

    /**
     * @return (Updatable) The name of the cipher suite to use for HTTPS or SSL connections.
     * 
     * If this field is not specified, the default is `oci-default-ssl-cipher-suite-v1`.
     * 
     * **Notes:**
     * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite. Clients cannot perform an SSL handshake if there is an incompatible configuration.
     * *  You must ensure compatibility between the ciphers configured in the cipher suite and the configured certificates. For example, RSA-based ciphers require RSA certificates and ECDSA-based ciphers require ECDSA certificates.
     * *  If the cipher configuration is not modified after load balancer creation, the `GET` operation returns `oci-default-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing listeners that predate this feature.
     * *  If the cipher configuration was modified using Oracle operations after load balancer creation, the `GET` operation returns `oci-customized-ssl-cipher-suite` as the value of this field in the SSL configuration for existing listeners that predate this feature.
     * *  The `GET` operation returns `oci-wider-compatible-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing backend sets that predate this feature.
     * *  If the `GET` operation on a listener returns `oci-customized-ssl-cipher-suite` as the value of this field, you must specify an appropriate predefined or custom cipher suite name when updating the resource.
     * *  The `oci-customized-ssl-cipher-suite` Oracle reserved cipher suite name is not accepted as valid input for this field.
     * 
     * example: `example_cipher_suite`
     * 
     */
    public Optional<Output<String>> cipherSuiteName() {
        return Optional.ofNullable(this.cipherSuiteName);
    }

    /**
     * (Updatable) Whether the load balancer listener should resume an encrypted session by reusing the cryptographic parameters of a previous TLS session, without having to perform a full handshake again. If &#34;true&#34;, the service resumes the previous TLS encrypted session. If &#34;false&#34;, the service starts a new TLS encrypted session. Enabling session resumption improves performance but provides a lower level of security. Disabling session resumption improves security but reduces performance.  Example: `true`
     * 
     */
    @Import(name="hasSessionResumption")
    private @Nullable Output<Boolean> hasSessionResumption;

    /**
     * @return (Updatable) Whether the load balancer listener should resume an encrypted session by reusing the cryptographic parameters of a previous TLS session, without having to perform a full handshake again. If &#34;true&#34;, the service resumes the previous TLS encrypted session. If &#34;false&#34;, the service starts a new TLS encrypted session. Enabling session resumption improves performance but provides a lower level of security. Disabling session resumption improves security but reduces performance.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> hasSessionResumption() {
        return Optional.ofNullable(this.hasSessionResumption);
    }

    /**
     * (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
     * 
     * The load balancer uses SSL protocols to establish a secure connection between a client and a server. A secure connection ensures that all data passed between the client and the server is private.
     * 
     * The Load Balancing service supports the following protocols:
     * *  TLSv1
     * *  TLSv1.1
     * *  TLSv1.2
     * *  TLSv1.3
     * 
     * If this field is not specified, TLSv1.2 is the default.
     * 
     * **Warning:** All SSL listeners created on a given port must use the same set of SSL protocols.
     * 
     * **Notes:**
     * *  The handshake to establish an SSL connection fails if the client supports none of the specified protocols.
     * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite.
     * *  For all existing load balancer listeners and backend sets that predate this feature, the `GET` operation displays a list of SSL protocols currently used by those resources.
     * 
     * example: `[&#34;TLSv1.1&#34;, &#34;TLSv1.2&#34;]`
     * 
     */
    @Import(name="protocols")
    private @Nullable Output<List<String>> protocols;

    /**
     * @return (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
     * 
     * The load balancer uses SSL protocols to establish a secure connection between a client and a server. A secure connection ensures that all data passed between the client and the server is private.
     * 
     * The Load Balancing service supports the following protocols:
     * *  TLSv1
     * *  TLSv1.1
     * *  TLSv1.2
     * *  TLSv1.3
     * 
     * If this field is not specified, TLSv1.2 is the default.
     * 
     * **Warning:** All SSL listeners created on a given port must use the same set of SSL protocols.
     * 
     * **Notes:**
     * *  The handshake to establish an SSL connection fails if the client supports none of the specified protocols.
     * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite.
     * *  For all existing load balancer listeners and backend sets that predate this feature, the `GET` operation displays a list of SSL protocols currently used by those resources.
     * 
     * example: `[&#34;TLSv1.1&#34;, &#34;TLSv1.2&#34;]`
     * 
     */
    public Optional<Output<List<String>>> protocols() {
        return Optional.ofNullable(this.protocols);
    }

    /**
     * (Updatable) When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
     * 
     * **Note:** This configuration is applicable only when the load balancer is acting as an SSL/HTTPS server. This field is ignored when the `SSLConfiguration` object is associated with a backend set.
     * 
     */
    @Import(name="serverOrderPreference")
    private @Nullable Output<String> serverOrderPreference;

    /**
     * @return (Updatable) When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
     * 
     * **Note:** This configuration is applicable only when the load balancer is acting as an SSL/HTTPS server. This field is ignored when the `SSLConfiguration` object is associated with a backend set.
     * 
     */
    public Optional<Output<String>> serverOrderPreference() {
        return Optional.ofNullable(this.serverOrderPreference);
    }

    /**
     * (Updatable) Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
     * 
     */
    @Import(name="trustedCertificateAuthorityIds")
    private @Nullable Output<List<String>> trustedCertificateAuthorityIds;

    /**
     * @return (Updatable) Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
     * 
     */
    public Optional<Output<List<String>>> trustedCertificateAuthorityIds() {
        return Optional.ofNullable(this.trustedCertificateAuthorityIds);
    }

    /**
     * (Updatable) The maximum depth for peer certificate chain verification.  Example: `3`
     * 
     */
    @Import(name="verifyDepth")
    private @Nullable Output<Integer> verifyDepth;

    /**
     * @return (Updatable) The maximum depth for peer certificate chain verification.  Example: `3`
     * 
     */
    public Optional<Output<Integer>> verifyDepth() {
        return Optional.ofNullable(this.verifyDepth);
    }

    /**
     * (Updatable) Whether the load balancer listener should verify peer certificates.  Example: `true`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="verifyPeerCertificate")
    private @Nullable Output<Boolean> verifyPeerCertificate;

    /**
     * @return (Updatable) Whether the load balancer listener should verify peer certificates.  Example: `true`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> verifyPeerCertificate() {
        return Optional.ofNullable(this.verifyPeerCertificate);
    }

    private ListenerSslConfigurationArgs() {}

    private ListenerSslConfigurationArgs(ListenerSslConfigurationArgs $) {
        this.certificateIds = $.certificateIds;
        this.certificateName = $.certificateName;
        this.cipherSuiteName = $.cipherSuiteName;
        this.hasSessionResumption = $.hasSessionResumption;
        this.protocols = $.protocols;
        this.serverOrderPreference = $.serverOrderPreference;
        this.trustedCertificateAuthorityIds = $.trustedCertificateAuthorityIds;
        this.verifyDepth = $.verifyDepth;
        this.verifyPeerCertificate = $.verifyPeerCertificate;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ListenerSslConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ListenerSslConfigurationArgs $;

        public Builder() {
            $ = new ListenerSslConfigurationArgs();
        }

        public Builder(ListenerSslConfigurationArgs defaults) {
            $ = new ListenerSslConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param certificateIds (Updatable) Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
         * 
         * @return builder
         * 
         */
        public Builder certificateIds(@Nullable Output<List<String>> certificateIds) {
            $.certificateIds = certificateIds;
            return this;
        }

        /**
         * @param certificateIds (Updatable) Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
         * 
         * @return builder
         * 
         */
        public Builder certificateIds(List<String> certificateIds) {
            return certificateIds(Output.of(certificateIds));
        }

        /**
         * @param certificateIds (Updatable) Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
         * 
         * @return builder
         * 
         */
        public Builder certificateIds(String... certificateIds) {
            return certificateIds(List.of(certificateIds));
        }

        /**
         * @param certificateName (Updatable) A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
         * 
         * @return builder
         * 
         */
        public Builder certificateName(@Nullable Output<String> certificateName) {
            $.certificateName = certificateName;
            return this;
        }

        /**
         * @param certificateName (Updatable) A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
         * 
         * @return builder
         * 
         */
        public Builder certificateName(String certificateName) {
            return certificateName(Output.of(certificateName));
        }

        /**
         * @param cipherSuiteName (Updatable) The name of the cipher suite to use for HTTPS or SSL connections.
         * 
         * If this field is not specified, the default is `oci-default-ssl-cipher-suite-v1`.
         * 
         * **Notes:**
         * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite. Clients cannot perform an SSL handshake if there is an incompatible configuration.
         * *  You must ensure compatibility between the ciphers configured in the cipher suite and the configured certificates. For example, RSA-based ciphers require RSA certificates and ECDSA-based ciphers require ECDSA certificates.
         * *  If the cipher configuration is not modified after load balancer creation, the `GET` operation returns `oci-default-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing listeners that predate this feature.
         * *  If the cipher configuration was modified using Oracle operations after load balancer creation, the `GET` operation returns `oci-customized-ssl-cipher-suite` as the value of this field in the SSL configuration for existing listeners that predate this feature.
         * *  The `GET` operation returns `oci-wider-compatible-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing backend sets that predate this feature.
         * *  If the `GET` operation on a listener returns `oci-customized-ssl-cipher-suite` as the value of this field, you must specify an appropriate predefined or custom cipher suite name when updating the resource.
         * *  The `oci-customized-ssl-cipher-suite` Oracle reserved cipher suite name is not accepted as valid input for this field.
         * 
         * example: `example_cipher_suite`
         * 
         * @return builder
         * 
         */
        public Builder cipherSuiteName(@Nullable Output<String> cipherSuiteName) {
            $.cipherSuiteName = cipherSuiteName;
            return this;
        }

        /**
         * @param cipherSuiteName (Updatable) The name of the cipher suite to use for HTTPS or SSL connections.
         * 
         * If this field is not specified, the default is `oci-default-ssl-cipher-suite-v1`.
         * 
         * **Notes:**
         * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite. Clients cannot perform an SSL handshake if there is an incompatible configuration.
         * *  You must ensure compatibility between the ciphers configured in the cipher suite and the configured certificates. For example, RSA-based ciphers require RSA certificates and ECDSA-based ciphers require ECDSA certificates.
         * *  If the cipher configuration is not modified after load balancer creation, the `GET` operation returns `oci-default-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing listeners that predate this feature.
         * *  If the cipher configuration was modified using Oracle operations after load balancer creation, the `GET` operation returns `oci-customized-ssl-cipher-suite` as the value of this field in the SSL configuration for existing listeners that predate this feature.
         * *  The `GET` operation returns `oci-wider-compatible-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing backend sets that predate this feature.
         * *  If the `GET` operation on a listener returns `oci-customized-ssl-cipher-suite` as the value of this field, you must specify an appropriate predefined or custom cipher suite name when updating the resource.
         * *  The `oci-customized-ssl-cipher-suite` Oracle reserved cipher suite name is not accepted as valid input for this field.
         * 
         * example: `example_cipher_suite`
         * 
         * @return builder
         * 
         */
        public Builder cipherSuiteName(String cipherSuiteName) {
            return cipherSuiteName(Output.of(cipherSuiteName));
        }

        /**
         * @param hasSessionResumption (Updatable) Whether the load balancer listener should resume an encrypted session by reusing the cryptographic parameters of a previous TLS session, without having to perform a full handshake again. If &#34;true&#34;, the service resumes the previous TLS encrypted session. If &#34;false&#34;, the service starts a new TLS encrypted session. Enabling session resumption improves performance but provides a lower level of security. Disabling session resumption improves security but reduces performance.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder hasSessionResumption(@Nullable Output<Boolean> hasSessionResumption) {
            $.hasSessionResumption = hasSessionResumption;
            return this;
        }

        /**
         * @param hasSessionResumption (Updatable) Whether the load balancer listener should resume an encrypted session by reusing the cryptographic parameters of a previous TLS session, without having to perform a full handshake again. If &#34;true&#34;, the service resumes the previous TLS encrypted session. If &#34;false&#34;, the service starts a new TLS encrypted session. Enabling session resumption improves performance but provides a lower level of security. Disabling session resumption improves security but reduces performance.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder hasSessionResumption(Boolean hasSessionResumption) {
            return hasSessionResumption(Output.of(hasSessionResumption));
        }

        /**
         * @param protocols (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
         * 
         * The load balancer uses SSL protocols to establish a secure connection between a client and a server. A secure connection ensures that all data passed between the client and the server is private.
         * 
         * The Load Balancing service supports the following protocols:
         * *  TLSv1
         * *  TLSv1.1
         * *  TLSv1.2
         * *  TLSv1.3
         * 
         * If this field is not specified, TLSv1.2 is the default.
         * 
         * **Warning:** All SSL listeners created on a given port must use the same set of SSL protocols.
         * 
         * **Notes:**
         * *  The handshake to establish an SSL connection fails if the client supports none of the specified protocols.
         * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite.
         * *  For all existing load balancer listeners and backend sets that predate this feature, the `GET` operation displays a list of SSL protocols currently used by those resources.
         * 
         * example: `[&#34;TLSv1.1&#34;, &#34;TLSv1.2&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder protocols(@Nullable Output<List<String>> protocols) {
            $.protocols = protocols;
            return this;
        }

        /**
         * @param protocols (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
         * 
         * The load balancer uses SSL protocols to establish a secure connection between a client and a server. A secure connection ensures that all data passed between the client and the server is private.
         * 
         * The Load Balancing service supports the following protocols:
         * *  TLSv1
         * *  TLSv1.1
         * *  TLSv1.2
         * *  TLSv1.3
         * 
         * If this field is not specified, TLSv1.2 is the default.
         * 
         * **Warning:** All SSL listeners created on a given port must use the same set of SSL protocols.
         * 
         * **Notes:**
         * *  The handshake to establish an SSL connection fails if the client supports none of the specified protocols.
         * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite.
         * *  For all existing load balancer listeners and backend sets that predate this feature, the `GET` operation displays a list of SSL protocols currently used by those resources.
         * 
         * example: `[&#34;TLSv1.1&#34;, &#34;TLSv1.2&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder protocols(List<String> protocols) {
            return protocols(Output.of(protocols));
        }

        /**
         * @param protocols (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
         * 
         * The load balancer uses SSL protocols to establish a secure connection between a client and a server. A secure connection ensures that all data passed between the client and the server is private.
         * 
         * The Load Balancing service supports the following protocols:
         * *  TLSv1
         * *  TLSv1.1
         * *  TLSv1.2
         * *  TLSv1.3
         * 
         * If this field is not specified, TLSv1.2 is the default.
         * 
         * **Warning:** All SSL listeners created on a given port must use the same set of SSL protocols.
         * 
         * **Notes:**
         * *  The handshake to establish an SSL connection fails if the client supports none of the specified protocols.
         * *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite.
         * *  For all existing load balancer listeners and backend sets that predate this feature, the `GET` operation displays a list of SSL protocols currently used by those resources.
         * 
         * example: `[&#34;TLSv1.1&#34;, &#34;TLSv1.2&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder protocols(String... protocols) {
            return protocols(List.of(protocols));
        }

        /**
         * @param serverOrderPreference (Updatable) When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
         * 
         * **Note:** This configuration is applicable only when the load balancer is acting as an SSL/HTTPS server. This field is ignored when the `SSLConfiguration` object is associated with a backend set.
         * 
         * @return builder
         * 
         */
        public Builder serverOrderPreference(@Nullable Output<String> serverOrderPreference) {
            $.serverOrderPreference = serverOrderPreference;
            return this;
        }

        /**
         * @param serverOrderPreference (Updatable) When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
         * 
         * **Note:** This configuration is applicable only when the load balancer is acting as an SSL/HTTPS server. This field is ignored when the `SSLConfiguration` object is associated with a backend set.
         * 
         * @return builder
         * 
         */
        public Builder serverOrderPreference(String serverOrderPreference) {
            return serverOrderPreference(Output.of(serverOrderPreference));
        }

        /**
         * @param trustedCertificateAuthorityIds (Updatable) Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
         * 
         * @return builder
         * 
         */
        public Builder trustedCertificateAuthorityIds(@Nullable Output<List<String>> trustedCertificateAuthorityIds) {
            $.trustedCertificateAuthorityIds = trustedCertificateAuthorityIds;
            return this;
        }

        /**
         * @param trustedCertificateAuthorityIds (Updatable) Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
         * 
         * @return builder
         * 
         */
        public Builder trustedCertificateAuthorityIds(List<String> trustedCertificateAuthorityIds) {
            return trustedCertificateAuthorityIds(Output.of(trustedCertificateAuthorityIds));
        }

        /**
         * @param trustedCertificateAuthorityIds (Updatable) Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
         * 
         * @return builder
         * 
         */
        public Builder trustedCertificateAuthorityIds(String... trustedCertificateAuthorityIds) {
            return trustedCertificateAuthorityIds(List.of(trustedCertificateAuthorityIds));
        }

        /**
         * @param verifyDepth (Updatable) The maximum depth for peer certificate chain verification.  Example: `3`
         * 
         * @return builder
         * 
         */
        public Builder verifyDepth(@Nullable Output<Integer> verifyDepth) {
            $.verifyDepth = verifyDepth;
            return this;
        }

        /**
         * @param verifyDepth (Updatable) The maximum depth for peer certificate chain verification.  Example: `3`
         * 
         * @return builder
         * 
         */
        public Builder verifyDepth(Integer verifyDepth) {
            return verifyDepth(Output.of(verifyDepth));
        }

        /**
         * @param verifyPeerCertificate (Updatable) Whether the load balancer listener should verify peer certificates.  Example: `true`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder verifyPeerCertificate(@Nullable Output<Boolean> verifyPeerCertificate) {
            $.verifyPeerCertificate = verifyPeerCertificate;
            return this;
        }

        /**
         * @param verifyPeerCertificate (Updatable) Whether the load balancer listener should verify peer certificates.  Example: `true`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder verifyPeerCertificate(Boolean verifyPeerCertificate) {
            return verifyPeerCertificate(Output.of(verifyPeerCertificate));
        }

        public ListenerSslConfigurationArgs build() {
            return $;
        }
    }

}
