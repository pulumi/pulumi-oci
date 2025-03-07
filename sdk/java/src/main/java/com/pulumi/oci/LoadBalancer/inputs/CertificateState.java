// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CertificateState extends com.pulumi.resources.ResourceArgs {

    public static final CertificateState Empty = new CertificateState();

    /**
     * The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
     * 
     * Example:
     * 
     * -----BEGIN CERTIFICATE-----
     * MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
     * EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
     * VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
     * aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
     * ...
     * -----END CERTIFICATE-----
     * 
     */
    @Import(name="caCertificate")
    private @Nullable Output<String> caCertificate;

    /**
     * @return The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
     * 
     * Example:
     * 
     * -----BEGIN CERTIFICATE-----
     * MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
     * EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
     * VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
     * aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
     * ...
     * -----END CERTIFICATE-----
     * 
     */
    public Optional<Output<String>> caCertificate() {
        return Optional.ofNullable(this.caCertificate);
    }

    /**
     * A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
     * 
     */
    @Import(name="certificateName")
    private @Nullable Output<String> certificateName;

    /**
     * @return A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
     * 
     */
    public Optional<Output<String>> certificateName() {
        return Optional.ofNullable(this.certificateName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
     * 
     */
    @Import(name="loadBalancerId")
    private @Nullable Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
     * 
     */
    public Optional<Output<String>> loadBalancerId() {
        return Optional.ofNullable(this.loadBalancerId);
    }

    /**
     * A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
     * 
     */
    @Import(name="passphrase")
    private @Nullable Output<String> passphrase;

    /**
     * @return A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
     * 
     */
    public Optional<Output<String>> passphrase() {
        return Optional.ofNullable(this.passphrase);
    }

    /**
     * The SSL private key for your certificate, in PEM format.
     * 
     * Example:
     * 
     * -----BEGIN RSA PRIVATE KEY-----
     * jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
     * tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
     * +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
     * /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
     * ...
     * -----END RSA PRIVATE KEY-----
     * 
     */
    @Import(name="privateKey")
    private @Nullable Output<String> privateKey;

    /**
     * @return The SSL private key for your certificate, in PEM format.
     * 
     * Example:
     * 
     * -----BEGIN RSA PRIVATE KEY-----
     * jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
     * tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
     * +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
     * /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
     * ...
     * -----END RSA PRIVATE KEY-----
     * 
     */
    public Optional<Output<String>> privateKey() {
        return Optional.ofNullable(this.privateKey);
    }

    /**
     * The public certificate, in PEM format, that you received from your SSL certificate provider.
     * 
     * Example:
     * 
     * -----BEGIN CERTIFICATE-----
     * MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
     * A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
     * MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
     * YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
     * ...
     * -----END CERTIFICATE-----
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="publicCertificate")
    private @Nullable Output<String> publicCertificate;

    /**
     * @return The public certificate, in PEM format, that you received from your SSL certificate provider.
     * 
     * Example:
     * 
     * -----BEGIN CERTIFICATE-----
     * MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
     * A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
     * MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
     * YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
     * ...
     * -----END CERTIFICATE-----
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> publicCertificate() {
        return Optional.ofNullable(this.publicCertificate);
    }

    @Import(name="state")
    private @Nullable Output<String> state;

    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private CertificateState() {}

    private CertificateState(CertificateState $) {
        this.caCertificate = $.caCertificate;
        this.certificateName = $.certificateName;
        this.loadBalancerId = $.loadBalancerId;
        this.passphrase = $.passphrase;
        this.privateKey = $.privateKey;
        this.publicCertificate = $.publicCertificate;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CertificateState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CertificateState $;

        public Builder() {
            $ = new CertificateState();
        }

        public Builder(CertificateState defaults) {
            $ = new CertificateState(Objects.requireNonNull(defaults));
        }

        /**
         * @param caCertificate The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
         * 
         * Example:
         * 
         * -----BEGIN CERTIFICATE-----
         * MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
         * EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
         * VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
         * aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
         * ...
         * -----END CERTIFICATE-----
         * 
         * @return builder
         * 
         */
        public Builder caCertificate(@Nullable Output<String> caCertificate) {
            $.caCertificate = caCertificate;
            return this;
        }

        /**
         * @param caCertificate The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
         * 
         * Example:
         * 
         * -----BEGIN CERTIFICATE-----
         * MIIEczCCA1ugAwIBAgIBADANBgkqhkiG9w0BAQQFAD..AkGA1UEBhMCR0Ix
         * EzARBgNVBAgTClNvbWUtU3RhdGUxFDASBgNVBAoTC0..0EgTHRkMTcwNQYD
         * VQQLEy5DbGFzcyAxIFB1YmxpYyBQcmltYXJ5IENlcn..XRpb24gQXV0aG9y
         * aXR5MRQwEgYDVQQDEwtCZXN0IENBIEx0ZDAeFw0wMD..TUwMTZaFw0wMTAy
         * ...
         * -----END CERTIFICATE-----
         * 
         * @return builder
         * 
         */
        public Builder caCertificate(String caCertificate) {
            return caCertificate(Output.of(caCertificate));
        }

        /**
         * @param certificateName A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
         * 
         * @return builder
         * 
         */
        public Builder certificateName(@Nullable Output<String> certificateName) {
            $.certificateName = certificateName;
            return this;
        }

        /**
         * @param certificateName A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
         * 
         * @return builder
         * 
         */
        public Builder certificateName(String certificateName) {
            return certificateName(Output.of(certificateName));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(@Nullable Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add the certificate bundle.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        /**
         * @param passphrase A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
         * 
         * @return builder
         * 
         */
        public Builder passphrase(@Nullable Output<String> passphrase) {
            $.passphrase = passphrase;
            return this;
        }

        /**
         * @param passphrase A passphrase for encrypted private keys. This is needed only if you created your certificate with a passphrase.
         * 
         * @return builder
         * 
         */
        public Builder passphrase(String passphrase) {
            return passphrase(Output.of(passphrase));
        }

        /**
         * @param privateKey The SSL private key for your certificate, in PEM format.
         * 
         * Example:
         * 
         * -----BEGIN RSA PRIVATE KEY-----
         * jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
         * tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
         * +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
         * /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
         * ...
         * -----END RSA PRIVATE KEY-----
         * 
         * @return builder
         * 
         */
        public Builder privateKey(@Nullable Output<String> privateKey) {
            $.privateKey = privateKey;
            return this;
        }

        /**
         * @param privateKey The SSL private key for your certificate, in PEM format.
         * 
         * Example:
         * 
         * -----BEGIN RSA PRIVATE KEY-----
         * jO1O1v2ftXMsawM90tnXwc6xhOAT1gDBC9S8DKeca..JZNUgYYwNS0dP2UK
         * tmyN+XqVcAKw4HqVmChXy5b5msu8eIq3uc2NqNVtR..2ksSLukP8pxXcHyb
         * +sEwvM4uf8qbnHAqwnOnP9+KV9vds6BaH1eRA4CHz..n+NVZlzBsTxTlS16
         * /Umr7wJzVrMqK5sDiSu4WuaaBdqMGfL5hLsTjcBFD..Da2iyQmSKuVD4lIZ
         * ...
         * -----END RSA PRIVATE KEY-----
         * 
         * @return builder
         * 
         */
        public Builder privateKey(String privateKey) {
            return privateKey(Output.of(privateKey));
        }

        /**
         * @param publicCertificate The public certificate, in PEM format, that you received from your SSL certificate provider.
         * 
         * Example:
         * 
         * -----BEGIN CERTIFICATE-----
         * MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
         * A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
         * MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
         * YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
         * ...
         * -----END CERTIFICATE-----
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder publicCertificate(@Nullable Output<String> publicCertificate) {
            $.publicCertificate = publicCertificate;
            return this;
        }

        /**
         * @param publicCertificate The public certificate, in PEM format, that you received from your SSL certificate provider.
         * 
         * Example:
         * 
         * -----BEGIN CERTIFICATE-----
         * MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbM..QswCQYDVQQGEwJKU
         * A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxE..TAPBgNVBAoTCEZyY
         * MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWB..gNVBAMTD0ZyYW5rN
         * YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmc..mFuazRkZC5jb20wH
         * ...
         * -----END CERTIFICATE-----
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder publicCertificate(String publicCertificate) {
            return publicCertificate(Output.of(publicCertificate));
        }

        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        public Builder state(String state) {
            return state(Output.of(state));
        }

        public CertificateState build() {
            return $;
        }
    }

}
