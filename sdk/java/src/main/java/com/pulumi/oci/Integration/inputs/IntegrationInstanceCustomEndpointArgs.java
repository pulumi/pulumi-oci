// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Integration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IntegrationInstanceCustomEndpointArgs extends com.pulumi.resources.ResourceArgs {

    public static final IntegrationInstanceCustomEndpointArgs Empty = new IntegrationInstanceCustomEndpointArgs();

    /**
     * When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
     * 
     */
    @Import(name="alias")
    private @Nullable Output<String> alias;

    /**
     * @return When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
     * 
     */
    public Optional<Output<String>> alias() {
        return Optional.ofNullable(this.alias);
    }

    /**
     * (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
     * 
     */
    @Import(name="certificateSecretId")
    private @Nullable Output<String> certificateSecretId;

    /**
     * @return (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
     * 
     */
    public Optional<Output<String>> certificateSecretId() {
        return Optional.ofNullable(this.certificateSecretId);
    }

    /**
     * The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
     * 
     */
    @Import(name="certificateSecretVersion")
    private @Nullable Output<Integer> certificateSecretVersion;

    /**
     * @return The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
     * 
     */
    public Optional<Output<Integer>> certificateSecretVersion() {
        return Optional.ofNullable(this.certificateSecretVersion);
    }

    /**
     * Type of DNS.
     * 
     */
    @Import(name="dnsType")
    private @Nullable Output<String> dnsType;

    /**
     * @return Type of DNS.
     * 
     */
    public Optional<Output<String>> dnsType() {
        return Optional.ofNullable(this.dnsType);
    }

    /**
     * DNS Zone name
     * 
     */
    @Import(name="dnsZoneName", required=true)
    private Output<String> dnsZoneName;

    /**
     * @return DNS Zone name
     * 
     */
    public Output<String> dnsZoneName() {
        return this.dnsZoneName;
    }

    /**
     * (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
     * 
     */
    @Import(name="hostname", required=true)
    private Output<String> hostname;

    /**
     * @return (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
     * 
     */
    public Output<String> hostname() {
        return this.hostname;
    }

    /**
     * Indicates if custom endpoint is managed by oracle or customer.
     * 
     */
    @Import(name="managedType")
    private @Nullable Output<String> managedType;

    /**
     * @return Indicates if custom endpoint is managed by oracle or customer.
     * 
     */
    public Optional<Output<String>> managedType() {
        return Optional.ofNullable(this.managedType);
    }

    private IntegrationInstanceCustomEndpointArgs() {}

    private IntegrationInstanceCustomEndpointArgs(IntegrationInstanceCustomEndpointArgs $) {
        this.alias = $.alias;
        this.certificateSecretId = $.certificateSecretId;
        this.certificateSecretVersion = $.certificateSecretVersion;
        this.dnsType = $.dnsType;
        this.dnsZoneName = $.dnsZoneName;
        this.hostname = $.hostname;
        this.managedType = $.managedType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IntegrationInstanceCustomEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IntegrationInstanceCustomEndpointArgs $;

        public Builder() {
            $ = new IntegrationInstanceCustomEndpointArgs();
        }

        public Builder(IntegrationInstanceCustomEndpointArgs defaults) {
            $ = new IntegrationInstanceCustomEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param alias When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
         * 
         * @return builder
         * 
         */
        public Builder alias(@Nullable Output<String> alias) {
            $.alias = alias;
            return this;
        }

        /**
         * @param alias When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
         * 
         * @return builder
         * 
         */
        public Builder alias(String alias) {
            return alias(Output.of(alias));
        }

        /**
         * @param certificateSecretId (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
         * 
         * @return builder
         * 
         */
        public Builder certificateSecretId(@Nullable Output<String> certificateSecretId) {
            $.certificateSecretId = certificateSecretId;
            return this;
        }

        /**
         * @param certificateSecretId (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
         * 
         * @return builder
         * 
         */
        public Builder certificateSecretId(String certificateSecretId) {
            return certificateSecretId(Output.of(certificateSecretId));
        }

        /**
         * @param certificateSecretVersion The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
         * 
         * @return builder
         * 
         */
        public Builder certificateSecretVersion(@Nullable Output<Integer> certificateSecretVersion) {
            $.certificateSecretVersion = certificateSecretVersion;
            return this;
        }

        /**
         * @param certificateSecretVersion The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
         * 
         * @return builder
         * 
         */
        public Builder certificateSecretVersion(Integer certificateSecretVersion) {
            return certificateSecretVersion(Output.of(certificateSecretVersion));
        }

        /**
         * @param dnsType Type of DNS.
         * 
         * @return builder
         * 
         */
        public Builder dnsType(@Nullable Output<String> dnsType) {
            $.dnsType = dnsType;
            return this;
        }

        /**
         * @param dnsType Type of DNS.
         * 
         * @return builder
         * 
         */
        public Builder dnsType(String dnsType) {
            return dnsType(Output.of(dnsType));
        }

        /**
         * @param dnsZoneName DNS Zone name
         * 
         * @return builder
         * 
         */
        public Builder dnsZoneName(Output<String> dnsZoneName) {
            $.dnsZoneName = dnsZoneName;
            return this;
        }

        /**
         * @param dnsZoneName DNS Zone name
         * 
         * @return builder
         * 
         */
        public Builder dnsZoneName(String dnsZoneName) {
            return dnsZoneName(Output.of(dnsZoneName));
        }

        /**
         * @param hostname (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
         * 
         * @return builder
         * 
         */
        public Builder hostname(Output<String> hostname) {
            $.hostname = hostname;
            return this;
        }

        /**
         * @param hostname (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
         * 
         * @return builder
         * 
         */
        public Builder hostname(String hostname) {
            return hostname(Output.of(hostname));
        }

        /**
         * @param managedType Indicates if custom endpoint is managed by oracle or customer.
         * 
         * @return builder
         * 
         */
        public Builder managedType(@Nullable Output<String> managedType) {
            $.managedType = managedType;
            return this;
        }

        /**
         * @param managedType Indicates if custom endpoint is managed by oracle or customer.
         * 
         * @return builder
         * 
         */
        public Builder managedType(String managedType) {
            return managedType(Output.of(managedType));
        }

        public IntegrationInstanceCustomEndpointArgs build() {
            if ($.dnsZoneName == null) {
                throw new MissingRequiredPropertyException("IntegrationInstanceCustomEndpointArgs", "dnsZoneName");
            }
            if ($.hostname == null) {
                throw new MissingRequiredPropertyException("IntegrationInstanceCustomEndpointArgs", "hostname");
            }
            return $;
        }
    }

}
