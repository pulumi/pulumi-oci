// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CertificatesManagement.inputs.GetCertificatesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCertificatesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCertificatesArgs Empty = new GetCertificatesArgs();

    /**
     * The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
     * 
     */
    @Import(name="certificateId")
    private @Nullable Output<String> certificateId;

    /**
     * @return The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
     * 
     */
    public Optional<Output<String>> certificateId() {
        return Optional.ofNullable(this.certificateId);
    }

    /**
     * A filter that returns only resources that match the given compartment OCID.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return A filter that returns only resources that match the given compartment OCID.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetCertificatesFilterArgs>> filters;

    public Optional<Output<List<GetCertificatesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    @Import(name="issuerCertificateAuthorityId")
    private @Nullable Output<String> issuerCertificateAuthorityId;

    /**
     * @return The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    public Optional<Output<String>> issuerCertificateAuthorityId() {
        return Optional.ofNullable(this.issuerCertificateAuthorityId);
    }

    /**
     * A filter that returns only resources that match the specified name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter that returns only resources that match the specified name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetCertificatesArgs() {}

    private GetCertificatesArgs(GetCertificatesArgs $) {
        this.certificateId = $.certificateId;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.issuerCertificateAuthorityId = $.issuerCertificateAuthorityId;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCertificatesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCertificatesArgs $;

        public Builder() {
            $ = new GetCertificatesArgs();
        }

        public Builder(GetCertificatesArgs defaults) {
            $ = new GetCertificatesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param certificateId The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
         * 
         * @return builder
         * 
         */
        public Builder certificateId(@Nullable Output<String> certificateId) {
            $.certificateId = certificateId;
            return this;
        }

        /**
         * @param certificateId The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
         * 
         * @return builder
         * 
         */
        public Builder certificateId(String certificateId) {
            return certificateId(Output.of(certificateId));
        }

        /**
         * @param compartmentId A filter that returns only resources that match the given compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId A filter that returns only resources that match the given compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetCertificatesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetCertificatesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetCertificatesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param issuerCertificateAuthorityId The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
         * 
         * @return builder
         * 
         */
        public Builder issuerCertificateAuthorityId(@Nullable Output<String> issuerCertificateAuthorityId) {
            $.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            return this;
        }

        /**
         * @param issuerCertificateAuthorityId The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
         * 
         * @return builder
         * 
         */
        public Builder issuerCertificateAuthorityId(String issuerCertificateAuthorityId) {
            return issuerCertificateAuthorityId(Output.of(issuerCertificateAuthorityId));
        }

        /**
         * @param name A filter that returns only resources that match the specified name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter that returns only resources that match the specified name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetCertificatesArgs build() {
            return $;
        }
    }

}