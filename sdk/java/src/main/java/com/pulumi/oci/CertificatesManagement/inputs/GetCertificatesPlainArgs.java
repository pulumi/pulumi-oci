// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CertificatesManagement.inputs.GetCertificatesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCertificatesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCertificatesPlainArgs Empty = new GetCertificatesPlainArgs();

    /**
     * The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
     * 
     */
    @Import(name="certificateId")
    private @Nullable String certificateId;

    /**
     * @return The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
     * 
     */
    public Optional<String> certificateId() {
        return Optional.ofNullable(this.certificateId);
    }

    /**
     * A filter that returns only resources that match the given compartment OCID.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return A filter that returns only resources that match the given compartment OCID.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable List<GetCertificatesFilter> filters;

    public Optional<List<GetCertificatesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    @Import(name="issuerCertificateAuthorityId")
    private @Nullable String issuerCertificateAuthorityId;

    /**
     * @return The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     * 
     */
    public Optional<String> issuerCertificateAuthorityId() {
        return Optional.ofNullable(this.issuerCertificateAuthorityId);
    }

    /**
     * A filter that returns only resources that match the specified name.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter that returns only resources that match the specified name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetCertificatesPlainArgs() {}

    private GetCertificatesPlainArgs(GetCertificatesPlainArgs $) {
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
    public static Builder builder(GetCertificatesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCertificatesPlainArgs $;

        public Builder() {
            $ = new GetCertificatesPlainArgs();
        }

        public Builder(GetCertificatesPlainArgs defaults) {
            $ = new GetCertificatesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param certificateId The OCID of the certificate. If the parameter is set to null, the service lists all certificates.
         * 
         * @return builder
         * 
         */
        public Builder certificateId(@Nullable String certificateId) {
            $.certificateId = certificateId;
            return this;
        }

        /**
         * @param compartmentId A filter that returns only resources that match the given compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetCertificatesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetCertificatesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param issuerCertificateAuthorityId The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
         * 
         * @return builder
         * 
         */
        public Builder issuerCertificateAuthorityId(@Nullable String issuerCertificateAuthorityId) {
            $.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            return this;
        }

        /**
         * @param name A filter that returns only resources that match the specified name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param state A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetCertificatesPlainArgs build() {
            return $;
        }
    }

}