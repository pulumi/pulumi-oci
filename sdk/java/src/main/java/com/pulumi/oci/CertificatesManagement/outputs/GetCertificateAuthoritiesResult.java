// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateAuthoritiesCertificateAuthorityCollection;
import com.pulumi.oci.CertificatesManagement.outputs.GetCertificateAuthoritiesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCertificateAuthoritiesResult {
    /**
     * @return The list of certificate_authority_collection.
     * 
     */
    private List<GetCertificateAuthoritiesCertificateAuthorityCollection> certificateAuthorityCollections;
    /**
     * @return The OCID of the CA.
     * 
     */
    private @Nullable String certificateAuthorityId;
    /**
     * @return The OCID of the compartment under which the CA is created.
     * 
     */
    private @Nullable String compartmentId;
    private @Nullable List<GetCertificateAuthoritiesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
     * 
     */
    private @Nullable String issuerCertificateAuthorityId;
    /**
     * @return A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
     * 
     */
    private @Nullable String name;
    /**
     * @return The current lifecycle state of the certificate authority.
     * 
     */
    private @Nullable String state;

    private GetCertificateAuthoritiesResult() {}
    /**
     * @return The list of certificate_authority_collection.
     * 
     */
    public List<GetCertificateAuthoritiesCertificateAuthorityCollection> certificateAuthorityCollections() {
        return this.certificateAuthorityCollections;
    }
    /**
     * @return The OCID of the CA.
     * 
     */
    public Optional<String> certificateAuthorityId() {
        return Optional.ofNullable(this.certificateAuthorityId);
    }
    /**
     * @return The OCID of the compartment under which the CA is created.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public List<GetCertificateAuthoritiesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
     * 
     */
    public Optional<String> issuerCertificateAuthorityId() {
        return Optional.ofNullable(this.issuerCertificateAuthorityId);
    }
    /**
     * @return A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current lifecycle state of the certificate authority.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificateAuthoritiesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCertificateAuthoritiesCertificateAuthorityCollection> certificateAuthorityCollections;
        private @Nullable String certificateAuthorityId;
        private @Nullable String compartmentId;
        private @Nullable List<GetCertificateAuthoritiesFilter> filters;
        private String id;
        private @Nullable String issuerCertificateAuthorityId;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetCertificateAuthoritiesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateAuthorityCollections = defaults.certificateAuthorityCollections;
    	      this.certificateAuthorityId = defaults.certificateAuthorityId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.issuerCertificateAuthorityId = defaults.issuerCertificateAuthorityId;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder certificateAuthorityCollections(List<GetCertificateAuthoritiesCertificateAuthorityCollection> certificateAuthorityCollections) {
            this.certificateAuthorityCollections = Objects.requireNonNull(certificateAuthorityCollections);
            return this;
        }
        public Builder certificateAuthorityCollections(GetCertificateAuthoritiesCertificateAuthorityCollection... certificateAuthorityCollections) {
            return certificateAuthorityCollections(List.of(certificateAuthorityCollections));
        }
        @CustomType.Setter
        public Builder certificateAuthorityId(@Nullable String certificateAuthorityId) {
            this.certificateAuthorityId = certificateAuthorityId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetCertificateAuthoritiesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetCertificateAuthoritiesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder issuerCertificateAuthorityId(@Nullable String issuerCertificateAuthorityId) {
            this.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetCertificateAuthoritiesResult build() {
            final var o = new GetCertificateAuthoritiesResult();
            o.certificateAuthorityCollections = certificateAuthorityCollections;
            o.certificateAuthorityId = certificateAuthorityId;
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.issuerCertificateAuthorityId = issuerCertificateAuthorityId;
            o.name = name;
            o.state = state;
            return o;
        }
    }
}