// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetPublicationPackagesFilter;
import com.pulumi.oci.Marketplace.outputs.GetPublicationPackagesPublicationPackage;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPublicationPackagesResult {
    private @Nullable List<GetPublicationPackagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The specified package&#39;s type.
     * 
     */
    private @Nullable String packageType;
    private @Nullable String packageVersion;
    private String publicationId;
    /**
     * @return The list of publication_packages.
     * 
     */
    private List<GetPublicationPackagesPublicationPackage> publicationPackages;

    private GetPublicationPackagesResult() {}
    public List<GetPublicationPackagesFilter> filters() {
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
     * @return The specified package&#39;s type.
     * 
     */
    public Optional<String> packageType() {
        return Optional.ofNullable(this.packageType);
    }
    public Optional<String> packageVersion() {
        return Optional.ofNullable(this.packageVersion);
    }
    public String publicationId() {
        return this.publicationId;
    }
    /**
     * @return The list of publication_packages.
     * 
     */
    public List<GetPublicationPackagesPublicationPackage> publicationPackages() {
        return this.publicationPackages;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPublicationPackagesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetPublicationPackagesFilter> filters;
        private String id;
        private @Nullable String packageType;
        private @Nullable String packageVersion;
        private String publicationId;
        private List<GetPublicationPackagesPublicationPackage> publicationPackages;
        public Builder() {}
        public Builder(GetPublicationPackagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.packageType = defaults.packageType;
    	      this.packageVersion = defaults.packageVersion;
    	      this.publicationId = defaults.publicationId;
    	      this.publicationPackages = defaults.publicationPackages;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetPublicationPackagesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetPublicationPackagesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder packageType(@Nullable String packageType) {
            this.packageType = packageType;
            return this;
        }
        @CustomType.Setter
        public Builder packageVersion(@Nullable String packageVersion) {
            this.packageVersion = packageVersion;
            return this;
        }
        @CustomType.Setter
        public Builder publicationId(String publicationId) {
            this.publicationId = Objects.requireNonNull(publicationId);
            return this;
        }
        @CustomType.Setter
        public Builder publicationPackages(List<GetPublicationPackagesPublicationPackage> publicationPackages) {
            this.publicationPackages = Objects.requireNonNull(publicationPackages);
            return this;
        }
        public Builder publicationPackages(GetPublicationPackagesPublicationPackage... publicationPackages) {
            return publicationPackages(List.of(publicationPackages));
        }
        public GetPublicationPackagesResult build() {
            final var o = new GetPublicationPackagesResult();
            o.filters = filters;
            o.id = id;
            o.packageType = packageType;
            o.packageVersion = packageVersion;
            o.publicationId = publicationId;
            o.publicationPackages = publicationPackages;
            return o;
        }
    }
}