// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Marketplace.outputs.GetListingPackageAgreementsAgreement;
import com.pulumi.oci.Marketplace.outputs.GetListingPackageAgreementsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetListingPackageAgreementsResult {
    /**
     * @return The list of agreements.
     * 
     */
    private List<GetListingPackageAgreementsAgreement> agreements;
    /**
     * @return The unique identifier for the compartment.
     * 
     */
    private @Nullable String compartmentId;
    private @Nullable List<GetListingPackageAgreementsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String listingId;
    private String packageVersion;

    private GetListingPackageAgreementsResult() {}
    /**
     * @return The list of agreements.
     * 
     */
    public List<GetListingPackageAgreementsAgreement> agreements() {
        return this.agreements;
    }
    /**
     * @return The unique identifier for the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public List<GetListingPackageAgreementsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String listingId() {
        return this.listingId;
    }
    public String packageVersion() {
        return this.packageVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingPackageAgreementsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetListingPackageAgreementsAgreement> agreements;
        private @Nullable String compartmentId;
        private @Nullable List<GetListingPackageAgreementsFilter> filters;
        private String id;
        private String listingId;
        private String packageVersion;
        public Builder() {}
        public Builder(GetListingPackageAgreementsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agreements = defaults.agreements;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.listingId = defaults.listingId;
    	      this.packageVersion = defaults.packageVersion;
        }

        @CustomType.Setter
        public Builder agreements(List<GetListingPackageAgreementsAgreement> agreements) {
            if (agreements == null) {
              throw new MissingRequiredPropertyException("GetListingPackageAgreementsResult", "agreements");
            }
            this.agreements = agreements;
            return this;
        }
        public Builder agreements(GetListingPackageAgreementsAgreement... agreements) {
            return agreements(List.of(agreements));
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetListingPackageAgreementsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetListingPackageAgreementsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetListingPackageAgreementsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder listingId(String listingId) {
            if (listingId == null) {
              throw new MissingRequiredPropertyException("GetListingPackageAgreementsResult", "listingId");
            }
            this.listingId = listingId;
            return this;
        }
        @CustomType.Setter
        public Builder packageVersion(String packageVersion) {
            if (packageVersion == null) {
              throw new MissingRequiredPropertyException("GetListingPackageAgreementsResult", "packageVersion");
            }
            this.packageVersion = packageVersion;
            return this;
        }
        public GetListingPackageAgreementsResult build() {
            final var _resultValue = new GetListingPackageAgreementsResult();
            _resultValue.agreements = agreements;
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.listingId = listingId;
            _resultValue.packageVersion = packageVersion;
            return _resultValue;
        }
    }
}
