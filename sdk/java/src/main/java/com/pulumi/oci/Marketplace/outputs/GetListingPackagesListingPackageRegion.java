// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetListingPackagesListingPackageRegionCountry;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetListingPackagesListingPackageRegion {
    /**
     * @return A code assigned to the item.
     * 
     */
    private String code;
    /**
     * @return Countries in the region.
     * 
     */
    private List<GetListingPackagesListingPackageRegionCountry> countries;
    /**
     * @return The name of the variable.
     * 
     */
    private String name;

    private GetListingPackagesListingPackageRegion() {}
    /**
     * @return A code assigned to the item.
     * 
     */
    public String code() {
        return this.code;
    }
    /**
     * @return Countries in the region.
     * 
     */
    public List<GetListingPackagesListingPackageRegionCountry> countries() {
        return this.countries;
    }
    /**
     * @return The name of the variable.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingPackagesListingPackageRegion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String code;
        private List<GetListingPackagesListingPackageRegionCountry> countries;
        private String name;
        public Builder() {}
        public Builder(GetListingPackagesListingPackageRegion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.countries = defaults.countries;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder code(String code) {
            this.code = Objects.requireNonNull(code);
            return this;
        }
        @CustomType.Setter
        public Builder countries(List<GetListingPackagesListingPackageRegionCountry> countries) {
            this.countries = Objects.requireNonNull(countries);
            return this;
        }
        public Builder countries(GetListingPackagesListingPackageRegionCountry... countries) {
            return countries(List.of(countries));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetListingPackagesListingPackageRegion build() {
            final var o = new GetListingPackagesListingPackageRegion();
            o.code = code;
            o.countries = countries;
            o.name = name;
            return o;
        }
    }
}