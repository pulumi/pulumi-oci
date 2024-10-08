// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Marketplace.outputs.GetListingsListingRegionCountry;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetListingsListingRegion {
    /**
     * @return A code assigned to the item.
     * 
     */
    private String code;
    /**
     * @return Countries in the region.
     * 
     */
    private List<GetListingsListingRegionCountry> countries;
    /**
     * @return The name of the listing.
     * 
     */
    private String name;

    private GetListingsListingRegion() {}
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
    public List<GetListingsListingRegionCountry> countries() {
        return this.countries;
    }
    /**
     * @return The name of the listing.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingsListingRegion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String code;
        private List<GetListingsListingRegionCountry> countries;
        private String name;
        public Builder() {}
        public Builder(GetListingsListingRegion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.countries = defaults.countries;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder code(String code) {
            if (code == null) {
              throw new MissingRequiredPropertyException("GetListingsListingRegion", "code");
            }
            this.code = code;
            return this;
        }
        @CustomType.Setter
        public Builder countries(List<GetListingsListingRegionCountry> countries) {
            if (countries == null) {
              throw new MissingRequiredPropertyException("GetListingsListingRegion", "countries");
            }
            this.countries = countries;
            return this;
        }
        public Builder countries(GetListingsListingRegionCountry... countries) {
            return countries(List.of(countries));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetListingsListingRegion", "name");
            }
            this.name = name;
            return this;
        }
        public GetListingsListingRegion build() {
            final var _resultValue = new GetListingsListingRegion();
            _resultValue.code = code;
            _resultValue.countries = countries;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
