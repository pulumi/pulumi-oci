// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetListingsListingRegionCountry {
    /**
     * @return A code assigned to the item.
     * 
     */
    private String code;
    /**
     * @return The name of the listing.
     * 
     */
    private String name;

    private GetListingsListingRegionCountry() {}
    /**
     * @return A code assigned to the item.
     * 
     */
    public String code() {
        return this.code;
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

    public static Builder builder(GetListingsListingRegionCountry defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String code;
        private String name;
        public Builder() {}
        public Builder(GetListingsListingRegionCountry defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder code(String code) {
            this.code = Objects.requireNonNull(code);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetListingsListingRegionCountry build() {
            final var o = new GetListingsListingRegionCountry();
            o.code = code;
            o.name = name;
            return o;
        }
    }
}