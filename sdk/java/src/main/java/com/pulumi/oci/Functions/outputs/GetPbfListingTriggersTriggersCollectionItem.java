// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPbfListingTriggersTriggersCollectionItem {
    /**
     * @return A filter to return only resources that match the service trigger source of a PBF.
     * 
     */
    private String name;

    private GetPbfListingTriggersTriggersCollectionItem() {}
    /**
     * @return A filter to return only resources that match the service trigger source of a PBF.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPbfListingTriggersTriggersCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(GetPbfListingTriggersTriggersCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetPbfListingTriggersTriggersCollectionItem build() {
            final var o = new GetPbfListingTriggersTriggersCollectionItem();
            o.name = name;
            return o;
        }
    }
}