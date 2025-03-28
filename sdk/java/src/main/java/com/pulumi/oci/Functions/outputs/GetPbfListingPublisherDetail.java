// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPbfListingPublisherDetail {
    /**
     * @return A brief descriptive name for the PBF trigger.
     * 
     */
    private String name;

    private GetPbfListingPublisherDetail() {}
    /**
     * @return A brief descriptive name for the PBF trigger.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPbfListingPublisherDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(GetPbfListingPublisherDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetPbfListingPublisherDetail", "name");
            }
            this.name = name;
            return this;
        }
        public GetPbfListingPublisherDetail build() {
            final var _resultValue = new GetPbfListingPublisherDetail();
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
