// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Oda.outputs.GetOdaPrivateEndpointsOdaPrivateEndpointCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOdaPrivateEndpointsOdaPrivateEndpointCollection {
    private List<GetOdaPrivateEndpointsOdaPrivateEndpointCollectionItem> items;

    private GetOdaPrivateEndpointsOdaPrivateEndpointCollection() {}
    public List<GetOdaPrivateEndpointsOdaPrivateEndpointCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOdaPrivateEndpointsOdaPrivateEndpointCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetOdaPrivateEndpointsOdaPrivateEndpointCollectionItem> items;
        public Builder() {}
        public Builder(GetOdaPrivateEndpointsOdaPrivateEndpointCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetOdaPrivateEndpointsOdaPrivateEndpointCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetOdaPrivateEndpointsOdaPrivateEndpointCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetOdaPrivateEndpointsOdaPrivateEndpointCollectionItem... items) {
            return items(List.of(items));
        }
        public GetOdaPrivateEndpointsOdaPrivateEndpointCollection build() {
            final var _resultValue = new GetOdaPrivateEndpointsOdaPrivateEndpointCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
