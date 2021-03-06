// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiValidationValidationDetailSrc {
    private final List<Object> items;

    @CustomType.Constructor
    private GetApiValidationValidationDetailSrc(@CustomType.Parameter("items") List<Object> items) {
        this.items = items;
    }

    public List<Object> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiValidationValidationDetailSrc defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<Object> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetApiValidationValidationDetailSrc defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<Object> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(Object... items) {
            return items(List.of(items));
        }        public GetApiValidationValidationDetailSrc build() {
            return new GetApiValidationValidationDetailSrc(items);
        }
    }
}
