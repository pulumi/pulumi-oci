// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Object;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiValidationValidationDetailSrc {
    private List<Object> items;

    private GetApiValidationValidationDetailSrc() {}
    public List<Object> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiValidationValidationDetailSrc defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<Object> items;
        public Builder() {}
        public Builder(GetApiValidationValidationDetailSrc defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<Object> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetApiValidationValidationDetailSrc", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(Object... items) {
            return items(List.of(items));
        }
        public GetApiValidationValidationDetailSrc build() {
            final var _resultValue = new GetApiValidationValidationDetailSrc();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
