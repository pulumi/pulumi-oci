// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetPluginErrorsPluginErrorCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetPluginErrorsPluginErrorCollection {
    /**
     * @return A list of PluginErrorSummary.
     * 
     */
    private List<GetPluginErrorsPluginErrorCollectionItem> items;

    private GetPluginErrorsPluginErrorCollection() {}
    /**
     * @return A list of PluginErrorSummary.
     * 
     */
    public List<GetPluginErrorsPluginErrorCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPluginErrorsPluginErrorCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetPluginErrorsPluginErrorCollectionItem> items;
        public Builder() {}
        public Builder(GetPluginErrorsPluginErrorCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetPluginErrorsPluginErrorCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetPluginErrorsPluginErrorCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetPluginErrorsPluginErrorCollectionItem... items) {
            return items(List.of(items));
        }
        public GetPluginErrorsPluginErrorCollection build() {
            final var _resultValue = new GetPluginErrorsPluginErrorCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
