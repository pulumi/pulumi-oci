// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet {
    /**
     * @return The template name used for filtering.
     * 
     */
    private String name;
    /**
     * @return The facet value.
     * 
     */
    private String value;

    private GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet() {}
    /**
     * @return The template name used for filtering.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The facet value.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String value;
        public Builder() {}
        public Builder(GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet", "value");
            }
            this.value = value;
            return this;
        }
        public GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet build() {
            final var _resultValue = new GetNamespaceTemplatesLogAnalyticsTemplateCollectionItemFacet();
            _resultValue.name = name;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
