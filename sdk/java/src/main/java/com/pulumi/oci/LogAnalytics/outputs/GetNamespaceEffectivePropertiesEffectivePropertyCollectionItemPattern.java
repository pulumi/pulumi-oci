// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern {
    /**
     * @return The effective level of the property value.
     * 
     */
    private String effectiveLevel;
    /**
     * @return The pattern id.
     * 
     */
    private String id;
    /**
     * @return The effective value of the property. This is determined by considering the value set at the most effective level.
     * 
     */
    private String value;

    private GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern() {}
    /**
     * @return The effective level of the property value.
     * 
     */
    public String effectiveLevel() {
        return this.effectiveLevel;
    }
    /**
     * @return The pattern id.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The effective value of the property. This is determined by considering the value set at the most effective level.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String effectiveLevel;
        private String id;
        private String value;
        public Builder() {}
        public Builder(GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.effectiveLevel = defaults.effectiveLevel;
    	      this.id = defaults.id;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder effectiveLevel(String effectiveLevel) {
            if (effectiveLevel == null) {
              throw new MissingRequiredPropertyException("GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern", "effectiveLevel");
            }
            this.effectiveLevel = effectiveLevel;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern", "value");
            }
            this.value = value;
            return this;
        }
        public GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern build() {
            final var _resultValue = new GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPattern();
            _resultValue.effectiveLevel = effectiveLevel;
            _resultValue.id = id;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
