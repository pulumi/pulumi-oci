// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipeDetectorRuleDetailConfigurationValue {
    /**
     * @return configuration list item type, either CUSTOM or MANAGED
     * 
     */
    private String listType;
    /**
     * @return type of the managed list
     * 
     */
    private String managedListType;
    /**
     * @return configuration value
     * 
     */
    private String value;

    private GetDetectorRecipeDetectorRuleDetailConfigurationValue() {}
    /**
     * @return configuration list item type, either CUSTOM or MANAGED
     * 
     */
    public String listType() {
        return this.listType;
    }
    /**
     * @return type of the managed list
     * 
     */
    public String managedListType() {
        return this.managedListType;
    }
    /**
     * @return configuration value
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectorRecipeDetectorRuleDetailConfigurationValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String listType;
        private String managedListType;
        private String value;
        public Builder() {}
        public Builder(GetDetectorRecipeDetectorRuleDetailConfigurationValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.listType = defaults.listType;
    	      this.managedListType = defaults.managedListType;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder listType(String listType) {
            this.listType = Objects.requireNonNull(listType);
            return this;
        }
        @CustomType.Setter
        public Builder managedListType(String managedListType) {
            this.managedListType = Objects.requireNonNull(managedListType);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDetectorRecipeDetectorRuleDetailConfigurationValue build() {
            final var o = new GetDetectorRecipeDetectorRuleDetailConfigurationValue();
            o.listType = listType;
            o.managedListType = managedListType;
            o.value = value;
            return o;
        }
    }
}