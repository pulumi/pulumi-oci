// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValue {
    /**
     * @return configuration list item type, either CUSTOM or MANAGED
     * 
     */
    private final String listType;
    /**
     * @return type of the managed list
     * 
     */
    private final String managedListType;
    /**
     * @return configuration value
     * 
     */
    private final String value;

    @CustomType.Constructor
    private GetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValue(
        @CustomType.Parameter("listType") String listType,
        @CustomType.Parameter("managedListType") String managedListType,
        @CustomType.Parameter("value") String value) {
        this.listType = listType;
        this.managedListType = managedListType;
        this.value = value;
    }

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

    public static Builder builder(GetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValue defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String listType;
        private String managedListType;
        private String value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.listType = defaults.listType;
    	      this.managedListType = defaults.managedListType;
    	      this.value = defaults.value;
        }

        public Builder listType(String listType) {
            this.listType = Objects.requireNonNull(listType);
            return this;
        }
        public Builder managedListType(String managedListType) {
            this.managedListType = Objects.requireNonNull(managedListType);
            return this;
        }
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValue build() {
            return new GetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValue(listType, managedListType, value);
        }
    }
}
