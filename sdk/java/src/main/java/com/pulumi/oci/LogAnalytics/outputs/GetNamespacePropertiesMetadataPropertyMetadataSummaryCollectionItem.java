// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItemLevel;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItem {
    /**
     * @return The default property value.
     * 
     */
    private String defaultValue;
    /**
     * @return The property description.
     * 
     */
    private String description;
    /**
     * @return The property display name.
     * 
     */
    private String displayName;
    /**
     * @return A list of levels at which the property could be defined.
     * 
     */
    private List<GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItemLevel> levels;
    /**
     * @return The property name used for filtering.
     * 
     */
    private String name;

    private GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItem() {}
    /**
     * @return The default property value.
     * 
     */
    public String defaultValue() {
        return this.defaultValue;
    }
    /**
     * @return The property description.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The property display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return A list of levels at which the property could be defined.
     * 
     */
    public List<GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItemLevel> levels() {
        return this.levels;
    }
    /**
     * @return The property name used for filtering.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String defaultValue;
        private String description;
        private String displayName;
        private List<GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItemLevel> levels;
        private String name;
        public Builder() {}
        public Builder(GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultValue = defaults.defaultValue;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.levels = defaults.levels;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder defaultValue(String defaultValue) {
            this.defaultValue = Objects.requireNonNull(defaultValue);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder levels(List<GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItemLevel> levels) {
            this.levels = Objects.requireNonNull(levels);
            return this;
        }
        public Builder levels(GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItemLevel... levels) {
            return levels(List.of(levels));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItem build() {
            final var o = new GetNamespacePropertiesMetadataPropertyMetadataSummaryCollectionItem();
            o.defaultValue = defaultValue;
            o.description = description;
            o.displayName = displayName;
            o.levels = levels;
            o.name = name;
            return o;
        }
    }
}