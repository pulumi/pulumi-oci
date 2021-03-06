// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetLogAnalyticsResourceCategoriesListItem {
    /**
     * @return The category name to which this resource belongs.
     * 
     */
    private final String categoryName;
    /**
     * @return The system flag. A value of false denotes a user-created category assignment. A value of true denotes an Oracle-defined category assignment.
     * 
     */
    private final Boolean isSystem;
    /**
     * @return The unique identifier of the resource, usually a name or ocid.
     * 
     */
    private final String resourceId;
    /**
     * @return The resource type.
     * 
     */
    private final String resourceType;

    @CustomType.Constructor
    private GetLogAnalyticsResourceCategoriesListItem(
        @CustomType.Parameter("categoryName") String categoryName,
        @CustomType.Parameter("isSystem") Boolean isSystem,
        @CustomType.Parameter("resourceId") String resourceId,
        @CustomType.Parameter("resourceType") String resourceType) {
        this.categoryName = categoryName;
        this.isSystem = isSystem;
        this.resourceId = resourceId;
        this.resourceType = resourceType;
    }

    /**
     * @return The category name to which this resource belongs.
     * 
     */
    public String categoryName() {
        return this.categoryName;
    }
    /**
     * @return The system flag. A value of false denotes a user-created category assignment. A value of true denotes an Oracle-defined category assignment.
     * 
     */
    public Boolean isSystem() {
        return this.isSystem;
    }
    /**
     * @return The unique identifier of the resource, usually a name or ocid.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return The resource type.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsResourceCategoriesListItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String categoryName;
        private Boolean isSystem;
        private String resourceId;
        private String resourceType;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogAnalyticsResourceCategoriesListItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.categoryName = defaults.categoryName;
    	      this.isSystem = defaults.isSystem;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceType = defaults.resourceType;
        }

        public Builder categoryName(String categoryName) {
            this.categoryName = Objects.requireNonNull(categoryName);
            return this;
        }
        public Builder isSystem(Boolean isSystem) {
            this.isSystem = Objects.requireNonNull(isSystem);
            return this;
        }
        public Builder resourceId(String resourceId) {
            this.resourceId = Objects.requireNonNull(resourceId);
            return this;
        }
        public Builder resourceType(String resourceType) {
            this.resourceType = Objects.requireNonNull(resourceType);
            return this;
        }        public GetLogAnalyticsResourceCategoriesListItem build() {
            return new GetLogAnalyticsResourceCategoriesListItem(categoryName, isSystem, resourceId, resourceType);
        }
    }
}
