// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsResourceCategoriesListCategory;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsResourceCategoriesListItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetLogAnalyticsResourceCategoriesListResult {
    /**
     * @return An array of categories. The array contents include detailed information about the distinct set of categories assigned to all the listed resources under items.
     * 
     */
    private List<GetLogAnalyticsResourceCategoriesListCategory> categories;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A list of resources and their category assignments
     * 
     */
    private List<GetLogAnalyticsResourceCategoriesListItem> items;
    private String namespace;
    private @Nullable String resourceCategories;
    private @Nullable String resourceIds;
    private @Nullable String resourceTypes;

    private GetLogAnalyticsResourceCategoriesListResult() {}
    /**
     * @return An array of categories. The array contents include detailed information about the distinct set of categories assigned to all the listed resources under items.
     * 
     */
    public List<GetLogAnalyticsResourceCategoriesListCategory> categories() {
        return this.categories;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A list of resources and their category assignments
     * 
     */
    public List<GetLogAnalyticsResourceCategoriesListItem> items() {
        return this.items;
    }
    public String namespace() {
        return this.namespace;
    }
    public Optional<String> resourceCategories() {
        return Optional.ofNullable(this.resourceCategories);
    }
    public Optional<String> resourceIds() {
        return Optional.ofNullable(this.resourceIds);
    }
    public Optional<String> resourceTypes() {
        return Optional.ofNullable(this.resourceTypes);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsResourceCategoriesListResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetLogAnalyticsResourceCategoriesListCategory> categories;
        private String id;
        private List<GetLogAnalyticsResourceCategoriesListItem> items;
        private String namespace;
        private @Nullable String resourceCategories;
        private @Nullable String resourceIds;
        private @Nullable String resourceTypes;
        public Builder() {}
        public Builder(GetLogAnalyticsResourceCategoriesListResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.categories = defaults.categories;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.namespace = defaults.namespace;
    	      this.resourceCategories = defaults.resourceCategories;
    	      this.resourceIds = defaults.resourceIds;
    	      this.resourceTypes = defaults.resourceTypes;
        }

        @CustomType.Setter
        public Builder categories(List<GetLogAnalyticsResourceCategoriesListCategory> categories) {
            this.categories = Objects.requireNonNull(categories);
            return this;
        }
        public Builder categories(GetLogAnalyticsResourceCategoriesListCategory... categories) {
            return categories(List.of(categories));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetLogAnalyticsResourceCategoriesListItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetLogAnalyticsResourceCategoriesListItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder resourceCategories(@Nullable String resourceCategories) {
            this.resourceCategories = resourceCategories;
            return this;
        }
        @CustomType.Setter
        public Builder resourceIds(@Nullable String resourceIds) {
            this.resourceIds = resourceIds;
            return this;
        }
        @CustomType.Setter
        public Builder resourceTypes(@Nullable String resourceTypes) {
            this.resourceTypes = resourceTypes;
            return this;
        }
        public GetLogAnalyticsResourceCategoriesListResult build() {
            final var o = new GetLogAnalyticsResourceCategoriesListResult();
            o.categories = categories;
            o.id = id;
            o.items = items;
            o.namespace = namespace;
            o.resourceCategories = resourceCategories;
            o.resourceIds = resourceIds;
            o.resourceTypes = resourceTypes;
            return o;
        }
    }
}