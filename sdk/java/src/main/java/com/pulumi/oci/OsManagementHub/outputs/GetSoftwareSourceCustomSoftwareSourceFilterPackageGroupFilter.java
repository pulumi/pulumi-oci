// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter {
    /**
     * @return The type of the filter, which can be of two types - INCLUDE or EXCLUDE.
     * 
     */
    private String filterType;
    /**
     * @return List of package group names.
     * 
     */
    private List<String> packageGroups;

    private GetSoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter() {}
    /**
     * @return The type of the filter, which can be of two types - INCLUDE or EXCLUDE.
     * 
     */
    public String filterType() {
        return this.filterType;
    }
    /**
     * @return List of package group names.
     * 
     */
    public List<String> packageGroups() {
        return this.packageGroups;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String filterType;
        private List<String> packageGroups;
        public Builder() {}
        public Builder(GetSoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterType = defaults.filterType;
    	      this.packageGroups = defaults.packageGroups;
        }

        @CustomType.Setter
        public Builder filterType(String filterType) {
            this.filterType = Objects.requireNonNull(filterType);
            return this;
        }
        @CustomType.Setter
        public Builder packageGroups(List<String> packageGroups) {
            this.packageGroups = Objects.requireNonNull(packageGroups);
            return this;
        }
        public Builder packageGroups(String... packageGroups) {
            return packageGroups(List.of(packageGroups));
        }
        public GetSoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter build() {
            final var o = new GetSoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter();
            o.filterType = filterType;
            o.packageGroups = packageGroups;
            return o;
        }
    }
}