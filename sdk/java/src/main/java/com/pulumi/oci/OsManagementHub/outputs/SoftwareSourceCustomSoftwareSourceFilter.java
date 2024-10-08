// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagementHub.outputs.SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter;
import com.pulumi.oci.OsManagementHub.outputs.SoftwareSourceCustomSoftwareSourceFilterPackageFilter;
import com.pulumi.oci.OsManagementHub.outputs.SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class SoftwareSourceCustomSoftwareSourceFilter {
    /**
     * @return (Updatable) The list of module stream/profile filters.
     * 
     */
    private @Nullable List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter> moduleStreamProfileFilters;
    /**
     * @return (Updatable) The list of package filters.
     * 
     */
    private @Nullable List<SoftwareSourceCustomSoftwareSourceFilterPackageFilter> packageFilters;
    /**
     * @return (Updatable) The list of group filters.
     * 
     */
    private @Nullable List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter> packageGroupFilters;

    private SoftwareSourceCustomSoftwareSourceFilter() {}
    /**
     * @return (Updatable) The list of module stream/profile filters.
     * 
     */
    public List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter> moduleStreamProfileFilters() {
        return this.moduleStreamProfileFilters == null ? List.of() : this.moduleStreamProfileFilters;
    }
    /**
     * @return (Updatable) The list of package filters.
     * 
     */
    public List<SoftwareSourceCustomSoftwareSourceFilterPackageFilter> packageFilters() {
        return this.packageFilters == null ? List.of() : this.packageFilters;
    }
    /**
     * @return (Updatable) The list of group filters.
     * 
     */
    public List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter> packageGroupFilters() {
        return this.packageGroupFilters == null ? List.of() : this.packageGroupFilters;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SoftwareSourceCustomSoftwareSourceFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter> moduleStreamProfileFilters;
        private @Nullable List<SoftwareSourceCustomSoftwareSourceFilterPackageFilter> packageFilters;
        private @Nullable List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter> packageGroupFilters;
        public Builder() {}
        public Builder(SoftwareSourceCustomSoftwareSourceFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.moduleStreamProfileFilters = defaults.moduleStreamProfileFilters;
    	      this.packageFilters = defaults.packageFilters;
    	      this.packageGroupFilters = defaults.packageGroupFilters;
        }

        @CustomType.Setter
        public Builder moduleStreamProfileFilters(@Nullable List<SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter> moduleStreamProfileFilters) {

            this.moduleStreamProfileFilters = moduleStreamProfileFilters;
            return this;
        }
        public Builder moduleStreamProfileFilters(SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter... moduleStreamProfileFilters) {
            return moduleStreamProfileFilters(List.of(moduleStreamProfileFilters));
        }
        @CustomType.Setter
        public Builder packageFilters(@Nullable List<SoftwareSourceCustomSoftwareSourceFilterPackageFilter> packageFilters) {

            this.packageFilters = packageFilters;
            return this;
        }
        public Builder packageFilters(SoftwareSourceCustomSoftwareSourceFilterPackageFilter... packageFilters) {
            return packageFilters(List.of(packageFilters));
        }
        @CustomType.Setter
        public Builder packageGroupFilters(@Nullable List<SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter> packageGroupFilters) {

            this.packageGroupFilters = packageGroupFilters;
            return this;
        }
        public Builder packageGroupFilters(SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilter... packageGroupFilters) {
            return packageGroupFilters(List.of(packageGroupFilters));
        }
        public SoftwareSourceCustomSoftwareSourceFilter build() {
            final var _resultValue = new SoftwareSourceCustomSoftwareSourceFilter();
            _resultValue.moduleStreamProfileFilters = moduleStreamProfileFilters;
            _resultValue.packageFilters = packageFilters;
            _resultValue.packageGroupFilters = packageGroupFilters;
            return _resultValue;
        }
    }
}
