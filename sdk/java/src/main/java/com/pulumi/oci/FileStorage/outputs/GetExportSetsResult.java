// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.FileStorage.outputs.GetExportSetsExportSet;
import com.pulumi.oci.FileStorage.outputs.GetExportSetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExportSetsResult {
    /**
     * @return The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of export_sets.
     * 
     */
    private List<GetExportSetsExportSet> exportSets;
    private @Nullable List<GetExportSetsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
     * 
     */
    private @Nullable String id;
    /**
     * @return The current state of the export set.
     * 
     */
    private @Nullable String state;

    private GetExportSetsResult() {}
    /**
     * @return The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of export_sets.
     * 
     */
    public List<GetExportSetsExportSet> exportSets() {
        return this.exportSets;
    }
    public List<GetExportSetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export set.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of the export set.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExportSetsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private @Nullable String displayName;
        private List<GetExportSetsExportSet> exportSets;
        private @Nullable List<GetExportSetsFilter> filters;
        private @Nullable String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetExportSetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.exportSets = defaults.exportSets;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder exportSets(List<GetExportSetsExportSet> exportSets) {
            this.exportSets = Objects.requireNonNull(exportSets);
            return this;
        }
        public Builder exportSets(GetExportSetsExportSet... exportSets) {
            return exportSets(List.of(exportSets));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExportSetsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetExportSetsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetExportSetsResult build() {
            final var o = new GetExportSetsResult();
            o.availabilityDomain = availabilityDomain;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.exportSets = exportSets;
            o.filters = filters;
            o.id = id;
            o.state = state;
            return o;
        }
    }
}