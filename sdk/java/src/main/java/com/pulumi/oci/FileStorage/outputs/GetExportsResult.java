// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.FileStorage.outputs.GetExportsExport;
import com.pulumi.oci.FileStorage.outputs.GetExportsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExportsResult {
    private @Nullable String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
     * 
     */
    private @Nullable String exportSetId;
    /**
     * @return The list of exports.
     * 
     */
    private List<GetExportsExport> exports;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
     * 
     */
    private @Nullable String fileSystemId;
    private @Nullable List<GetExportsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export.
     * 
     */
    private @Nullable String id;
    /**
     * @return The current state of this export.
     * 
     */
    private @Nullable String state;

    private GetExportsResult() {}
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
     * 
     */
    public Optional<String> exportSetId() {
        return Optional.ofNullable(this.exportSetId);
    }
    /**
     * @return The list of exports.
     * 
     */
    public List<GetExportsExport> exports() {
        return this.exports;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
     * 
     */
    public Optional<String> fileSystemId() {
        return Optional.ofNullable(this.fileSystemId);
    }
    public List<GetExportsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of this export.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExportsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String exportSetId;
        private List<GetExportsExport> exports;
        private @Nullable String fileSystemId;
        private @Nullable List<GetExportsFilter> filters;
        private @Nullable String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetExportsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.exportSetId = defaults.exportSetId;
    	      this.exports = defaults.exports;
    	      this.fileSystemId = defaults.fileSystemId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder exportSetId(@Nullable String exportSetId) {
            this.exportSetId = exportSetId;
            return this;
        }
        @CustomType.Setter
        public Builder exports(List<GetExportsExport> exports) {
            this.exports = Objects.requireNonNull(exports);
            return this;
        }
        public Builder exports(GetExportsExport... exports) {
            return exports(List.of(exports));
        }
        @CustomType.Setter
        public Builder fileSystemId(@Nullable String fileSystemId) {
            this.fileSystemId = fileSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExportsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetExportsFilter... filters) {
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
        public GetExportsResult build() {
            final var o = new GetExportsResult();
            o.compartmentId = compartmentId;
            o.exportSetId = exportSetId;
            o.exports = exports;
            o.fileSystemId = fileSystemId;
            o.filters = filters;
            o.id = id;
            o.state = state;
            return o;
        }
    }
}