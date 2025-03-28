// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion;
import com.pulumi.oci.Core.outputs.GetComputeGlobalImageCapabilitySchemasVersionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetComputeGlobalImageCapabilitySchemasVersionsResult {
    /**
     * @return The ocid of the compute global image capability schema
     * 
     */
    private String computeGlobalImageCapabilitySchemaId;
    /**
     * @return The list of compute_global_image_capability_schema_versions.
     * 
     */
    private List<GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion> computeGlobalImageCapabilitySchemaVersions;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetComputeGlobalImageCapabilitySchemasVersionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetComputeGlobalImageCapabilitySchemasVersionsResult() {}
    /**
     * @return The ocid of the compute global image capability schema
     * 
     */
    public String computeGlobalImageCapabilitySchemaId() {
        return this.computeGlobalImageCapabilitySchemaId;
    }
    /**
     * @return The list of compute_global_image_capability_schema_versions.
     * 
     */
    public List<GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion> computeGlobalImageCapabilitySchemaVersions() {
        return this.computeGlobalImageCapabilitySchemaVersions;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetComputeGlobalImageCapabilitySchemasVersionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeGlobalImageCapabilitySchemasVersionsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String computeGlobalImageCapabilitySchemaId;
        private List<GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion> computeGlobalImageCapabilitySchemaVersions;
        private @Nullable String displayName;
        private @Nullable List<GetComputeGlobalImageCapabilitySchemasVersionsFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetComputeGlobalImageCapabilitySchemasVersionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.computeGlobalImageCapabilitySchemaId = defaults.computeGlobalImageCapabilitySchemaId;
    	      this.computeGlobalImageCapabilitySchemaVersions = defaults.computeGlobalImageCapabilitySchemaVersions;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder computeGlobalImageCapabilitySchemaId(String computeGlobalImageCapabilitySchemaId) {
            if (computeGlobalImageCapabilitySchemaId == null) {
              throw new MissingRequiredPropertyException("GetComputeGlobalImageCapabilitySchemasVersionsResult", "computeGlobalImageCapabilitySchemaId");
            }
            this.computeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
            return this;
        }
        @CustomType.Setter
        public Builder computeGlobalImageCapabilitySchemaVersions(List<GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion> computeGlobalImageCapabilitySchemaVersions) {
            if (computeGlobalImageCapabilitySchemaVersions == null) {
              throw new MissingRequiredPropertyException("GetComputeGlobalImageCapabilitySchemasVersionsResult", "computeGlobalImageCapabilitySchemaVersions");
            }
            this.computeGlobalImageCapabilitySchemaVersions = computeGlobalImageCapabilitySchemaVersions;
            return this;
        }
        public Builder computeGlobalImageCapabilitySchemaVersions(GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion... computeGlobalImageCapabilitySchemaVersions) {
            return computeGlobalImageCapabilitySchemaVersions(List.of(computeGlobalImageCapabilitySchemaVersions));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetComputeGlobalImageCapabilitySchemasVersionsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetComputeGlobalImageCapabilitySchemasVersionsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetComputeGlobalImageCapabilitySchemasVersionsResult", "id");
            }
            this.id = id;
            return this;
        }
        public GetComputeGlobalImageCapabilitySchemasVersionsResult build() {
            final var _resultValue = new GetComputeGlobalImageCapabilitySchemasVersionsResult();
            _resultValue.computeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
            _resultValue.computeGlobalImageCapabilitySchemaVersions = computeGlobalImageCapabilitySchemaVersions;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
