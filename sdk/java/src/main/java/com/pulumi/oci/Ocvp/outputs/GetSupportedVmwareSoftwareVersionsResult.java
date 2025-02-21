// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Ocvp.outputs.GetSupportedVmwareSoftwareVersionsFilter;
import com.pulumi.oci.Ocvp.outputs.GetSupportedVmwareSoftwareVersionsItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSupportedVmwareSoftwareVersionsResult {
    private String compartmentId;
    private @Nullable List<GetSupportedVmwareSoftwareVersionsFilter> filters;
    private @Nullable String hostShapeName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A list of the supported versions of bundled VMware software.
     * 
     */
    private List<GetSupportedVmwareSoftwareVersionsItem> items;
    /**
     * @return A short, unique string that identifies the version of bundled software.
     * 
     */
    private @Nullable String version;
    private @Nullable String versionToUpgrade;

    private GetSupportedVmwareSoftwareVersionsResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetSupportedVmwareSoftwareVersionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    public Optional<String> hostShapeName() {
        return Optional.ofNullable(this.hostShapeName);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A list of the supported versions of bundled VMware software.
     * 
     */
    public List<GetSupportedVmwareSoftwareVersionsItem> items() {
        return this.items;
    }
    /**
     * @return A short, unique string that identifies the version of bundled software.
     * 
     */
    public Optional<String> version() {
        return Optional.ofNullable(this.version);
    }
    public Optional<String> versionToUpgrade() {
        return Optional.ofNullable(this.versionToUpgrade);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSupportedVmwareSoftwareVersionsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetSupportedVmwareSoftwareVersionsFilter> filters;
        private @Nullable String hostShapeName;
        private String id;
        private List<GetSupportedVmwareSoftwareVersionsItem> items;
        private @Nullable String version;
        private @Nullable String versionToUpgrade;
        public Builder() {}
        public Builder(GetSupportedVmwareSoftwareVersionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.hostShapeName = defaults.hostShapeName;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.version = defaults.version;
    	      this.versionToUpgrade = defaults.versionToUpgrade;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSupportedVmwareSoftwareVersionsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSupportedVmwareSoftwareVersionsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSupportedVmwareSoftwareVersionsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder hostShapeName(@Nullable String hostShapeName) {

            this.hostShapeName = hostShapeName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSupportedVmwareSoftwareVersionsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetSupportedVmwareSoftwareVersionsItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSupportedVmwareSoftwareVersionsResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSupportedVmwareSoftwareVersionsItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder version(@Nullable String version) {

            this.version = version;
            return this;
        }
        @CustomType.Setter
        public Builder versionToUpgrade(@Nullable String versionToUpgrade) {

            this.versionToUpgrade = versionToUpgrade;
            return this;
        }
        public GetSupportedVmwareSoftwareVersionsResult build() {
            final var _resultValue = new GetSupportedVmwareSoftwareVersionsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.hostShapeName = hostShapeName;
            _resultValue.id = id;
            _resultValue.items = items;
            _resultValue.version = version;
            _resultValue.versionToUpgrade = versionToUpgrade;
            return _resultValue;
        }
    }
}
