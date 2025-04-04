// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagement.outputs.GetSoftwareSourceStreamProfileFilter;
import com.pulumi.oci.OsManagement.outputs.GetSoftwareSourceStreamProfileModuleStreamProfile;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSoftwareSourceStreamProfileResult {
    private @Nullable String compartmentId;
    private @Nullable List<GetSoftwareSourceStreamProfileFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The name of the module that contains the stream profile
     * 
     */
    private @Nullable String moduleName;
    /**
     * @return The list of module_stream_profiles.
     * 
     */
    private List<GetSoftwareSourceStreamProfileModuleStreamProfile> moduleStreamProfiles;
    /**
     * @return The name of the profile
     * 
     */
    private @Nullable String profileName;
    private String softwareSourceId;
    /**
     * @return The name of the stream that contains the profile
     * 
     */
    private @Nullable String streamName;

    private GetSoftwareSourceStreamProfileResult() {}
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public List<GetSoftwareSourceStreamProfileFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The name of the module that contains the stream profile
     * 
     */
    public Optional<String> moduleName() {
        return Optional.ofNullable(this.moduleName);
    }
    /**
     * @return The list of module_stream_profiles.
     * 
     */
    public List<GetSoftwareSourceStreamProfileModuleStreamProfile> moduleStreamProfiles() {
        return this.moduleStreamProfiles;
    }
    /**
     * @return The name of the profile
     * 
     */
    public Optional<String> profileName() {
        return Optional.ofNullable(this.profileName);
    }
    public String softwareSourceId() {
        return this.softwareSourceId;
    }
    /**
     * @return The name of the stream that contains the profile
     * 
     */
    public Optional<String> streamName() {
        return Optional.ofNullable(this.streamName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourceStreamProfileResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable List<GetSoftwareSourceStreamProfileFilter> filters;
        private String id;
        private @Nullable String moduleName;
        private List<GetSoftwareSourceStreamProfileModuleStreamProfile> moduleStreamProfiles;
        private @Nullable String profileName;
        private String softwareSourceId;
        private @Nullable String streamName;
        public Builder() {}
        public Builder(GetSoftwareSourceStreamProfileResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.moduleName = defaults.moduleName;
    	      this.moduleStreamProfiles = defaults.moduleStreamProfiles;
    	      this.profileName = defaults.profileName;
    	      this.softwareSourceId = defaults.softwareSourceId;
    	      this.streamName = defaults.streamName;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSoftwareSourceStreamProfileFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSoftwareSourceStreamProfileFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceStreamProfileResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder moduleName(@Nullable String moduleName) {

            this.moduleName = moduleName;
            return this;
        }
        @CustomType.Setter
        public Builder moduleStreamProfiles(List<GetSoftwareSourceStreamProfileModuleStreamProfile> moduleStreamProfiles) {
            if (moduleStreamProfiles == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceStreamProfileResult", "moduleStreamProfiles");
            }
            this.moduleStreamProfiles = moduleStreamProfiles;
            return this;
        }
        public Builder moduleStreamProfiles(GetSoftwareSourceStreamProfileModuleStreamProfile... moduleStreamProfiles) {
            return moduleStreamProfiles(List.of(moduleStreamProfiles));
        }
        @CustomType.Setter
        public Builder profileName(@Nullable String profileName) {

            this.profileName = profileName;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceId(String softwareSourceId) {
            if (softwareSourceId == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceStreamProfileResult", "softwareSourceId");
            }
            this.softwareSourceId = softwareSourceId;
            return this;
        }
        @CustomType.Setter
        public Builder streamName(@Nullable String streamName) {

            this.streamName = streamName;
            return this;
        }
        public GetSoftwareSourceStreamProfileResult build() {
            final var _resultValue = new GetSoftwareSourceStreamProfileResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.moduleName = moduleName;
            _resultValue.moduleStreamProfiles = moduleStreamProfiles;
            _resultValue.profileName = profileName;
            _resultValue.softwareSourceId = softwareSourceId;
            _resultValue.streamName = streamName;
            return _resultValue;
        }
    }
}
