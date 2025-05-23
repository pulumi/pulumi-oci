// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwarePackageSoftwareSourceFilter;
import com.pulumi.oci.OsManagementHub.outputs.GetSoftwarePackageSoftwareSourceSoftwareSourceCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSoftwarePackageSoftwareSourceResult {
    /**
     * @return The architecture type supported by the software source.
     * 
     */
    private @Nullable List<String> archTypes;
    /**
     * @return Availability of the software source (for non-OCI environments).
     * 
     */
    private @Nullable List<String> availabilities;
    private @Nullable List<String> availabilityAnywheres;
    /**
     * @return Availability of the software source (for Oracle Cloud Infrastructure environments).
     * 
     */
    private @Nullable List<String> availabilityAtOcis;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the software source.
     * 
     */
    private String compartmentId;
    /**
     * @return User-friendly name.
     * 
     */
    private @Nullable String displayName;
    private @Nullable String displayNameContains;
    private @Nullable List<GetSoftwarePackageSoftwareSourceFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OS family of the software source.
     * 
     */
    private @Nullable List<String> osFamilies;
    private String softwarePackageName;
    /**
     * @return The list of software_source_collection.
     * 
     */
    private List<GetSoftwarePackageSoftwareSourceSoftwareSourceCollection> softwareSourceCollections;
    /**
     * @return Type of software source.
     * 
     */
    private @Nullable List<String> softwareSourceTypes;
    /**
     * @return The current state of the software source.
     * 
     */
    private @Nullable List<String> states;

    private GetSoftwarePackageSoftwareSourceResult() {}
    /**
     * @return The architecture type supported by the software source.
     * 
     */
    public List<String> archTypes() {
        return this.archTypes == null ? List.of() : this.archTypes;
    }
    /**
     * @return Availability of the software source (for non-OCI environments).
     * 
     */
    public List<String> availabilities() {
        return this.availabilities == null ? List.of() : this.availabilities;
    }
    public List<String> availabilityAnywheres() {
        return this.availabilityAnywheres == null ? List.of() : this.availabilityAnywheres;
    }
    /**
     * @return Availability of the software source (for Oracle Cloud Infrastructure environments).
     * 
     */
    public List<String> availabilityAtOcis() {
        return this.availabilityAtOcis == null ? List.of() : this.availabilityAtOcis;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the software source.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return User-friendly name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public Optional<String> displayNameContains() {
        return Optional.ofNullable(this.displayNameContains);
    }
    public List<GetSoftwarePackageSoftwareSourceFilter> filters() {
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
     * @return The OS family of the software source.
     * 
     */
    public List<String> osFamilies() {
        return this.osFamilies == null ? List.of() : this.osFamilies;
    }
    public String softwarePackageName() {
        return this.softwarePackageName;
    }
    /**
     * @return The list of software_source_collection.
     * 
     */
    public List<GetSoftwarePackageSoftwareSourceSoftwareSourceCollection> softwareSourceCollections() {
        return this.softwareSourceCollections;
    }
    /**
     * @return Type of software source.
     * 
     */
    public List<String> softwareSourceTypes() {
        return this.softwareSourceTypes == null ? List.of() : this.softwareSourceTypes;
    }
    /**
     * @return The current state of the software source.
     * 
     */
    public List<String> states() {
        return this.states == null ? List.of() : this.states;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwarePackageSoftwareSourceResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> archTypes;
        private @Nullable List<String> availabilities;
        private @Nullable List<String> availabilityAnywheres;
        private @Nullable List<String> availabilityAtOcis;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable String displayNameContains;
        private @Nullable List<GetSoftwarePackageSoftwareSourceFilter> filters;
        private String id;
        private @Nullable List<String> osFamilies;
        private String softwarePackageName;
        private List<GetSoftwarePackageSoftwareSourceSoftwareSourceCollection> softwareSourceCollections;
        private @Nullable List<String> softwareSourceTypes;
        private @Nullable List<String> states;
        public Builder() {}
        public Builder(GetSoftwarePackageSoftwareSourceResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archTypes = defaults.archTypes;
    	      this.availabilities = defaults.availabilities;
    	      this.availabilityAnywheres = defaults.availabilityAnywheres;
    	      this.availabilityAtOcis = defaults.availabilityAtOcis;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.displayNameContains = defaults.displayNameContains;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.osFamilies = defaults.osFamilies;
    	      this.softwarePackageName = defaults.softwarePackageName;
    	      this.softwareSourceCollections = defaults.softwareSourceCollections;
    	      this.softwareSourceTypes = defaults.softwareSourceTypes;
    	      this.states = defaults.states;
        }

        @CustomType.Setter
        public Builder archTypes(@Nullable List<String> archTypes) {

            this.archTypes = archTypes;
            return this;
        }
        public Builder archTypes(String... archTypes) {
            return archTypes(List.of(archTypes));
        }
        @CustomType.Setter
        public Builder availabilities(@Nullable List<String> availabilities) {

            this.availabilities = availabilities;
            return this;
        }
        public Builder availabilities(String... availabilities) {
            return availabilities(List.of(availabilities));
        }
        @CustomType.Setter
        public Builder availabilityAnywheres(@Nullable List<String> availabilityAnywheres) {

            this.availabilityAnywheres = availabilityAnywheres;
            return this;
        }
        public Builder availabilityAnywheres(String... availabilityAnywheres) {
            return availabilityAnywheres(List.of(availabilityAnywheres));
        }
        @CustomType.Setter
        public Builder availabilityAtOcis(@Nullable List<String> availabilityAtOcis) {

            this.availabilityAtOcis = availabilityAtOcis;
            return this;
        }
        public Builder availabilityAtOcis(String... availabilityAtOcis) {
            return availabilityAtOcis(List.of(availabilityAtOcis));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackageSoftwareSourceResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder displayNameContains(@Nullable String displayNameContains) {

            this.displayNameContains = displayNameContains;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSoftwarePackageSoftwareSourceFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSoftwarePackageSoftwareSourceFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackageSoftwareSourceResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder osFamilies(@Nullable List<String> osFamilies) {

            this.osFamilies = osFamilies;
            return this;
        }
        public Builder osFamilies(String... osFamilies) {
            return osFamilies(List.of(osFamilies));
        }
        @CustomType.Setter
        public Builder softwarePackageName(String softwarePackageName) {
            if (softwarePackageName == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackageSoftwareSourceResult", "softwarePackageName");
            }
            this.softwarePackageName = softwarePackageName;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceCollections(List<GetSoftwarePackageSoftwareSourceSoftwareSourceCollection> softwareSourceCollections) {
            if (softwareSourceCollections == null) {
              throw new MissingRequiredPropertyException("GetSoftwarePackageSoftwareSourceResult", "softwareSourceCollections");
            }
            this.softwareSourceCollections = softwareSourceCollections;
            return this;
        }
        public Builder softwareSourceCollections(GetSoftwarePackageSoftwareSourceSoftwareSourceCollection... softwareSourceCollections) {
            return softwareSourceCollections(List.of(softwareSourceCollections));
        }
        @CustomType.Setter
        public Builder softwareSourceTypes(@Nullable List<String> softwareSourceTypes) {

            this.softwareSourceTypes = softwareSourceTypes;
            return this;
        }
        public Builder softwareSourceTypes(String... softwareSourceTypes) {
            return softwareSourceTypes(List.of(softwareSourceTypes));
        }
        @CustomType.Setter
        public Builder states(@Nullable List<String> states) {

            this.states = states;
            return this;
        }
        public Builder states(String... states) {
            return states(List.of(states));
        }
        public GetSoftwarePackageSoftwareSourceResult build() {
            final var _resultValue = new GetSoftwarePackageSoftwareSourceResult();
            _resultValue.archTypes = archTypes;
            _resultValue.availabilities = availabilities;
            _resultValue.availabilityAnywheres = availabilityAnywheres;
            _resultValue.availabilityAtOcis = availabilityAtOcis;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.displayNameContains = displayNameContains;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.osFamilies = osFamilies;
            _resultValue.softwarePackageName = softwarePackageName;
            _resultValue.softwareSourceCollections = softwareSourceCollections;
            _resultValue.softwareSourceTypes = softwareSourceTypes;
            _resultValue.states = states;
            return _resultValue;
        }
    }
}
