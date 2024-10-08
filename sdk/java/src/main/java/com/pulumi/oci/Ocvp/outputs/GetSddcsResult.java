// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Ocvp.outputs.GetSddcsFilter;
import com.pulumi.oci.Ocvp.outputs.GetSddcsSddcCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSddcsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
     * 
     */
    private String compartmentId;
    /**
     * @return (**Deprecated**) The availability domain the ESXi hosts are running in. For Multi-AD SDDC, it is `multi-AD`.  Example: `Uocm:PHX-AD-1`, `multi-AD`.
     * 
     */
    private @Nullable String computeAvailabilityDomain;
    /**
     * @return A descriptive name for the SDDC. It must be unique, start with a letter, and contain only letters, digits, whitespaces, dashes and underscores. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetSddcsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of sddc_collection.
     * 
     */
    private List<GetSddcsSddcCollection> sddcCollections;
    /**
     * @return The current state of the SDDC.
     * 
     */
    private @Nullable String state;

    private GetSddcsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return (**Deprecated**) The availability domain the ESXi hosts are running in. For Multi-AD SDDC, it is `multi-AD`.  Example: `Uocm:PHX-AD-1`, `multi-AD`.
     * 
     */
    public Optional<String> computeAvailabilityDomain() {
        return Optional.ofNullable(this.computeAvailabilityDomain);
    }
    /**
     * @return A descriptive name for the SDDC. It must be unique, start with a letter, and contain only letters, digits, whitespaces, dashes and underscores. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetSddcsFilter> filters() {
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
     * @return The list of sddc_collection.
     * 
     */
    public List<GetSddcsSddcCollection> sddcCollections() {
        return this.sddcCollections;
    }
    /**
     * @return The current state of the SDDC.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSddcsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String computeAvailabilityDomain;
        private @Nullable String displayName;
        private @Nullable List<GetSddcsFilter> filters;
        private String id;
        private List<GetSddcsSddcCollection> sddcCollections;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetSddcsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeAvailabilityDomain = defaults.computeAvailabilityDomain;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.sddcCollections = defaults.sddcCollections;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSddcsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder computeAvailabilityDomain(@Nullable String computeAvailabilityDomain) {

            this.computeAvailabilityDomain = computeAvailabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSddcsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSddcsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSddcsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder sddcCollections(List<GetSddcsSddcCollection> sddcCollections) {
            if (sddcCollections == null) {
              throw new MissingRequiredPropertyException("GetSddcsResult", "sddcCollections");
            }
            this.sddcCollections = sddcCollections;
            return this;
        }
        public Builder sddcCollections(GetSddcsSddcCollection... sddcCollections) {
            return sddcCollections(List.of(sddcCollections));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetSddcsResult build() {
            final var _resultValue = new GetSddcsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.computeAvailabilityDomain = computeAvailabilityDomain;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.sddcCollections = sddcCollections;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
