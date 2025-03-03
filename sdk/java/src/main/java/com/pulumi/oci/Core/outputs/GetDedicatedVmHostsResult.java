// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetDedicatedVmHostsDedicatedVmHost;
import com.pulumi.oci.Core.outputs.GetDedicatedVmHostsFilter;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDedicatedVmHostsResult {
    /**
     * @return The availability domain the dedicated virtual machine host is running in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The OCID of the compartment that contains the dedicated virtual machine host.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of dedicated_vm_hosts.
     * 
     */
    private List<GetDedicatedVmHostsDedicatedVmHost> dedicatedVmHosts;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDedicatedVmHostsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String instanceShapeName;
    private @Nullable Double remainingMemoryInGbsGreaterThanOrEqualTo;
    private @Nullable Double remainingOcpusGreaterThanOrEqualTo;
    /**
     * @return The current state of the dedicated VM host.
     * 
     */
    private @Nullable String state;

    private GetDedicatedVmHostsResult() {}
    /**
     * @return The availability domain the dedicated virtual machine host is running in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The OCID of the compartment that contains the dedicated virtual machine host.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of dedicated_vm_hosts.
     * 
     */
    public List<GetDedicatedVmHostsDedicatedVmHost> dedicatedVmHosts() {
        return this.dedicatedVmHosts;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDedicatedVmHostsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> instanceShapeName() {
        return Optional.ofNullable(this.instanceShapeName);
    }
    public Optional<Double> remainingMemoryInGbsGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.remainingMemoryInGbsGreaterThanOrEqualTo);
    }
    public Optional<Double> remainingOcpusGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.remainingOcpusGreaterThanOrEqualTo);
    }
    /**
     * @return The current state of the dedicated VM host.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVmHostsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private String compartmentId;
        private List<GetDedicatedVmHostsDedicatedVmHost> dedicatedVmHosts;
        private @Nullable String displayName;
        private @Nullable List<GetDedicatedVmHostsFilter> filters;
        private String id;
        private @Nullable String instanceShapeName;
        private @Nullable Double remainingMemoryInGbsGreaterThanOrEqualTo;
        private @Nullable Double remainingOcpusGreaterThanOrEqualTo;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDedicatedVmHostsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dedicatedVmHosts = defaults.dedicatedVmHosts;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.instanceShapeName = defaults.instanceShapeName;
    	      this.remainingMemoryInGbsGreaterThanOrEqualTo = defaults.remainingMemoryInGbsGreaterThanOrEqualTo;
    	      this.remainingOcpusGreaterThanOrEqualTo = defaults.remainingOcpusGreaterThanOrEqualTo;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {

            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dedicatedVmHosts(List<GetDedicatedVmHostsDedicatedVmHost> dedicatedVmHosts) {
            if (dedicatedVmHosts == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostsResult", "dedicatedVmHosts");
            }
            this.dedicatedVmHosts = dedicatedVmHosts;
            return this;
        }
        public Builder dedicatedVmHosts(GetDedicatedVmHostsDedicatedVmHost... dedicatedVmHosts) {
            return dedicatedVmHosts(List.of(dedicatedVmHosts));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDedicatedVmHostsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDedicatedVmHostsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceShapeName(@Nullable String instanceShapeName) {

            this.instanceShapeName = instanceShapeName;
            return this;
        }
        @CustomType.Setter
        public Builder remainingMemoryInGbsGreaterThanOrEqualTo(@Nullable Double remainingMemoryInGbsGreaterThanOrEqualTo) {

            this.remainingMemoryInGbsGreaterThanOrEqualTo = remainingMemoryInGbsGreaterThanOrEqualTo;
            return this;
        }
        @CustomType.Setter
        public Builder remainingOcpusGreaterThanOrEqualTo(@Nullable Double remainingOcpusGreaterThanOrEqualTo) {

            this.remainingOcpusGreaterThanOrEqualTo = remainingOcpusGreaterThanOrEqualTo;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetDedicatedVmHostsResult build() {
            final var _resultValue = new GetDedicatedVmHostsResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.compartmentId = compartmentId;
            _resultValue.dedicatedVmHosts = dedicatedVmHosts;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.instanceShapeName = instanceShapeName;
            _resultValue.remainingMemoryInGbsGreaterThanOrEqualTo = remainingMemoryInGbsGreaterThanOrEqualTo;
            _resultValue.remainingOcpusGreaterThanOrEqualTo = remainingOcpusGreaterThanOrEqualTo;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
