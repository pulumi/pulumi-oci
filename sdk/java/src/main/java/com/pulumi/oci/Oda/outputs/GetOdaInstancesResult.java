// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Oda.outputs.GetOdaInstancesFilter;
import com.pulumi.oci.Oda.outputs.GetOdaInstancesOdaInstance;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetOdaInstancesResult {
    /**
     * @return Identifier of the compartment that the instance belongs to.
     * 
     */
    private String compartmentId;
    /**
     * @return User-defined name for the Digital Assistant instance. Avoid entering confidential information. You can change this value.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetOdaInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of oda_instances.
     * 
     */
    private List<GetOdaInstancesOdaInstance> odaInstances;
    /**
     * @return The current state of the Digital Assistant instance.
     * 
     */
    private @Nullable String state;

    private GetOdaInstancesResult() {}
    /**
     * @return Identifier of the compartment that the instance belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return User-defined name for the Digital Assistant instance. Avoid entering confidential information. You can change this value.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetOdaInstancesFilter> filters() {
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
     * @return The list of oda_instances.
     * 
     */
    public List<GetOdaInstancesOdaInstance> odaInstances() {
        return this.odaInstances;
    }
    /**
     * @return The current state of the Digital Assistant instance.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOdaInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetOdaInstancesFilter> filters;
        private String id;
        private List<GetOdaInstancesOdaInstance> odaInstances;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetOdaInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.odaInstances = defaults.odaInstances;
    	      this.state = defaults.state;
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
        public Builder filters(@Nullable List<GetOdaInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetOdaInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder odaInstances(List<GetOdaInstancesOdaInstance> odaInstances) {
            this.odaInstances = Objects.requireNonNull(odaInstances);
            return this;
        }
        public Builder odaInstances(GetOdaInstancesOdaInstance... odaInstances) {
            return odaInstances(List.of(odaInstances));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetOdaInstancesResult build() {
            final var o = new GetOdaInstancesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.odaInstances = odaInstances;
            o.state = state;
            return o;
        }
    }
}