// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Bastion.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Bastion.outputs.GetBastionsBastion;
import com.pulumi.oci.Bastion.outputs.GetBastionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBastionsResult {
    private final @Nullable String bastionId;
    private final @Nullable String bastionLifecycleState;
    /**
     * @return The list of bastions.
     * 
     */
    private final List<GetBastionsBastion> bastions;
    /**
     * @return The unique identifier (OCID) of the compartment where the bastion is located.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetBastionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The name of the bastion, which can&#39;t be changed after creation.
     * 
     */
    private final @Nullable String name;

    @CustomType.Constructor
    private GetBastionsResult(
        @CustomType.Parameter("bastionId") @Nullable String bastionId,
        @CustomType.Parameter("bastionLifecycleState") @Nullable String bastionLifecycleState,
        @CustomType.Parameter("bastions") List<GetBastionsBastion> bastions,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetBastionsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("name") @Nullable String name) {
        this.bastionId = bastionId;
        this.bastionLifecycleState = bastionLifecycleState;
        this.bastions = bastions;
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.name = name;
    }

    public Optional<String> bastionId() {
        return Optional.ofNullable(this.bastionId);
    }
    public Optional<String> bastionLifecycleState() {
        return Optional.ofNullable(this.bastionLifecycleState);
    }
    /**
     * @return The list of bastions.
     * 
     */
    public List<GetBastionsBastion> bastions() {
        return this.bastions;
    }
    /**
     * @return The unique identifier (OCID) of the compartment where the bastion is located.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetBastionsFilter> filters() {
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
     * @return The name of the bastion, which can&#39;t be changed after creation.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBastionsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String bastionId;
        private @Nullable String bastionLifecycleState;
        private List<GetBastionsBastion> bastions;
        private String compartmentId;
        private @Nullable List<GetBastionsFilter> filters;
        private String id;
        private @Nullable String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBastionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bastionId = defaults.bastionId;
    	      this.bastionLifecycleState = defaults.bastionLifecycleState;
    	      this.bastions = defaults.bastions;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
        }

        public Builder bastionId(@Nullable String bastionId) {
            this.bastionId = bastionId;
            return this;
        }
        public Builder bastionLifecycleState(@Nullable String bastionLifecycleState) {
            this.bastionLifecycleState = bastionLifecycleState;
            return this;
        }
        public Builder bastions(List<GetBastionsBastion> bastions) {
            this.bastions = Objects.requireNonNull(bastions);
            return this;
        }
        public Builder bastions(GetBastionsBastion... bastions) {
            return bastions(List.of(bastions));
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetBastionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBastionsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }        public GetBastionsResult build() {
            return new GetBastionsResult(bastionId, bastionLifecycleState, bastions, compartmentId, filters, id, name);
        }
    }
}
