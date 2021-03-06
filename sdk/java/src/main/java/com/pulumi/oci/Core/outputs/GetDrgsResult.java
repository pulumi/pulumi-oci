// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetDrgsDrg;
import com.pulumi.oci.Core.outputs.GetDrgsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetDrgsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG.
     * 
     */
    private final String compartmentId;
    /**
     * @return The list of drgs.
     * 
     */
    private final List<GetDrgsDrg> drgs;
    private final @Nullable List<GetDrgsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetDrgsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("drgs") List<GetDrgsDrg> drgs,
        @CustomType.Parameter("filters") @Nullable List<GetDrgsFilter> filters,
        @CustomType.Parameter("id") String id) {
        this.compartmentId = compartmentId;
        this.drgs = drgs;
        this.filters = filters;
        this.id = id;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of drgs.
     * 
     */
    public List<GetDrgsDrg> drgs() {
        return this.drgs;
    }
    public List<GetDrgsFilter> filters() {
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

    public static Builder builder(GetDrgsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<GetDrgsDrg> drgs;
        private @Nullable List<GetDrgsFilter> filters;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDrgsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.drgs = defaults.drgs;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder drgs(List<GetDrgsDrg> drgs) {
            this.drgs = Objects.requireNonNull(drgs);
            return this;
        }
        public Builder drgs(GetDrgsDrg... drgs) {
            return drgs(List.of(drgs));
        }
        public Builder filters(@Nullable List<GetDrgsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDrgsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetDrgsResult build() {
            return new GetDrgsResult(compartmentId, drgs, filters, id);
        }
    }
}
