// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetCrossConnectPortSpeedShapeFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCrossConnectPortSpeedShapePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCrossConnectPortSpeedShapePlainArgs Empty = new GetCrossConnectPortSpeedShapePlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetCrossConnectPortSpeedShapeFilter> filters;

    public Optional<List<GetCrossConnectPortSpeedShapeFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetCrossConnectPortSpeedShapePlainArgs() {}

    private GetCrossConnectPortSpeedShapePlainArgs(GetCrossConnectPortSpeedShapePlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCrossConnectPortSpeedShapePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCrossConnectPortSpeedShapePlainArgs $;

        public Builder() {
            $ = new GetCrossConnectPortSpeedShapePlainArgs();
        }

        public Builder(GetCrossConnectPortSpeedShapePlainArgs defaults) {
            $ = new GetCrossConnectPortSpeedShapePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetCrossConnectPortSpeedShapeFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetCrossConnectPortSpeedShapeFilter... filters) {
            return filters(List.of(filters));
        }

        public GetCrossConnectPortSpeedShapePlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}