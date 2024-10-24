// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetByoipAllocatedRangesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetByoipAllocatedRangesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetByoipAllocatedRangesPlainArgs Empty = new GetByoipAllocatedRangesPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
     * 
     */
    @Import(name="byoipRangeId", required=true)
    private String byoipRangeId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
     * 
     */
    public String byoipRangeId() {
        return this.byoipRangeId;
    }

    @Import(name="filters")
    private @Nullable List<GetByoipAllocatedRangesFilter> filters;

    public Optional<List<GetByoipAllocatedRangesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetByoipAllocatedRangesPlainArgs() {}

    private GetByoipAllocatedRangesPlainArgs(GetByoipAllocatedRangesPlainArgs $) {
        this.byoipRangeId = $.byoipRangeId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetByoipAllocatedRangesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetByoipAllocatedRangesPlainArgs $;

        public Builder() {
            $ = new GetByoipAllocatedRangesPlainArgs();
        }

        public Builder(GetByoipAllocatedRangesPlainArgs defaults) {
            $ = new GetByoipAllocatedRangesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param byoipRangeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
         * 
         * @return builder
         * 
         */
        public Builder byoipRangeId(String byoipRangeId) {
            $.byoipRangeId = byoipRangeId;
            return this;
        }

        public Builder filters(@Nullable List<GetByoipAllocatedRangesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetByoipAllocatedRangesFilter... filters) {
            return filters(List.of(filters));
        }

        public GetByoipAllocatedRangesPlainArgs build() {
            if ($.byoipRangeId == null) {
                throw new MissingRequiredPropertyException("GetByoipAllocatedRangesPlainArgs", "byoipRangeId");
            }
            return $;
        }
    }

}
