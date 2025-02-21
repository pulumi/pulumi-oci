// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetDataGuardAssociationsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDataGuardAssociationsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDataGuardAssociationsArgs Empty = new GetDataGuardAssociationsArgs();

    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="databaseId", required=true)
    private Output<String> databaseId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> databaseId() {
        return this.databaseId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDataGuardAssociationsFilterArgs>> filters;

    public Optional<Output<List<GetDataGuardAssociationsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDataGuardAssociationsArgs() {}

    private GetDataGuardAssociationsArgs(GetDataGuardAssociationsArgs $) {
        this.databaseId = $.databaseId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDataGuardAssociationsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDataGuardAssociationsArgs $;

        public Builder() {
            $ = new GetDataGuardAssociationsArgs();
        }

        public Builder(GetDataGuardAssociationsArgs defaults) {
            $ = new GetDataGuardAssociationsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param databaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder databaseId(Output<String> databaseId) {
            $.databaseId = databaseId;
            return this;
        }

        /**
         * @param databaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder databaseId(String databaseId) {
            return databaseId(Output.of(databaseId));
        }

        public Builder filters(@Nullable Output<List<GetDataGuardAssociationsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDataGuardAssociationsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDataGuardAssociationsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetDataGuardAssociationsArgs build() {
            if ($.databaseId == null) {
                throw new MissingRequiredPropertyException("GetDataGuardAssociationsArgs", "databaseId");
            }
            return $;
        }
    }

}
